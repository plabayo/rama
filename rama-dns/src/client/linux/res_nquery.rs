#![expect(
    clippy::allow_attributes,
    reason = "the bindgen-generated `mod bindings` include uses `#[allow(...)]` for a set of lints whose underlying triggers vary by libc/glibc shape; `#[expect]` would warn unfulfilled on some hosts"
)]

use std::{
    mem,
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use rama_core::{
    bytes::Bytes,
    error::BoxError,
    futures::{Stream, async_stream::stream_fn},
    stream::{StreamExt, wrappers::ReceiverStream},
    telemetry::tracing,
};
use rama_net::address::Domain;

use libc::c_int;
use tokio::sync::mpsc;

use super::{LinuxDnsResolverError, LookupEvent, dns_name_from_domain};

pub(super) fn lookup_ipv4_stream(
    domain: Domain,
    timeout: Duration,
    response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<Ipv4Addr>, BoxError>> + Send {
    lookup_record_stream(
        domain,
        timeout,
        response_buffer_size,
        ffi::NS_T_A as c_int,
        parse_a_response,
    )
}

pub(super) fn lookup_ipv6_stream(
    domain: Domain,
    timeout: Duration,
    response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<Ipv6Addr>, BoxError>> + Send {
    lookup_record_stream(
        domain,
        timeout,
        response_buffer_size,
        ffi::NS_T_AAAA as c_int,
        parse_aaaa_response,
    )
}

pub(super) fn lookup_txt_stream(
    domain: Domain,
    timeout: Duration,
    response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<Bytes>, BoxError>> + Send {
    lookup_record_stream(
        domain,
        timeout,
        response_buffer_size,
        ffi::NS_T_TXT as c_int,
        parse_txt_response,
    )
}

fn lookup_record_stream<T, P>(
    domain: Domain,
    timeout: Duration,
    response_buffer_size: usize,
    rrtype: libc::c_int,
    parser: P,
) -> impl Stream<Item = Result<LookupEvent<T>, BoxError>> + Send
where
    T: Send + 'static,
    P: Fn(&[u8], &mut dyn FnMut(T, u32)) -> Result<(), BoxError> + Send + 'static,
{
    stream_fn(async move |mut yielder| {
        tracing::debug!(?timeout, %domain, rrtype, "dns::linux: res_nquery");

        let (tx, rx) = mpsc::channel(8);
        let join = tokio::task::spawn_blocking(move || {
            // `lookup_record_packet` always returns the wire response (or None
            // for transport errors); NXDOMAIN/NODATA come back as a packet
            // whose answer section is empty but whose authority section
            // typically carries a SOA RR — see RFC 2308 §5.
            let Some(packet) = lookup_record_packet(domain, rrtype, response_buffer_size)? else {
                return Ok(());
            };

            let mut emitted = 0_usize;
            parser(&packet, &mut |item, ttl| {
                emitted += 1;
                _ = tx.blocking_send(Ok(LookupEvent::Record(item, ttl)));
            })?;

            if emitted == 0 {
                // Authoritative negative: announce the SOA-derived TTL (per
                // RFC 2308 §5, `min(SOA.TTL, SOA.MINIMUM)`) so the cache can
                // honor the zone's intent rather than a fixed client default.
                let soa_ttl = parse_authority_soa_ttl(&packet);
                _ = tx.blocking_send(Ok(LookupEvent::AuthoritativeNegative { soa_ttl }));
            }

            Ok::<_, BoxError>(())
        });

        let mut stream = std::pin::pin!(ReceiverStream::new(rx).timeout(timeout));

        while let Some(result) = stream.next().await {
            match result {
                Ok(item) => yielder.yield_item(item).await,
                Err(err) => {
                    tracing::debug!(
                        %err,
                        "linux::res_nquery: item failed to resolve on time: return timeout error",
                    );
                    // `res_nquery` is a blocking libc call, so timing out here only stops
                    // waiting for the worker result; it does not cancel the underlying OS
                    // resolver call once it has started.
                    yielder
                        .yield_item(Err(LinuxDnsResolverError::timeout(timeout).into()))
                        .await;
                    return;
                }
            }
        }

        match join.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                yielder
                    .yield_item(Err(LinuxDnsResolverError::message(format!(
                        "linux dns res_nquery task failed: {err}"
                    ))
                    .into()))
                    .await;
            }
            Err(err) => {
                tracing::debug!(
                    "linux::res_nquery: lookup_record_stream error = {err} (report as timeout)"
                );
                yielder
                    .yield_item(Err(LinuxDnsResolverError::timeout(timeout).into()))
                    .await;
            }
        }
    })
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "Domain is consumed by `as_str` borrow + dropped at fn end; taking by value makes the lifetime trivial inside `spawn_blocking`"
)]
fn lookup_record_packet(
    domain: Domain,
    rrtype: libc::c_int,
    response_buffer_size: usize,
) -> Result<Option<Vec<u8>>, BoxError> {
    let name = dns_name_from_domain(domain.as_str())?;
    let mut state: ffi::ResState = unsafe { mem::zeroed() };

    // SAFETY: `state` points to writable resolver context storage.
    if unsafe { ffi::res_ninit(&mut state) } != 0 {
        return Err(LinuxDnsResolverError::message("res_ninit failed").into());
    }
    let _guard = ResStateGuard(&mut state as *mut _);

    let mut buffer = vec![0_u8; response_buffer_size];

    // SAFETY:
    // - `state` is initialized by `res_ninit`.
    // - `name` is a valid NUL-terminated DNS name.
    // - `buffer` is writable response storage.
    let response_len = unsafe {
        ffi::res_nquery(
            &mut state,
            name.as_ptr(),
            ffi::NS_C_IN as libc::c_int,
            rrtype,
            buffer.as_mut_ptr(),
            buffer.len() as libc::c_int,
        )
    };

    if response_len < 0 {
        let h_errno = state.res_h_errno;
        if matches!(h_errno, 0 | ffi::HOST_NOT_FOUND | ffi::NO_DATA) {
            tracing::debug!(%domain, rrtype, h_errno, "dns::linux: res_nquery empty result");
            // glibc copies the wire response into `buffer` before classifying
            // the rcode and returning -1 (see `__libc_res_nquery` in
            // `resolv/res_query.c`). The exact response length isn't surfaced,
            // but the parser walks via DNS header counts and bounds itself on
            // `packet.len()`, so handing over the full capacity is safe — any
            // bytes past the real response are zeros from `vec![0; ...]` that
            // look like empty labels / records and terminate the walk
            // harmlessly. This lets us recover the SOA TTL from the authority
            // section for RFC 2308-correct negative caching.
            return Ok(Some(buffer));
        }
        return Err(LinuxDnsResolverError::message(format!(
            "res_nquery failed (h_errno={h_errno})",
        ))
        .into());
    }

    if response_len as usize > buffer.len() {
        return Err(LinuxDnsResolverError::message(format!(
            "res_nquery response exceeds buffer: required={response_len} capacity={}",
            buffer.len()
        ))
        .into());
    }

    buffer.truncate(response_len as usize);
    Ok(Some(buffer))
}

struct ResStateGuard(*mut ffi::ResState);

impl Drop for ResStateGuard {
    fn drop(&mut self) {
        unsafe {
            ffi::res_nclose(self.0);
        }
    }
}

fn parse_a_response(packet: &[u8], emit: &mut dyn FnMut(Ipv4Addr, u32)) -> Result<(), BoxError> {
    parse_answers(packet, ffi::NS_T_A, |rdata, ttl| {
        if rdata.len() != 4 {
            return Err(LinuxDnsResolverError::message(format!(
                "invalid A record length: {}",
                rdata.len()
            ))
            .into());
        }
        emit(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]), ttl);
        Ok(())
    })
}

fn parse_aaaa_response(packet: &[u8], emit: &mut dyn FnMut(Ipv6Addr, u32)) -> Result<(), BoxError> {
    parse_answers(packet, ffi::NS_T_AAAA, |rdata, ttl| {
        if rdata.len() != 16 {
            return Err(LinuxDnsResolverError::message(format!(
                "invalid AAAA record length: {}",
                rdata.len()
            ))
            .into());
        }
        let mut octets = [0_u8; 16];
        octets.copy_from_slice(rdata);
        emit(Ipv6Addr::from(octets), ttl);
        Ok(())
    })
}

fn parse_txt_response(packet: &[u8], emit: &mut dyn FnMut(Bytes, u32)) -> Result<(), BoxError> {
    parse_answers(packet, ffi::NS_T_TXT, |rdata, ttl| {
        let mut offset = 0;

        while offset < rdata.len() {
            let len = rdata[offset] as usize;
            offset += 1;
            if offset + len > rdata.len() {
                return Err(LinuxDnsResolverError::message("invalid TXT record payload").into());
            }
            emit(Bytes::copy_from_slice(&rdata[offset..offset + len]), ttl);
            offset += len;
        }

        Ok(())
    })
}

fn parse_answers<P>(packet: &[u8], expected_type: u16, mut parser: P) -> Result<(), BoxError>
where
    P: FnMut(&[u8], u32) -> Result<(), BoxError>,
{
    if packet.len() < 12 {
        return Err(LinuxDnsResolverError::message("short DNS response header").into());
    }

    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;

    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_dns_name(packet, offset)?;
        offset = offset
            .checked_add(4)
            .filter(|offset| *offset <= packet.len())
            .ok_or_else(|| LinuxDnsResolverError::message("truncated DNS question"))?;
    }

    for _ in 0..ancount {
        offset = skip_dns_name(packet, offset)?;
        if offset + 10 > packet.len() {
            return Err(LinuxDnsResolverError::message("truncated DNS answer").into());
        }

        let rrtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let rrclass = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let ttl = u32::from_be_bytes([
            packet[offset + 4],
            packet[offset + 5],
            packet[offset + 6],
            packet[offset + 7],
        ]);
        let rdlen = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlen > packet.len() {
            return Err(LinuxDnsResolverError::message("truncated DNS rdata").into());
        }

        if rrtype == expected_type && rrclass == ffi::NS_C_IN {
            parser(&packet[offset..offset + rdlen], ttl)?;
        }

        offset += rdlen;
    }

    Ok(())
}

/// Walks the authority section of a DNS response, returning the SOA-derived
/// negative-cache TTL per RFC 2308 §5: `min(SOA.TTL, SOA.MINIMUM)`.
///
/// Returns `None` if the response carries no usable SOA RR (no authority
/// records, only NS, malformed rdata, …) — callers should then fall back to
/// the configured default.
fn parse_authority_soa_ttl(packet: &[u8]) -> Option<u32> {
    if packet.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let nscount = u16::from_be_bytes([packet[8], packet[9]]) as usize;

    let mut offset = 12;
    for _ in 0..qdcount {
        offset = skip_dns_name(packet, offset).ok()?;
        offset = offset
            .checked_add(4)
            .filter(|offset| *offset <= packet.len())?;
    }

    for _ in 0..ancount {
        offset = skip_dns_name(packet, offset).ok()?;
        if offset + 10 > packet.len() {
            return None;
        }
        let rdlen = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset = offset.checked_add(10)?.checked_add(rdlen)?;
        if offset > packet.len() {
            return None;
        }
    }

    for _ in 0..nscount {
        offset = skip_dns_name(packet, offset).ok()?;
        if offset + 10 > packet.len() {
            return None;
        }
        let rrtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let rrclass = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let ttl = u32::from_be_bytes([
            packet[offset + 4],
            packet[offset + 5],
            packet[offset + 6],
            packet[offset + 7],
        ]);
        let rdlen = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;
        let rdata_end = offset.checked_add(rdlen)?;
        if rdata_end > packet.len() {
            return None;
        }

        if rrtype == ffi::NS_T_SOA && rrclass == ffi::NS_C_IN {
            // SOA rdata: MNAME, RNAME, then five 32-bit fields. We only need
            // the last one (MINIMUM), so walk past both names and read it.
            let mut soa_off = offset;
            soa_off = skip_dns_name(packet, soa_off).ok()?;
            if soa_off > rdata_end {
                return None;
            }
            soa_off = skip_dns_name(packet, soa_off).ok()?;
            if soa_off.checked_add(20)? > rdata_end {
                return None;
            }
            let minimum = u32::from_be_bytes([
                packet[soa_off + 16],
                packet[soa_off + 17],
                packet[soa_off + 18],
                packet[soa_off + 19],
            ]);
            return Some(ttl.min(minimum));
        }

        offset = rdata_end;
    }

    None
}

fn skip_dns_name(packet: &[u8], mut offset: usize) -> Result<usize, BoxError> {
    let mut jumps = 0;
    loop {
        let Some(&len) = packet.get(offset) else {
            return Err(LinuxDnsResolverError::message("truncated DNS name").into());
        };

        // RFC 1035 name compression: `11xxxxxx xxxxxxxx` is a 14-bit pointer.
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= packet.len() {
                return Err(
                    LinuxDnsResolverError::message("truncated DNS compression pointer").into(),
                );
            }
            return Ok(offset + 2);
        }
        if len == 0 {
            return Ok(offset + 1);
        }

        offset += 1 + len as usize;
        if offset > packet.len() {
            return Err(LinuxDnsResolverError::message("truncated DNS label").into());
        }

        jumps += 1;
        if jumps > 128 {
            return Err(LinuxDnsResolverError::message("too many DNS labels").into());
        }
    }
}

mod ffi {
    use libc::{c_char, c_int};

    #[allow(
        clippy::all,
        clippy::multiple_unsafe_ops_per_block,
        clippy::undocumented_unsafe_blocks,
        non_camel_case_types,
        non_snake_case,
        non_upper_case_globals,
        unsafe_op_in_unsafe_fn,
        unreachable_pub,
        unused
    )]
    mod bindings {
        include!(concat!(env!("OUT_DIR"), "/resolv_bindings.rs"));
    }

    // DNS class/type constants mirrored from glibc's resolver headers.
    //
    // Sources:
    // - https://codebrowser.dev/glibc/glibc/resolv/arpa/nameser_compat.h.html
    // - https://codebrowser.dev/glibc/glibc/resolv/arpa/nameser.h.html

    /// Internet
    pub(super) const NS_C_IN: u16 = 1;

    /// A (IPv4)
    pub(super) const NS_T_A: u16 = 1;
    /// SOA (Start of Authority)
    pub(super) const NS_T_SOA: u16 = 6;
    /// TXT
    pub(super) const NS_T_TXT: u16 = 16;
    /// AAAA (IPv6)
    pub(super) const NS_T_AAAA: u16 = 28;

    // Resolver h_errno values from <netdb.h>.
    //
    // Source:
    // - https://codebrowser.dev/glibc/glibc/resolv/netdb.h.html

    /// Authoritative Answer Host not found.
    pub(super) const HOST_NOT_FOUND: c_int = 1;
    /// Valid name, no data record of requested type.
    pub(super) const NO_DATA: c_int = 4;

    // Thread-safe resolver state generated from the target platform's
    // `<resolv.h>` definition via bindgen.
    //
    // Sources:
    // - https://codebrowser.dev/glibc/glibc/resolv/resolv.h.html
    // - https://man7.org/linux/man-pages/man3/resolver.3.html
    // - https://man.freebsd.org/cgi/man.cgi?query=resolver&sektion=3
    // - https://man.openbsd.org/resolver.3
    // - https://man.netbsd.org/resolver.3
    pub(super) type ResState = bindings::__res_state;

    // GNU/Linux symbol mapping:
    // - `res_ninit` is exported as `__res_ninit`
    // - `res_nclose` is exported as `__res_nclose`
    // - `res_nquery` is exported as `res_nquery`
    //
    // Sources:
    // - https://codebrowser.dev/glibc/glibc/resolv/res_init.c.html
    // - https://codebrowser.dev/glibc/glibc/resolv/res-close.c.html
    // - https://codebrowser.dev/glibc/glibc/resolv/res_query.c.html
    // - https://man7.org/linux/man-pages/man3/resolver.3.html
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[link(name = "resolv")]
    unsafe extern "C" {
        #[link_name = "__res_ninit"]
        pub(super) fn res_ninit(state: *mut ResState) -> c_int;
        #[link_name = "__res_nclose"]
        pub(super) fn res_nclose(state: *mut ResState);
        pub(super) fn res_nquery(
            state: *mut ResState,
            dname: *const c_char,
            class: c_int,
            typ: c_int,
            answer: *mut u8,
            anslen: c_int,
        ) -> c_int;
    }

    // BSDs expose the re-entrant libresolv APIs under their public `res_n*`
    // symbol names.
    //
    // Sources:
    // - https://man.freebsd.org/cgi/man.cgi?query=resolver&sektion=3
    // - https://man.openbsd.org/resolver.3
    // - https://man.netbsd.org/resolver.3
    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    #[link(name = "resolv")]
    unsafe extern "C" {
        pub(super) fn res_ninit(state: *mut ResState) -> c_int;
        pub(super) fn res_nclose(state: *mut ResState);
        pub(super) fn res_nquery(
            state: *mut ResState,
            dname: *const c_char,
            class: c_int,
            typ: c_int,
            answer: *mut u8,
            anslen: c_int,
        ) -> c_int;
    }
}

#[cfg(test)]
mod soa_ttl_tests {
    use super::{ffi, parse_authority_soa_ttl};

    /// Build a minimal NXDOMAIN/NODATA DNS response carrying a single SOA RR
    /// in the authority section. Question section uses an A-record query for
    /// "example.com.". SOA MNAME/RNAME are "ns.example.com." and
    /// "hostmaster.example.com." in uncompressed form.
    fn build_negative_response(soa_ttl: u32, soa_minimum: u32) -> Vec<u8> {
        let mut p = Vec::new();
        // Header: id=0, flags=0x8183 (response, AA, NXDOMAIN), qd=1, an=0, ns=1, ar=0
        p.extend_from_slice(&[0, 0, 0x81, 0x83, 0, 1, 0, 0, 0, 1, 0, 0]);
        // Question: example.com. type=A class=IN
        write_name(&mut p, &["example", "com"]);
        p.extend_from_slice(&ffi::NS_T_A.to_be_bytes());
        p.extend_from_slice(&ffi::NS_C_IN.to_be_bytes());
        // Authority: example.com. type=SOA class=IN ttl=soa_ttl rdlen=?
        write_name(&mut p, &["example", "com"]);
        p.extend_from_slice(&ffi::NS_T_SOA.to_be_bytes());
        p.extend_from_slice(&ffi::NS_C_IN.to_be_bytes());
        p.extend_from_slice(&soa_ttl.to_be_bytes());
        let rdlen_pos = p.len();
        p.extend_from_slice(&[0, 0]); // placeholder
        let rdata_start = p.len();
        write_name(&mut p, &["ns", "example", "com"]);
        write_name(&mut p, &["hostmaster", "example", "com"]);
        p.extend_from_slice(&1_u32.to_be_bytes()); // SERIAL
        p.extend_from_slice(&3600_u32.to_be_bytes()); // REFRESH
        p.extend_from_slice(&600_u32.to_be_bytes()); // RETRY
        p.extend_from_slice(&86400_u32.to_be_bytes()); // EXPIRE
        p.extend_from_slice(&soa_minimum.to_be_bytes()); // MINIMUM
        let rdlen = (p.len() - rdata_start) as u16;
        p[rdlen_pos..rdlen_pos + 2].copy_from_slice(&rdlen.to_be_bytes());
        p
    }

    fn write_name(buf: &mut Vec<u8>, labels: &[&str]) {
        for label in labels {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
    }

    #[test]
    fn returns_min_of_ttl_and_minimum() {
        let packet = build_negative_response(300, 60);
        assert_eq!(parse_authority_soa_ttl(&packet), Some(60));

        let packet = build_negative_response(60, 300);
        assert_eq!(parse_authority_soa_ttl(&packet), Some(60));
    }

    #[test]
    fn returns_zero_when_zone_disables_negative_caching() {
        let packet = build_negative_response(0, 300);
        assert_eq!(parse_authority_soa_ttl(&packet), Some(0));

        let packet = build_negative_response(300, 0);
        assert_eq!(parse_authority_soa_ttl(&packet), Some(0));
    }

    #[test]
    fn none_for_response_with_no_authority_section() {
        // qd=1, an=0, ns=0, ar=0
        let mut p = Vec::new();
        p.extend_from_slice(&[0, 0, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0]);
        write_name(&mut p, &["example", "com"]);
        p.extend_from_slice(&ffi::NS_T_A.to_be_bytes());
        p.extend_from_slice(&ffi::NS_C_IN.to_be_bytes());
        assert_eq!(parse_authority_soa_ttl(&p), None);
    }

    #[test]
    fn none_for_truncated_buffer() {
        let packet = build_negative_response(300, 60);
        for trunc in 0..packet.len() {
            // None of these should panic; most should return None.
            let _ = parse_authority_soa_ttl(&packet[..trunc]);
        }
    }

    #[test]
    fn none_for_short_header() {
        assert_eq!(parse_authority_soa_ttl(&[]), None);
        assert_eq!(parse_authority_soa_ttl(&[0; 11]), None);
    }

    #[test]
    fn tolerates_trailing_zeros_after_response() {
        // Simulates `res_nquery` returning -1 with the wire response copied
        // into a larger zeroed buffer: the parser must terminate via header
        // counts, not run off into the padding.
        let mut packet = build_negative_response(120, 90);
        packet.resize(16 * 1024, 0);
        assert_eq!(parse_authority_soa_ttl(&packet), Some(90));
    }
}
