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
use rama_utils::octets::kib;

use libc::c_int;
use tokio::sync::mpsc;

use super::{LinuxDnsResolverError, LookupEvent, dns_name_from_domain};
use crate::wire::{RecordType, ServiceBinding};

const INITIAL_RESPONSE_BUFFER_SIZE: usize = kib(16);
const DNS_HEADER_SIZE: usize = 12;
const MAX_DNS_MESSAGE_SIZE: usize = u16::MAX as usize;

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

pub(super) fn lookup_svcb_stream(
    domain: Domain,
    timeout: Duration,
    response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<ServiceBinding>, BoxError>> + Send {
    lookup_service_binding_stream(domain, timeout, response_buffer_size, RecordType::SVCB)
}

pub(super) fn lookup_https_stream(
    domain: Domain,
    timeout: Duration,
    response_buffer_size: usize,
) -> impl Stream<Item = Result<LookupEvent<ServiceBinding>, BoxError>> + Send {
    lookup_service_binding_stream(domain, timeout, response_buffer_size, RecordType::HTTPS)
}

fn lookup_service_binding_stream(
    domain: Domain,
    timeout: Duration,
    response_buffer_size: usize,
    record_type: RecordType,
) -> impl Stream<Item = Result<LookupEvent<ServiceBinding>, BoxError>> + Send {
    lookup_record_stream(
        domain,
        timeout,
        response_buffer_size,
        i32::from(u16::from(record_type)),
        move |packet, emit| parse_service_binding_response(packet, record_type, emit),
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
        tracing::debug!(?timeout, %domain, rrtype, "dns::linux: res_nsearch");

        let (tx, rx) = mpsc::channel(8);
        let join = tokio::task::spawn_blocking(move || {
            // `lookup_record_packet` always returns the wire response (or None
            // for transport errors); NXDOMAIN/NODATA come back as a packet
            // whose answer section is empty but whose authority section
            // typically carries a SOA RR — see RFC 2308 §5.
            let Some(packet) = lookup_record_packet(domain, rrtype, response_buffer_size)? else {
                return Ok(());
            };

            // Parse and validate the complete response before publishing any
            // item. In particular, RFC 9460 section 2.2 requires a malformed
            // SVCB/HTTPS member to invalidate its entire RRset.
            let records = parse_complete_response(&packet, &parser)?;

            if records.is_empty() {
                // Authoritative negative: announce the SOA-derived TTL (per
                // RFC 2308 §5, `min(SOA.TTL, SOA.MINIMUM)`) so the cache can
                // honor the zone's intent rather than a fixed client default.
                let soa_ttl = parse_authority_soa_ttl(&packet);
                _ = tx.blocking_send(Ok(LookupEvent::AuthoritativeNegative { soa_ttl }));
            } else {
                for (item, ttl) in records {
                    _ = tx.blocking_send(Ok(LookupEvent::Record(item, Some(ttl))));
                }
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
                        "linux::res_nsearch: item failed to resolve on time: return timeout error",
                    );
                    // `res_nsearch` is a blocking libc call, so timing out here only stops
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
                        "linux dns res_nsearch task failed: {err}"
                    ))
                    .into()))
                    .await;
            }
            Err(err) => {
                tracing::debug!(
                    "linux::res_nsearch: lookup_record_stream error = {err} (report as timeout)"
                );
                yielder
                    .yield_item(Err(LinuxDnsResolverError::timeout(timeout).into()))
                    .await;
            }
        }
    })
}

fn parse_complete_response<T, P>(packet: &[u8], parser: &P) -> Result<Vec<(T, u32)>, BoxError>
where
    P: Fn(&[u8], &mut dyn FnMut(T, u32)) -> Result<(), BoxError>,
{
    let mut records = Vec::new();
    parser(packet, &mut |item, ttl| records.push((item, ttl)))?;
    Ok(records)
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
    let max_response_size = response_buffer_limit(response_buffer_size)?;
    let name = dns_name_from_domain(domain.as_str())?;
    let mut state: ffi::ResState = unsafe { mem::zeroed() };

    // SAFETY: `state` points to writable resolver context storage.
    if unsafe { ffi::res_ninit(&mut state) } != 0 {
        return Err(LinuxDnsResolverError::message("res_ninit failed").into());
    }
    let _guard = ResStateGuard(&mut state as *mut _);

    let mut buffer = vec![0_u8; INITIAL_RESPONSE_BUFFER_SIZE.min(max_response_size)];

    loop {
        // SAFETY:
        // - `state` is initialized by `res_ninit`.
        // - `name` is a valid NUL-terminated DNS name.
        // - `buffer` is writable response storage.
        //
        // `res_nsearch` (vs `res_nquery`) walks the search list from
        // `/etc/resolv.conf` and applies the `ndots` rule, so short / unqualified
        // names resolve the same way `getaddrinfo` and hickory's system resolver
        // would resolve them.
        let response_len = unsafe {
            ffi::res_nsearch(
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
                tracing::debug!(%domain, rrtype, h_errno, "dns::linux: res_nsearch empty result");
                // glibc copies the wire response into `buffer` before classifying
                // the rcode and returning -1 (see `__libc_res_nsearch` in
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
                "res_nsearch failed (h_errno={h_errno})",
            ))
            .into());
        }

        let response_len = response_len as usize;
        if grow_response_buffer(&mut buffer, response_len, max_response_size)? {
            // libc returns the required wire length when the supplied answer
            // buffer is too small. Retry with exactly that capacity, avoiding
            // a 64 KiB allocation for the overwhelmingly common small answer.
            continue;
        }

        buffer.truncate(response_len);
        return Ok(Some(buffer));
    }
}

fn response_buffer_limit(configured: usize) -> Result<usize, BoxError> {
    if configured < DNS_HEADER_SIZE {
        return Err(LinuxDnsResolverError::message(format!(
            "res_nsearch response buffer size must be at least the {DNS_HEADER_SIZE}-byte DNS header",
        ))
        .into());
    }
    Ok(configured.min(MAX_DNS_MESSAGE_SIZE))
}

fn grow_response_buffer(
    buffer: &mut Vec<u8>,
    required: usize,
    maximum: usize,
) -> Result<bool, BoxError> {
    if required <= buffer.len() {
        return Ok(false);
    }
    if required > maximum {
        return Err(LinuxDnsResolverError::message(format!(
            "res_nsearch response exceeds configured maximum: required={required} maximum={maximum}",
        ))
        .into());
    }
    buffer.resize(required, 0);
    Ok(true)
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

fn parse_service_binding_response(
    packet: &[u8],
    record_type: RecordType,
    emit: &mut dyn FnMut(ServiceBinding, u32),
) -> Result<(), BoxError> {
    parse_answers(packet, record_type.into(), |rdata, ttl| {
        emit(ServiceBinding::parse_rdata(rdata)?, ttl);
        Ok(())
    })
}

fn parse_answers<P>(packet: &[u8], expected_type: u16, mut parser: P) -> Result<(), BoxError>
where
    P: FnMut(&[u8], u32) -> Result<(), BoxError>,
{
    if packet.len() < DNS_HEADER_SIZE {
        return Err(LinuxDnsResolverError::message("short DNS response header").into());
    }

    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;

    let mut offset = DNS_HEADER_SIZE;
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
/// records, only NS, malformed rdata, …) — callers must leave the negative
/// response uncached here.
fn parse_authority_soa_ttl(packet: &[u8]) -> Option<u32> {
    if packet.len() < DNS_HEADER_SIZE {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let nscount = u16::from_be_bytes([packet[8], packet[9]]) as usize;

    let mut offset = DNS_HEADER_SIZE;
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
    // - `res_nsearch` is exported as `res_nsearch`
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
        pub(super) fn res_nsearch(
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
        pub(super) fn res_nsearch(
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
mod response_buffer_tests {
    use super::{DNS_HEADER_SIZE, grow_response_buffer, response_buffer_limit};

    #[test]
    fn rejects_capacities_smaller_than_the_fixed_dns_header() {
        for configured in 0..DNS_HEADER_SIZE {
            let err = response_buffer_limit(configured).expect_err("header would not fit");
            assert!(err.to_string().contains("at least the 12-byte DNS header"));
        }
        assert_eq!(
            response_buffer_limit(DNS_HEADER_SIZE).expect("exact header capacity"),
            DNS_HEADER_SIZE
        );
        assert_eq!(response_buffer_limit(usize::MAX).expect("clamped"), 65_535);
    }

    #[test]
    fn grows_on_demand_up_to_the_configured_maximum() {
        let mut buffer = vec![0; 16 * 1024];
        assert!(grow_response_buffer(&mut buffer, 40_000, 65_535).expect("grow"));
        assert_eq!(buffer.len(), 40_000);
        assert!(!grow_response_buffer(&mut buffer, 40_000, 65_535).expect("already fits"));

        let err = grow_response_buffer(&mut buffer, 65_535, 60_000)
            .expect_err("configured maximum is enforced");
        assert!(err.to_string().contains("required=65535 maximum=60000"));
    }
}

#[cfg(test)]
mod soa_ttl_tests {
    use super::{ffi, parse_authority_soa_ttl};
    use rama_utils::octets::kib;

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
        // Simulates `res_nsearch` returning -1 with the wire response copied
        // into a larger zeroed buffer: the parser must terminate via header
        // counts, not run off into the padding.
        let mut packet = build_negative_response(120, 90);
        packet.resize(kib(16), 0);
        assert_eq!(parse_authority_soa_ttl(&packet), Some(90));
    }
}

#[cfg(test)]
mod service_binding_tests {
    use super::{RecordType, parse_complete_response, parse_service_binding_response};

    fn response(record_type: RecordType, rdata: &[u8]) -> Vec<u8> {
        response_records(record_type, &[rdata])
    }

    fn response_records(record_type: RecordType, rdatas: &[&[u8]]) -> Vec<u8> {
        let mut packet = vec![
            0, 0, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm', 0,
        ];
        packet[6..8].copy_from_slice(
            &u16::try_from(rdatas.len() + 1)
                .expect("short answer list")
                .to_be_bytes(),
        );
        packet.extend_from_slice(&u16::from(record_type).to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());

        // Ancillary CNAME answer.
        packet.extend_from_slice(&[0xc0, 0x0c]);
        packet.extend_from_slice(&5_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&60_u32.to_be_bytes());
        packet.extend_from_slice(&2_u16.to_be_bytes());
        packet.extend_from_slice(&[0xc0, 0x0c]);

        for rdata in rdatas {
            packet.extend_from_slice(&[0xc0, 0x0c]);
            packet.extend_from_slice(&u16::from(record_type).to_be_bytes());
            packet.extend_from_slice(&1_u16.to_be_bytes());
            packet.extend_from_slice(&123_u32.to_be_bytes());
            packet.extend_from_slice(
                &u16::try_from(rdata.len())
                    .expect("short RDATA")
                    .to_be_bytes(),
            );
            packet.extend_from_slice(rdata);
        }
        packet
    }

    #[test]
    fn parses_svcb_and_https_answers_with_ttl() {
        for (record_type, port) in [(RecordType::SVCB, 8443_u16), (RecordType::HTTPS, 443)] {
            let mut rdata = vec![0, 1, 0, 0, 3, 0, 2];
            rdata.extend_from_slice(&port.to_be_bytes());
            let packet = response(record_type, &rdata);
            let mut records = Vec::new();
            parse_service_binding_response(&packet, record_type, &mut |value, ttl| {
                records.push((value, ttl));
            })
            .expect("valid response");

            assert_eq!(records.len(), 1);
            assert_eq!(records[0].0.port(), Some(port));
            assert_eq!(records[0].1, 123);
        }
    }

    #[test]
    fn filters_other_type_and_rejects_malformed_rdata() {
        let packet = response(RecordType::SVCB, &[0, 1, 0]);
        let mut emitted = 0;
        parse_service_binding_response(&packet, RecordType::HTTPS, &mut |_, _| emitted += 1)
            .expect("different type is ignored");
        assert_eq!(emitted, 0);

        let packet = response(RecordType::SVCB, &[0, 1]);
        parse_service_binding_response(&packet, RecordType::SVCB, &mut |_, _| {})
            .expect_err("missing target name");
    }

    #[test]
    fn complete_response_discards_records_before_a_malformed_member() {
        let valid = [0, 1, 0, 0, 3, 0, 2, 0x20, 0xfb];
        let malformed = [0, 1];
        let packet = response_records(RecordType::SVCB, &[&valid, &malformed]);

        parse_complete_response(&packet, &|packet, emit| {
            parse_service_binding_response(packet, RecordType::SVCB, emit)
        })
        .expect_err("one malformed member invalidates the complete response RRset");
    }
}
