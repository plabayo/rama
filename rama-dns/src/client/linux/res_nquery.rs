use std::{
    mem,
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use rama_core::{
    bytes::Bytes,
    error::BoxError,
    futures::{Stream, async_stream::stream_fn},
    telemetry::tracing,
};
use rama_net::address::Domain;

use libc::c_int;
use tokio::sync::mpsc;

use super::{LinuxDnsResolverError, dns_name_from_domain};

// Large enough for the common UDP path, but not an upper bound for all resolver
// responses. We explicitly error if libresolv reports a larger answer.
const RESPONSE_BUFFER_SIZE: usize = 4096;

pub(super) fn lookup_ipv4_stream(
    domain: Domain,
    timeout: Duration,
) -> impl Stream<Item = Result<Ipv4Addr, BoxError>> + Send {
    lookup_record_stream(domain, timeout, ffi::NS_T_A as c_int, parse_a_response)
}

pub(super) fn lookup_ipv6_stream(
    domain: Domain,
    timeout: Duration,
) -> impl Stream<Item = Result<Ipv6Addr, BoxError>> + Send {
    lookup_record_stream(
        domain,
        timeout,
        ffi::NS_T_AAAA as c_int,
        parse_aaaa_response,
    )
}

pub(super) fn lookup_txt_stream(
    domain: Domain,
    timeout: Duration,
) -> impl Stream<Item = Result<Bytes, BoxError>> + Send {
    lookup_record_stream(domain, timeout, ffi::NS_T_TXT as c_int, parse_txt_response)
}

fn lookup_record_stream<T, P>(
    domain: Domain,
    timeout: Duration,
    rrtype: libc::c_int,
    parser: P,
) -> impl Stream<Item = Result<T, BoxError>> + Send
where
    T: Send + 'static,
    P: Fn(&[u8], &mut dyn FnMut(T)) -> Result<(), BoxError> + Send + 'static,
{
    stream_fn(async move |mut yielder| {
        tracing::debug!(?timeout, %domain, rrtype, "dns::linux: res_nquery");

        let (tx, mut rx) = mpsc::channel(8);
        let join = tokio::task::spawn_blocking(move || {
            lookup_record_packet(domain, rrtype).and_then(|packet| match packet {
                Some(packet) => parser(&packet, &mut |item| {
                    let _ = tx.blocking_send(Ok(item));
                }),
                None => Ok(()),
            })
        });

        loop {
            match tokio::time::timeout(timeout, rx.recv()).await {
                Ok(Some(item)) => yielder.yield_item(item).await,
                Ok(None) => break,
                Err(_) => {
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

#[allow(clippy::needless_pass_by_value)]
fn lookup_record_packet(domain: Domain, rrtype: libc::c_int) -> Result<Option<Vec<u8>>, BoxError> {
    let name = dns_name_from_domain(domain.as_str())?;
    let mut state: ffi::res_state = unsafe { mem::zeroed() };

    // SAFETY: `state` points to writable resolver context storage.
    if unsafe { ffi::res_ninit(&mut state) } != 0 {
        return Err(LinuxDnsResolverError::message("res_ninit failed").into());
    }
    let _guard = ResStateGuard(&mut state as *mut _);

    let mut buffer = vec![0_u8; RESPONSE_BUFFER_SIZE];

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
            return Ok(None);
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

struct ResStateGuard(*mut ffi::res_state);

impl Drop for ResStateGuard {
    fn drop(&mut self) {
        unsafe {
            ffi::res_nclose(self.0);
        }
    }
}

fn parse_a_response(packet: &[u8], emit: &mut dyn FnMut(Ipv4Addr)) -> Result<(), BoxError> {
    parse_answers(packet, ffi::NS_T_A, |rdata| {
        if rdata.len() != 4 {
            return Err(LinuxDnsResolverError::message(format!(
                "invalid A record length: {}",
                rdata.len()
            ))
            .into());
        }
        emit(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
        Ok(())
    })
}

fn parse_aaaa_response(packet: &[u8], emit: &mut dyn FnMut(Ipv6Addr)) -> Result<(), BoxError> {
    parse_answers(packet, ffi::NS_T_AAAA, |rdata| {
        if rdata.len() != 16 {
            return Err(LinuxDnsResolverError::message(format!(
                "invalid AAAA record length: {}",
                rdata.len()
            ))
            .into());
        }
        let mut octets = [0_u8; 16];
        octets.copy_from_slice(rdata);
        emit(Ipv6Addr::from(octets));
        Ok(())
    })
}

fn parse_txt_response(packet: &[u8], emit: &mut dyn FnMut(Bytes)) -> Result<(), BoxError> {
    parse_answers(packet, ffi::NS_T_TXT, |rdata| {
        let mut offset = 0;

        while offset < rdata.len() {
            let len = rdata[offset] as usize;
            offset += 1;
            if offset + len > rdata.len() {
                return Err(LinuxDnsResolverError::message("invalid TXT record payload").into());
            }
            emit(Bytes::copy_from_slice(&rdata[offset..offset + len]));
            offset += len;
        }

        Ok(())
    })
}

fn parse_answers<P>(packet: &[u8], expected_type: u16, mut parser: P) -> Result<(), BoxError>
where
    P: FnMut(&[u8]) -> Result<(), BoxError>,
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
        let rdlen = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlen > packet.len() {
            return Err(LinuxDnsResolverError::message("truncated DNS rdata").into());
        }

        if rrtype == expected_type && rrclass == ffi::NS_C_IN {
            parser(&packet[offset..offset + rdlen])?;
        }

        offset += rdlen;
    }

    Ok(())
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
    use libc::{c_char, c_int, sockaddr_in, sockaddr_in6};

    // DNS class/type constants mirrored from glibc's resolver headers.
    //
    // Sources:
    // - https://codebrowser.dev/glibc/glibc/resolv/arpa/nameser_compat.h.html
    // - https://codebrowser.dev/glibc/glibc/resolv/arpa/nameser.h.html

    /// Internet
    pub(super) const NS_C_IN: u16 = 1;

    /// A (IPv4)
    pub(super) const NS_T_A: u16 = 1;
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

    // Resolver limits from <resolv.h>.
    //
    // Source:
    // - https://codebrowser.dev/glibc/glibc/resolv/resolv.h.html

    /// Max configured nameservers in `res_state.nsaddr_list` / `ResExt.nsaddrs`.
    const MAXNS: usize = 3;
    /// Max search domains in `res_state.dnsrch`.
    const MAXDNSRCH: usize = 6;
    /// Max sortlist entries in `res_state.sort_list`.
    const MAXRESOLVSORT: usize = 10;

    /// Sort address entry embedded in `struct __res_state`.
    ///
    /// Source:
    /// - https://codebrowser.dev/glibc/glibc/resolv/resolv.h.html
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SortAddr {
        addr: libc::in_addr,
        mask: u32,
    }

    /// Resolver extension block embedded in `struct __res_state`.
    ///
    /// Source:
    /// - https://codebrowser.dev/glibc/glibc/resolv/resolv.h.html
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ResExt {
        nscount: u16,
        nsmap: [u16; MAXNS],
        nssocks: [c_int; MAXNS],
        nscount6: u16,
        nsinit: u16,
        nsaddrs: [*mut sockaddr_in6; MAXNS],
        __glibc_reserved: [u32; 2],
    }

    /// Union used by glibc's resolver state for the trailing extension payload.
    ///
    /// Source:
    /// - https://codebrowser.dev/glibc/glibc/resolv/resolv.h.html
    #[repr(C)]
    union U {
        pad: [c_char; 52],
        ext: ResExt,
    }

    /// Thread-safe resolver state used by `res_ninit` / `res_nquery`.
    ///
    /// This mirrors glibc's resolver state layout so we can call the re-entrant
    /// libresolv APIs without relying on generated bindings.
    ///
    /// Source:
    /// - https://codebrowser.dev/glibc/glibc/resolv/resolv.h.html
    #[repr(C)]
    pub(super) struct res_state {
        retrans: c_int,
        retry: c_int,
        options: libc::c_ulong,
        nscount: c_int,
        nsaddr_list: [sockaddr_in; MAXNS],
        id: u16,
        dnsrch: [*mut c_char; MAXDNSRCH + 1],
        defdname: [c_char; 256],
        pfcode: libc::c_ulong,
        ndots: u32,
        nsort: u32,
        ipv6_unavail: u32,
        unused: u32,
        sort_list: [SortAddr; MAXRESOLVSORT],
        __glibc_unused_qhook: *mut libc::c_void,
        __glibc_unused_rhook: *mut libc::c_void,
        pub(super) res_h_errno: c_int,
        _vcsock: c_int,
        _flags: u32,
        _u: U,
    }

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
        pub(super) fn res_ninit(state: *mut res_state) -> c_int;
        #[link_name = "__res_nclose"]
        pub(super) fn res_nclose(state: *mut res_state);
        pub(super) fn res_nquery(
            state: *mut res_state,
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
        pub(super) fn res_ninit(state: *mut res_state) -> c_int;
        pub(super) fn res_nclose(state: *mut res_state);
        pub(super) fn res_nquery(
            state: *mut res_state,
            dname: *const c_char,
            class: c_int,
            typ: c_int,
            answer: *mut u8,
            anslen: c_int,
        ) -> c_int;
    }
}
