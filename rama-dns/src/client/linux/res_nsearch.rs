#![expect(
    clippy::allow_attributes,
    reason = "the bindgen-generated `mod bindings` include uses `#[allow(...)]` for a set of lints whose underlying triggers vary by libc/glibc shape; `#[expect]` would warn unfulfilled on some hosts"
)]

use std::{
    mem,
    net::{Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use rama_core::{
    error::BoxError,
    futures::{Stream, async_stream::stream_fn},
    telemetry::tracing,
};
use rama_net::address::Domain;
use rama_utils::octets::kib;

use libc::c_int;
use tokio::sync::mpsc;

use self::walk::{Asked, Walk};
use super::{LinuxDnsResolverError, LookupEvent, NativeConfig, dns_name_from_domain};
use crate::{
    client::limit::{DnsTimeoutError, deadline_after},
    wire::{Name, RecordType, ServiceBinding, Txt, parse_a_rdata, parse_aaaa_rdata},
};

mod walk;

const INITIAL_RESPONSE_BUFFER_SIZE: usize = kib(16);
const DNS_HEADER_SIZE: usize = 12;
const MAX_DNS_MESSAGE_SIZE: usize = u16::MAX as usize;

pub(super) fn lookup_ipv4_stream(
    domain: Domain,
    timeout: Duration,
    native: NativeConfig,
) -> impl Stream<Item = Result<LookupEvent<Ipv4Addr>, BoxError>> + Send {
    lookup_record_stream(
        domain,
        timeout,
        native,
        ffi::NS_T_A as c_int,
        parse_a_response,
    )
}

pub(super) fn lookup_ipv6_stream(
    domain: Domain,
    timeout: Duration,
    native: NativeConfig,
) -> impl Stream<Item = Result<LookupEvent<Ipv6Addr>, BoxError>> + Send {
    lookup_record_stream(
        domain,
        timeout,
        native,
        ffi::NS_T_AAAA as c_int,
        parse_aaaa_response,
    )
}

pub(super) fn lookup_txt_stream(
    domain: Domain,
    timeout: Duration,
    native: NativeConfig,
) -> impl Stream<Item = Result<LookupEvent<Txt>, BoxError>> + Send {
    lookup_record_stream(
        domain,
        timeout,
        native,
        ffi::NS_T_TXT as c_int,
        parse_txt_response,
    )
}

pub(super) fn lookup_cname_stream(
    domain: Domain,
    timeout: Duration,
    native: NativeConfig,
) -> impl Stream<Item = Result<LookupEvent<Name>, BoxError>> + Send {
    lookup_record_stream(
        domain,
        timeout,
        native,
        ffi::NS_T_CNAME as c_int,
        parse_cname_response,
    )
}

pub(super) fn lookup_svcb_stream(
    domain: Domain,
    timeout: Duration,
    native: NativeConfig,
) -> impl Stream<Item = Result<LookupEvent<ServiceBinding>, BoxError>> + Send {
    lookup_service_binding_stream(domain, timeout, native, RecordType::SVCB)
}

pub(super) fn lookup_https_stream(
    domain: Domain,
    timeout: Duration,
    native: NativeConfig,
) -> impl Stream<Item = Result<LookupEvent<ServiceBinding>, BoxError>> + Send {
    lookup_service_binding_stream(domain, timeout, native, RecordType::HTTPS)
}

fn lookup_service_binding_stream(
    domain: Domain,
    timeout: Duration,
    native: NativeConfig,
    record_type: RecordType,
) -> impl Stream<Item = Result<LookupEvent<ServiceBinding>, BoxError>> + Send {
    lookup_record_stream(
        domain,
        timeout,
        native,
        i32::from(u16::from(record_type)),
        move |packet, emit| parse_service_binding_response(packet, record_type, emit),
    )
}

fn lookup_record_stream<T, P>(
    domain: Domain,
    timeout: Duration,
    native: NativeConfig,
    rrtype: libc::c_int,
    parser: P,
) -> impl Stream<Item = Result<LookupEvent<T>, BoxError>> + Send
where
    T: Send + 'static,
    P: Fn(&[u8], &mut dyn FnMut(T, u32)) -> Result<(), BoxError> + Send + 'static,
{
    stream_fn(async move |mut yielder| {
        tracing::debug!(?timeout, %domain, rrtype, "dns::linux: res_nsearch");

        let deadline = deadline_after(timeout);
        let (tx, mut rx) = mpsc::channel(8);
        let response_buffer_size = native.response_buffer_size;
        let task = native.limit.spawn_blocking(deadline, move |budget| {
            if budget.is_zero() {
                return Err(DnsTimeoutError::new(timeout).into());
            }
            // `lookup_record_packet` always returns the wire response (or None
            // for transport errors); NXDOMAIN/NODATA come back as a packet
            // whose answer section is empty but whose authority section
            // typically carries a SOA RR — see RFC 2308 §5.
            let Some(packet) =
                lookup_record_packet(domain, rrtype, response_buffer_size, budget, timeout)?
            else {
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
        let Some(join) = task.await else {
            tracing::debug!("linux::res_nsearch: no native lookup slot before the deadline");
            yielder
                .yield_item(Err(DnsTimeoutError::new(timeout).into()))
                .await;
            return;
        };

        loop {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(item)) => yielder.yield_item(item).await,
                Ok(None) => break,
                Err(err) => {
                    tracing::debug!(
                        %err,
                        "linux::res_nsearch: item failed to resolve on time: return timeout error",
                    );
                    // the libc lookup is a blocking call, so timing out here only stops
                    // waiting for the worker result; it does not cancel the underlying OS
                    // resolver call once it has started.
                    yielder
                        .yield_item(Err(DnsTimeoutError::new(timeout).into()))
                        .await;
                    return;
                }
            }
        }

        match join.await {
            Ok(Ok(())) => {}
            // as is, so a timeout stays a `DnsTimeoutError`
            Ok(Err(err)) => yielder.yield_item(Err(err)).await,
            Err(err) => {
                tracing::debug!(
                    "linux::res_nsearch: lookup_record_stream error = {err} (report as timeout)"
                );
                yielder
                    .yield_item(Err(DnsTimeoutError::new(timeout).into()))
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
    budget: Duration,
    timeout: Duration,
) -> Result<Option<Vec<u8>>, BoxError> {
    let max_response_size = response_buffer_limit(response_buffer_size)?;
    let deadline = Instant::now() + budget;
    let mut state: ffi::ResState = unsafe { mem::zeroed() };

    // SAFETY: `state` points to writable resolver context storage.
    if unsafe { ffi::res_ninit(&mut state) } != 0 {
        return Err(LinuxDnsResolverError::message("res_ninit failed").into());
    }
    // every later access goes through the guard, so its drop never aliases
    let nscount = state.nscount;
    let mut state = ResStateGuard(&mut state, nscount);
    #[cfg(test)]
    stub_tests::use_stub(state.0, domain.as_str());
    state.1 = state.0.nscount;
    // TCP is asked here, unlike by libc within the deadline: for a truncated
    // answer, and for every name with `use-vc`
    let tries = walk::Tries {
        retrans: state.0.retrans,
        retry: state.0.retry,
        nscount: state.0.nscount,
        tcp: state.0.options & ffi::RES_USEVC != 0,
    };
    state.0.options |= ffi::RES_IGNTC;

    let alias = walk::hostalias(domain.as_str());
    let walk = Walk::new(state.0, domain.as_str(), alias, walk::full_search_list)?;
    let mut outcomes = walk.outcomes();
    loop {
        let at = walk.run(&mut outcomes, deadline, |name, budget| {
            let asked = walk::ask(state.0, tries, name, rrtype, max_response_size, budget);
            // a short budget asks fewer nameservers, the next name all again
            state.0.nscount = tries.nscount;
            asked
        });
        if matches!(outcomes[at], Some(Asked::Timeout)) {
            // a caching stub may hold a late answer by now
            let timed_out = outcomes
                .iter()
                .filter(|outcome| matches!(outcome, Some(Asked::Timeout)))
                .count();
            if walk::another_try(state.0, deadline, timed_out) {
                for outcome in &mut outcomes {
                    if matches!(outcome, Some(Asked::Timeout)) {
                        *outcome = None;
                    }
                }
                continue;
            }
        }
        let Some(decided) = outcomes[at].take() else {
            return Err(
                LinuxDnsResolverError::message("dns lookup ended without an answer").into(),
            );
        };
        if let Asked::NxDomain(_) | Asked::NoData(_) = decided {
            tracing::debug!(%domain, rrtype, "dns::linux: res_nquery empty result");
        }
        return decided.into_packet(timeout);
    }
}

/// libc leaves `errno` alone on success, so a value from an earlier call on
/// this thread must not pass for this call's.
fn clear_errno() {
    // SAFETY: returns this thread's errno slot, valid for its lifetime
    let errno = unsafe { libc::__errno_location() };
    // SAFETY: the slot is this thread's own and writable
    unsafe { *errno = 0 };
}

/// Shorten libc's retransmits so one name's tries land inside `budget`: by
/// default one lost datagram would use up the whole budget.
///
/// Fewer tries are made only when even a second per send does not fit.
fn fit_retransmits(state: &mut ffi::ResState, budget: Duration) {
    let budget = whole_secs(budget).max(1);
    // libc waits a second per nameserver at least: ask fewer if all do not fit
    if state.nscount > budget {
        state.nscount = budget;
    }
    let nscount = state.nscount.clamp(1, MAX_NAMESERVERS);
    let total = |retrans, retry: c_int| retry.max(1).saturating_mul(try_secs(retrans, nscount));

    let mut retrans = state.retrans.max(1);
    while retrans > 1 && total(retrans, state.retry) > budget {
        retrans -= 1;
    }
    state.retrans = retrans;
    if total(retrans, state.retry) > budget {
        state.retry = (budget / try_secs(retrans, nscount)).max(1);
    }
}

/// `budget` to the nearest second, the unit libc waits in: the budget arrives a
/// little short of the timeout, so its last second is kept.
fn whole_secs(budget: Duration) -> c_int {
    c_int::try_from(budget.saturating_add(Duration::from_millis(500)).as_secs())
        .unwrap_or(c_int::MAX)
}

/// Seconds one try waits on all nameservers, as glibc's `send_dg` computes it.
fn try_secs(retrans: c_int, nscount: c_int) -> c_int {
    (0..nscount)
        .map(|ns| {
            let secs = retrans.saturating_mul(1 << ns);
            let secs = if ns > 0 { secs / nscount } else { secs };
            secs.max(1)
        })
        .fold(0, c_int::saturating_add)
}

/// `MAXNS` in `<resolv.h>`.
const MAX_NAMESERVERS: c_int = 3;

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

/// The state and its nameserver count: a lookup may ask fewer nameservers,
/// but libc frees its copies of only those counted when it closes.
struct ResStateGuard<'a>(&'a mut ffi::ResState, c_int);

impl Drop for ResStateGuard<'_> {
    fn drop(&mut self) {
        self.0.nscount = self.1;
        // SAFETY: the state was initialized by `res_ninit` and is closed once.
        unsafe {
            ffi::res_nclose(self.0);
        }
    }
}

fn parse_a_response(packet: &[u8], emit: &mut dyn FnMut(Ipv4Addr, u32)) -> Result<(), BoxError> {
    parse_answers(packet, ffi::NS_T_A, |packet, rdata, ttl| {
        emit(parse_a_rdata(&packet[rdata])?, ttl);
        Ok(())
    })
}

fn parse_aaaa_response(packet: &[u8], emit: &mut dyn FnMut(Ipv6Addr, u32)) -> Result<(), BoxError> {
    parse_answers(packet, ffi::NS_T_AAAA, |packet, rdata, ttl| {
        emit(parse_aaaa_rdata(&packet[rdata])?, ttl);
        Ok(())
    })
}

fn parse_txt_response(packet: &[u8], emit: &mut dyn FnMut(Txt, u32)) -> Result<(), BoxError> {
    parse_answers(packet, ffi::NS_T_TXT, |packet, rdata, ttl| {
        emit(Txt::parse_rdata(&packet[rdata])?, ttl);
        Ok(())
    })
}

fn parse_cname_response(packet: &[u8], emit: &mut dyn FnMut(Name, u32)) -> Result<(), BoxError> {
    parse_answers(packet, ffi::NS_T_CNAME, |packet, rdata, ttl| {
        let rdata_len = rdata.len();
        let (name, consumed) = Name::from_message(packet, rdata.start)?;
        if consumed != rdata_len {
            return Err(LinuxDnsResolverError::message(
                "CNAME RDATA contains data after its target name",
            )
            .into());
        }
        emit(name, ttl);
        Ok(())
    })
}

fn parse_service_binding_response(
    packet: &[u8],
    record_type: RecordType,
    emit: &mut dyn FnMut(ServiceBinding, u32),
) -> Result<(), BoxError> {
    parse_answers(packet, record_type.into(), |packet, rdata, ttl| {
        emit(ServiceBinding::parse_rdata(&packet[rdata])?, ttl);
        Ok(())
    })
}

fn parse_answers<P>(packet: &[u8], expected_type: u16, mut parser: P) -> Result<(), BoxError>
where
    P: FnMut(&[u8], std::ops::Range<usize>, u32) -> Result<(), BoxError>,
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
            parser(packet, offset..offset + rdlen, ttl)?;
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
    /// CNAME (canonical name)
    pub(super) const NS_T_CNAME: u16 = 5;
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
    /// Non-authoritative failure: SERVFAIL, or no nameserver answered.
    pub(super) const TRY_AGAIN: c_int = 2;
    /// Non-recoverable failure, e.g. FORMERR or a name too long to ask.
    #[cfg(test)]
    pub(super) const NO_RECOVERY: c_int = 3;
    /// Valid name, no data record of requested type.
    pub(super) const NO_DATA: c_int = 4;

    // Search options from glibc's <resolv.h>.

    /// Search a name without dots in the default domain.
    pub(super) const RES_DEFNAMES: libc::c_ulong = 0x80;
    /// Search a dotted relative name in the search list.
    pub(super) const RES_DNSRCH: libc::c_ulong = 0x200;
    /// Take a truncated answer as is, rather than asking again over TCP.
    pub(super) const RES_IGNTC: libc::c_ulong = 0x20;
    /// Ask over TCP only (`use-vc`).
    pub(super) const RES_USEVC: libc::c_ulong = 0x08;
    /// Do not ask a name without dots as is once it was searched.
    pub(super) const RES_NOTLDQUERY: libc::c_ulong = 0x0100_0000;

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
    pub(super) type SockaddrIn = bindings::sockaddr_in;

    // GNU/Linux changed the public resolver symbol mapping in glibc 2.34.
    // Compile a small C shim against the target's `<resolv.h>` so native and
    // cross toolchains each select the mapping appropriate for their glibc ABI.
    //
    // Sources:
    // - https://codebrowser.dev/glibc/glibc/resolv/res_init.c.html
    // - https://codebrowser.dev/glibc/glibc/resolv/res-close.c.html
    // - https://codebrowser.dev/glibc/glibc/resolv/res_query.c.html
    // - https://man7.org/linux/man-pages/man3/resolver.3.html
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[link(name = "resolv")]
    unsafe extern "C" {
        #[link_name = "rama_res_ninit"]
        pub(super) fn res_ninit(state: *mut ResState) -> c_int;
        #[link_name = "rama_res_nclose"]
        pub(super) fn res_nclose(state: *mut ResState);
        #[link_name = "rama_res_nquery"]
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
mod stub_tests {
    use std::assert_matches;
    use std::{
        ffi::CStr,
        io::{Read as _, Write as _},
        net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket},
        ptr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant},
    };

    use parking_lot::Mutex;
    use rama_core::futures::StreamExt as _;
    use rama_net::address::Domain;

    use super::{
        DnsTimeoutError, NativeConfig, ffi, lookup_ipv4_stream, lookup_record_packet,
        parse_txt_response,
    };
    use crate::client::limit::{Limits, LookupLimit};

    struct Stub {
        name: &'static str,
        port: u16,
        options: Options,
    }

    /// How a lookup sees its stub.
    #[derive(Clone, Copy)]
    struct Options {
        search: Option<&'static CStr>,
        sends: libc::c_int,
        /// `use-vc`: TCP only.
        tcp_only: bool,
        /// A nameserver that never answers comes first.
        dead_first: Option<u16>,
    }

    impl Options {
        fn new(search: Option<&'static CStr>, sends: libc::c_int) -> Self {
            Self {
                search,
                sends,
                tcp_only: false,
                dead_first: None,
            }
        }
    }

    static STUBS: Mutex<Vec<Stub>> = Mutex::new(Vec::new());

    /// Called by the lookup itself, right after `res_ninit`.
    pub(super) fn use_stub(state: &mut ffi::ResState, name: &str) {
        let stubs = STUBS.lock();
        let Some(stub) = stubs.iter().find(|stub| stub.name == name) else {
            return;
        };
        let options = stub.options;
        // a second per send
        state.retrans = 1;
        state.retry = options.sends;
        state.nscount = 0;
        for port in [options.dead_first, Some(stub.port)].into_iter().flatten() {
            let ns = usize::try_from(state.nscount).expect("a nameserver index");
            let nameserver = &mut state.nsaddr_list[ns];
            nameserver.sin_family = libc::AF_INET as _;
            nameserver.sin_port = port.to_be();
            nameserver.sin_addr.s_addr = u32::from(Ipv4Addr::LOCALHOST).to_be();
            // an IPv6 nameserver from resolv.conf would take precedence
            // SAFETY: `res_ninit` initialized `_ext`, the variant glibc uses
            unsafe { state._u._ext.nsaddrs[ns] = ptr::null_mut() };
            state.nscount += 1;
        }
        state.dnsrch = [ptr::null_mut(); 7];
        if let Some(search) = options.search {
            state.dnsrch[0] = search.as_ptr().cast_mut();
        }
        state.set_ndots(1);
        // no OPT record after the question, which the stub matches on
        state.options &= !RES_USE_EDNS0;
        if options.tcp_only {
            state.options |= ffi::RES_USEVC;
        }
    }

    /// A nameserver that takes queries, over UDP and TCP, and never answers.
    fn dead_nameserver() -> u16 {
        static DEAD: Mutex<Vec<(UdpSocket, TcpListener)>> = Mutex::new(Vec::new());
        loop {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind dead stub");
            let port = socket.local_addr().expect("dead stub addr").port();
            if let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, port)) {
                DEAD.lock().push((socket, listener));
                return port;
            }
        }
    }

    /// `RES_USE_EDNS0` in glibc's <resolv.h>.
    const RES_USE_EDNS0: libc::c_ulong = 0x0010_0000;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Reply {
        Silence,
        Rcode(u8),
        /// Ignore the first query, answer the rest with 127.0.0.1.
        SecondTime,
        /// NXDOMAIN for names under `corp.test`, silence for the rest.
        SearchOnly,
        /// A reply too short to hold a header.
        Undersized,
        /// SERVFAIL after 950ms, NXDOMAIN at once for names under `corp.test`.
        SlowServfail,
        /// A truncated answer, which TCP then completes or does not.
        Truncated(Tcp),
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Tcp {
        /// [`TXT_RECORDS`] TXT records, too many for a datagram.
        Txt,
        /// The same, a few bytes at a time.
        Trickle,
        /// One byte of the answer, then nothing.
        Stall,
        /// Takes the query, never answers.
        Silence,
        /// Not listening at all.
        Closed,
    }

    const TXT_RECORDS: usize = 8;

    /// What a stub saw and did.
    #[derive(Default)]
    struct Seen {
        queries: AtomicUsize,
        replies: AtomicUsize,
        tcp_queries: AtomicUsize,
    }

    impl Seen {
        fn tcp_queries(&self) -> usize {
            self.tcp_queries.load(Ordering::SeqCst)
        }

        fn queries(&self) -> usize {
            self.queries.load(Ordering::SeqCst)
        }

        fn replies(&self) -> usize {
            self.replies.load(Ordering::SeqCst)
        }
    }

    /// Serves `name` from a loopback stub, which libc asks up to `sends`
    /// times per name.
    fn serve(
        name: &'static str,
        search: Option<&'static CStr>,
        sends: libc::c_int,
        reply: Reply,
    ) -> Arc<Seen> {
        serve_with(name, reply, Options::new(search, sends))
    }

    fn serve_with(name: &'static str, reply: Reply, options: Options) -> Arc<Seen> {
        // TCP on the same port, unless it is to refuse
        let (socket, listener) = loop {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind stub");
            let port = socket.local_addr().expect("stub addr").port();
            if reply == Reply::Truncated(Tcp::Closed) {
                break (socket, None);
            }
            if let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, port)) {
                break (socket, Some(listener));
            }
        };
        let port = socket.local_addr().expect("stub addr").port();
        STUBS.lock().push(Stub {
            name,
            port,
            options,
        });
        let stub = Arc::new(Seen::default());
        if let (Some(listener), Reply::Truncated(tcp)) = (listener, reply) {
            let seen = stub.clone();
            thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    seen.tcp_queries.fetch_add(1, Ordering::SeqCst);
                    serve_tcp(stream, tcp);
                }
            });
        }
        let seen = stub.clone();
        thread::spawn(move || {
            let mut packet = [0; 512];
            while let Ok((len, peer)) = socket.recv_from(&mut packet) {
                let nth = seen.queries.fetch_add(1, Ordering::SeqCst);
                let query = &packet[..len];
                let response = match reply {
                    Reply::SecondTime if nth == 0 => continue,
                    Reply::SearchOnly | Reply::SlowServfail
                        if query.ends_with(SEARCH_DOMAIN_A_QUESTION) =>
                    {
                        header_only(query, 3)
                    }
                    Reply::Silence | Reply::SearchOnly => continue,
                    Reply::Rcode(rcode) => header_only(query, rcode),
                    Reply::SecondTime => with_loopback_answer(query),
                    Reply::Undersized => query[..2].to_vec(),
                    Reply::SlowServfail => {
                        thread::sleep(Duration::from_millis(950));
                        header_only(query, 2)
                    }
                    Reply::Truncated(_) => {
                        let mut response = header_only(query, 0);
                        response[2] |= 0x02;
                        response
                    }
                };
                seen.replies.fetch_add(1, Ordering::SeqCst);
                _ = socket.send_to(&response, peer);
            }
        });
        stub
    }

    /// The end of an A question for a name under `corp.test`.
    const SEARCH_DOMAIN_A_QUESTION: &[u8] = b"\x04corp\x04test\x00\x00\x01\x00\x01";

    /// Answers one TCP query as `tcp` says.
    fn serve_tcp(mut stream: TcpStream, tcp: Tcp) {
        let mut len = [0; 2];
        if stream.read_exact(&mut len).is_err() {
            return;
        }
        let mut query = vec![0; usize::from(u16::from_be_bytes(len))];
        if stream.read_exact(&mut query).is_err() {
            return;
        }
        if tcp == Tcp::Silence {
            // hold the connection open until the client leaves
            _ = stream.read(&mut [0; 1]);
            return;
        }
        let mut response = header_only(&query, 0);
        response[7] = TXT_RECORDS as u8;
        for _ in 0..TXT_RECORDS {
            response.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 60, 0, 201, 200]);
            response.extend_from_slice(&[b'x'; 200]);
        }
        let len = u16::try_from(response.len()).expect("small answer");
        let framed = [len.to_be_bytes().as_slice(), &response].concat();
        match tcp {
            Tcp::Trickle => {
                for piece in framed.chunks(500) {
                    _ = stream.write_all(&piece[..1]);
                    thread::sleep(Duration::from_millis(20));
                    _ = stream.write_all(&piece[1..]);
                    thread::sleep(Duration::from_millis(20));
                }
            }
            Tcp::Stall => {
                _ = stream.write_all(&framed[..1]);
                _ = stream.read(&mut [0; 1]);
            }
            _ => _ = stream.write_all(&framed),
        }
    }

    fn header_only(query: &[u8], rcode: u8) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2] = 0x81;
        response[3] = 0x80 | rcode;
        response
    }

    fn with_loopback_answer(query: &[u8]) -> Vec<u8> {
        let mut response = header_only(query, 0);
        response[7] = 1;
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
        response
    }

    fn lookup(
        name: &'static str,
        budget: Duration,
    ) -> Result<Option<Vec<u8>>, rama_core::error::BoxError> {
        lookup_type(name, ffi::NS_T_A, budget)
    }

    fn lookup_type(
        name: &'static str,
        rrtype: u16,
        budget: Duration,
    ) -> Result<Option<Vec<u8>>, rama_core::error::BoxError> {
        let domain = Domain::from_static(name);
        lookup_record_packet(domain, libc::c_int::from(rrtype), 4096, budget, budget)
    }

    #[test]
    fn a_truncated_answer_is_asked_again_over_tcp() {
        let stub = serve("big.stub.test", None, 1, Reply::Truncated(Tcp::Txt));
        let packet = lookup_type("big.stub.test", ffi::NS_T_TXT, Duration::from_secs(2))
            .expect("the TCP answer")
            .expect("its response");
        let mut texts = Vec::new();
        parse_txt_response(&packet, &mut |text, _| texts.push(text)).expect("TXT records");
        assert_eq!(texts.len(), TXT_RECORDS);
        assert_eq!((stub.queries(), stub.tcp_queries()), (1, 1));
    }

    #[test]
    fn a_silent_tcp_retry_ends_with_the_budget() {
        let stub = serve("hush.stub.test", None, 1, Reply::Truncated(Tcp::Silence));
        let started = Instant::now();
        // its own thread: libc's TCP retry would block it for good
        let (done, lookup_ended) = mpsc::channel();
        thread::spawn(move || {
            _ = done.send(lookup("hush.stub.test", Duration::from_millis(1400)));
        });
        let ended = lookup_ended
            .recv_timeout(Duration::from_secs(10))
            .expect("the lookup hangs on a silent TCP retry");
        let err = ended.expect_err("silence");
        assert!(err.downcast_ref::<DnsTimeoutError>().is_some(), "{err}");
        assert!(started.elapsed() < Duration::from_millis(1900));
        assert_eq!(stub.tcp_queries(), 1);
    }

    #[test]
    fn a_tcp_answer_in_pieces_is_read_whole() {
        _ = serve("drip.stub.test", None, 1, Reply::Truncated(Tcp::Trickle));
        let packet = lookup_type("drip.stub.test", ffi::NS_T_TXT, Duration::from_secs(2))
            .expect("the TCP answer")
            .expect("its response");
        let mut texts = 0;
        parse_txt_response(&packet, &mut |_, _| texts += 1).expect("TXT records");
        assert_eq!(texts, TXT_RECORDS);
    }

    /// `lookup`, on a thread of its own, unless it hangs.
    fn lookup_or_hang(name: &'static str, budget: Duration) -> rama_core::error::BoxError {
        let (done, ended) = mpsc::channel();
        thread::spawn(move || _ = done.send(lookup(name, budget)));
        ended
            .recv_timeout(Duration::from_secs(10))
            .expect("the lookup hangs")
            .expect_err("no answer")
    }

    #[test]
    fn a_stalled_tcp_answer_ends_with_the_budget() {
        _ = serve("stall.stub.test", None, 1, Reply::Truncated(Tcp::Stall));
        let started = Instant::now();
        let err = lookup_or_hang("stall.stub.test", Duration::from_millis(1400));
        assert!(err.downcast_ref::<DnsTimeoutError>().is_some(), "{err}");
        assert!(started.elapsed() < Duration::from_millis(1900));
    }

    #[test]
    fn a_tcp_retry_moves_on_to_the_next_nameserver() {
        let options = Options {
            dead_first: Some(dead_nameserver()),
            ..Options::new(None, 1)
        };
        let stub = serve_with("next.stub.test", Reply::Truncated(Tcp::Txt), options);
        let started = Instant::now();
        let packet = lookup_type("next.stub.test", ffi::NS_T_TXT, Duration::from_secs(3))
            .expect("the second nameserver's TCP answer")
            .expect("its response");
        let mut texts = 0;
        parse_txt_response(&packet, &mut |_, _| texts += 1).expect("TXT records");
        assert_eq!(texts, TXT_RECORDS);
        assert_eq!(stub.tcp_queries(), 1);
        assert!(started.elapsed() < Duration::from_millis(3500));
    }

    #[test]
    fn use_vc_asks_over_tcp_only() {
        let options = Options {
            tcp_only: true,
            ..Options::new(None, 1)
        };
        let stub = serve_with("vc.stub.test", Reply::Truncated(Tcp::Txt), options);
        let packet = lookup_type("vc.stub.test", ffi::NS_T_TXT, Duration::from_secs(2))
            .expect("the TCP answer")
            .expect("its response");
        let mut texts = 0;
        parse_txt_response(&packet, &mut |_, _| texts += 1).expect("TXT records");
        assert_eq!(texts, TXT_RECORDS);
        assert_eq!((stub.queries(), stub.tcp_queries()), (0, 1));

        // and ends with the budget, where libc's own TCP would not
        _ = serve_with("vc-hush.stub.test", Reply::Truncated(Tcp::Silence), options);
        let started = Instant::now();
        let err = lookup_or_hang("vc-hush.stub.test", Duration::from_millis(1400));
        assert!(err.downcast_ref::<DnsTimeoutError>().is_some(), "{err}");
        assert!(started.elapsed() < Duration::from_millis(1900));
    }

    #[test]
    fn a_refused_tcp_retry_is_an_error() {
        _ = serve("closed.stub.test", None, 1, Reply::Truncated(Tcp::Closed));
        let started = Instant::now();
        let err = lookup("closed.stub.test", Duration::from_secs(2)).expect_err("no TCP");
        assert!(err.downcast_ref::<DnsTimeoutError>().is_none(), "{err}");
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_slow_servfail_next_to_a_search_answer_is_an_error() {
        // `slow.stub` gets SERVFAIL after 950ms, `slow.stub.corp.test` NXDOMAIN
        let stub = serve("slow.stub", Some(c"corp.test"), 1, Reply::SlowServfail);
        let started = Instant::now();
        let err = lookup("slow.stub", Duration::from_millis(4990)).expect_err("SERVFAIL");
        assert!(err.downcast_ref::<DnsTimeoutError>().is_none(), "{err}");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(stub.queries(), 2);
    }

    #[test]
    fn a_servfail_is_an_answer_not_a_timeout() {
        for (name, rcode) in [("servfail.stub.test", 2), ("refused.stub.test", 5)] {
            let stub = serve(name, None, 1, Reply::Rcode(rcode));
            let started = Instant::now();
            let err = lookup(name, Duration::from_millis(4990)).expect_err("an error answer");
            assert!(err.downcast_ref::<DnsTimeoutError>().is_none(), "{err}");
            assert!(started.elapsed() < Duration::from_secs(1));
            assert!(stub.queries() <= 4, "{}", stub.queries());
        }
    }

    #[test]
    fn a_timeout_next_to_a_search_answer_is_still_a_timeout() {
        // a single label asks `corp.test` first, a dotted name asks it last;
        // under `corp.test` comes NXDOMAIN, the name as is gets silence
        for name in ["stalehdr", "stalehdr.stub"] {
            let stub = serve(name, Some(c"corp.test"), 1, Reply::SearchOnly);
            let started = Instant::now();
            let err = lookup(name, Duration::from_millis(2400)).expect_err("silence");
            assert!(
                err.downcast_ref::<DnsTimeoutError>().is_some(),
                "{name}: {err}"
            );
            assert!(stub.queries() >= 2, "{name}: {}", stub.queries());
            assert!(stub.replies() >= 1, "{name}: no NXDOMAIN under `corp.test`");
            assert!(started.elapsed() < Duration::from_millis(2900), "{name}");
        }
    }

    #[test]
    fn a_reply_rejected_at_once_is_not_asked_again() {
        let stub = serve("undersized.stub.test", None, 1, Reply::Undersized);
        let started = Instant::now();
        let err = lookup("undersized.stub.test", Duration::from_millis(2400))
            .expect_err("an unusable reply");
        assert!(err.downcast_ref::<DnsTimeoutError>().is_none(), "{err}");
        assert!(stub.queries() <= 4, "{}", stub.queries());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_timed_out_query_is_asked_again_within_the_budget() {
        let stub = serve("again.stub.test", None, 1, Reply::SecondTime);
        let started = Instant::now();
        let packet = lookup("again.stub.test", Duration::from_millis(2400))
            .expect("answered the second time")
            .expect("a response");
        assert_eq!(packet[7], 1, "one answer");
        assert_eq!(stub.queries(), 2);
        assert!(started.elapsed() < Duration::from_millis(2400));
    }

    #[test]
    fn a_silent_stub_times_out_within_the_budget() {
        let stub = serve("silent.stub.test", None, 1, Reply::Silence);
        let started = Instant::now();
        let err = lookup("silent.stub.test", Duration::from_millis(1400)).expect_err("silence");
        assert!(err.downcast_ref::<DnsTimeoutError>().is_some(), "{err}");
        // another 1s walk no longer fits in what is left
        assert_eq!(stub.queries(), 1);
        assert!(started.elapsed() < Duration::from_millis(1900));
    }

    #[test]
    fn two_names_share_the_budget() {
        let stub = serve("split.stub.test", Some(c"corp.test"), 2, Reply::Silence);
        let started = Instant::now();
        let err = lookup("split.stub.test", Duration::from_millis(2400)).expect_err("silence");
        assert!(err.downcast_ref::<DnsTimeoutError>().is_some(), "{err}");
        // as is, then with `corp.test`: one send of a second each, not two
        assert_eq!(stub.queries(), 2);
        assert!(started.elapsed() < Duration::from_millis(2900));
    }

    #[test]
    fn only_the_root_to_search_asks_once() {
        let stub = serve("rooted.stub.test", Some(c"."), 1, Reply::Rcode(3));
        let packet = lookup("rooted.stub.test", Duration::from_secs(2))
            .expect("a negative answer")
            .expect("its response");
        assert_eq!(packet[3] & 0x0f, 3, "NXDOMAIN");
        // as is and then rooted would be the same query twice
        assert_eq!(stub.queries(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_native_timeout_reaches_the_caller_as_itself() {
        _ = serve("caller.stub.test", None, 1, Reply::Silence);
        let native = NativeConfig {
            response_buffer_size: 4096,
            limit: LookupLimit::new(Limits::ONE_QUERY),
        };
        let timeout = Duration::from_millis(1400);
        let items: Vec<_> =
            lookup_ipv4_stream(Domain::from_static("caller.stub.test"), timeout, native)
                .collect()
                .await;
        assert_matches!(
            items.as_slice(),
            [Err(err)] if err
                .downcast_ref::<DnsTimeoutError>()
                .is_some_and(|err| err.timeout() == timeout),
            "{:?}",
            items
                .iter()
                .map(|item| item.as_ref().err().map(ToString::to_string))
                .collect::<Vec<_>>(),
        );
    }
}

#[cfg(test)]
mod response_buffer_tests {
    use std::{mem, time::Duration};

    use super::{
        DNS_HEADER_SIZE, ResStateGuard, clear_errno, ffi, fit_retransmits, grow_response_buffer,
        response_buffer_limit, try_secs, whole_secs,
    };

    #[test]
    fn a_stale_errno_is_cleared() {
        // SAFETY: closing an invalid fd only sets errno
        let closed = unsafe { libc::close(-1) };
        assert_eq!(closed, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
        clear_errno();
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(0));
    }

    /// `(retrans, retry)` after fitting, and the seconds one name may then wait.
    fn fitted(
        retrans: libc::c_int,
        retry: libc::c_int,
        nscount: libc::c_int,
        budget: Duration,
    ) -> (libc::c_int, libc::c_int, libc::c_int) {
        // SAFETY: `__res_state` is plain old data; zeroed is a valid value.
        let mut state: ffi::ResState = unsafe { mem::zeroed() };
        state.retrans = retrans;
        state.retry = retry;
        state.nscount = nscount;
        fit_retransmits(&mut state, budget);
        let waited = state.retry.max(1) * try_secs(state.retrans, state.nscount.clamp(1, 3));
        (state.retrans, state.retry, waited)
    }

    #[test]
    fn retransmits_fit_the_lookup_budget() {
        let secs = Duration::from_secs;
        // glibc defaults against one stub: retransmit after 2s, not at 5s
        assert_eq!(fitted(5, 2, 1, secs(5)), (2, 2, 4));
        // glibc waits at least a second per send, so drop a try instead
        assert_eq!(fitted(5, 2, 3, secs(5)), (1, 1, 3));
        assert_eq!(fitted(5, 2, 1, secs(1)), (1, 1, 1));
        // three nameservers do not fit two seconds: ask the first two
        assert_eq!(fitted(5, 2, 3, secs(2)), (1, 1, 2));
        // a hostile `options timeout:30 attempts:5` with three nameservers
        assert_eq!(fitted(30, 5, 3, secs(5)), (1, 1, 3));
        // a shorter configured wait is kept, a fitting one is never lengthened
        assert_eq!(fitted(1, 2, 1, secs(5)), (1, 2, 2));
        assert_eq!(fitted(5, 2, 1, secs(30)), (5, 2, 10));
        assert_eq!(fitted(5, 0, 0, secs(5)), (5, 0, 5));
        // the budget a 2s or 5s timeout leaves once the call starts
        assert_eq!(fitted(5, 2, 1, Duration::from_millis(1990)), (1, 2, 2));
        assert_eq!(fitted(1, 5, 1, Duration::from_millis(4980)), (1, 5, 5));
    }

    #[test]
    fn closing_counts_every_nameserver_again() {
        // SAFETY: `__res_state` is plain old data; zeroed is a valid value.
        let mut state: ffi::ResState = unsafe { mem::zeroed() };
        // SAFETY: `state` points to writable resolver context storage.
        assert_eq!(unsafe { ffi::res_ninit(&mut state) }, 0);
        let configured = state.nscount;
        let guard = ResStateGuard(&mut state, configured);
        // as a short budget leaves it
        guard.0.nscount = 0;
        drop(guard);
        assert_eq!(state.nscount, configured);
    }

    #[test]
    fn whole_secs_rounds_to_the_nearest_second() {
        assert_eq!(whole_secs(Duration::from_millis(499)), 0);
        assert_eq!(whole_secs(Duration::from_millis(500)), 1);
        // a 5s timeout fits 4s of retransmits, leaving one more try
        assert_eq!(
            whole_secs(Duration::from_millis(4980) - Duration::from_secs(4)),
            1
        );
        assert_eq!(whole_secs(Duration::MAX), libc::c_int::MAX);
    }

    #[test]
    fn libc_waits_per_try_as_send_dg_computes_it() {
        assert_eq!(try_secs(5, 1), 5);
        // 5, then (5 << 1) / 3, then (5 << 2) / 3
        assert_eq!(try_secs(5, 3), 5 + 3 + 6);
        // never under a second per nameserver
        assert_eq!(try_secs(1, 3), 3);
    }

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
mod record_response_tests {
    use super::{
        RecordType, parse_cname_response, parse_complete_response, parse_service_binding_response,
        parse_txt_response,
    };

    fn response(record_type: RecordType, rdata: &[u8]) -> Vec<u8> {
        response_records(record_type, &[rdata])
    }

    fn response_records(record_type: RecordType, rdatas: &[&[u8]]) -> Vec<u8> {
        let mut packet = vec![
            0, 0, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm', 0,
        ];
        let ancillary_count = usize::from(record_type != RecordType::CNAME);
        packet[6..8].copy_from_slice(
            &u16::try_from(rdatas.len() + ancillary_count)
                .expect("short answer list")
                .to_be_bytes(),
        );
        packet.extend_from_slice(&u16::from(record_type).to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());

        if ancillary_count != 0 {
            // Ancillary CNAME answer.
            packet.extend_from_slice(&[0xc0, 0x0c]);
            packet.extend_from_slice(&5_u16.to_be_bytes());
            packet.extend_from_slice(&1_u16.to_be_bytes());
            packet.extend_from_slice(&60_u32.to_be_bytes());
            packet.extend_from_slice(&2_u16.to_be_bytes());
            packet.extend_from_slice(&[0xc0, 0x0c]);
        }

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
    fn cname_response_expands_compressed_rdata_with_ttl() {
        let packet = response(RecordType::CNAME, &[0xc0, 0x0c]);
        let records = parse_complete_response(&packet, &parse_cname_response).expect("valid CNAME");

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0.to_string(), "example.com.");
        assert_eq!(records[0].1, 123);

        let packet = response(RecordType::CNAME, &[0xc0, 0x0c, 0]);
        parse_complete_response(&packet, &parse_cname_response)
            .expect_err("trailing CNAME RDATA is malformed");
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

    #[test]
    fn txt_response_preserves_one_item_per_record_and_string_boundaries() {
        let first = [3, b'f', b'o', b'o', 0];
        let second = [3, b'b', b'a', b'r'];
        let packet = response_records(RecordType::TXT, &[&first, &second]);
        let records = parse_complete_response(&packet, &parse_txt_response).expect("valid TXT");

        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].0.iter().collect::<Vec<_>>(),
            [&b"foo"[..], &b""[..]]
        );
        assert_eq!(records[1].0.iter().collect::<Vec<_>>(), [&b"bar"[..]]);
        assert_eq!(records[0].1, 123);
        assert_eq!(records[1].1, 123);
    }

    #[test]
    fn txt_response_discards_records_before_a_malformed_member() {
        let valid = [2, b'o', b'k'];
        let malformed = [3, b'n', b'o'];
        let packet = response_records(RecordType::TXT, &[&valid, &malformed]);

        parse_complete_response(&packet, &parse_txt_response)
            .expect_err("one malformed member invalidates the complete response RRset");
    }
}
