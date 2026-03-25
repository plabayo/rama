//! Apple-native DNS resolver backed by Apple's DNS Service Discovery C API.
//!
//! This resolver uses the socket-based DNS-SD interface exposed in `dns_sd.h`
//! and driven by the `mDNSResponder` daemon.
//!
//! Official Apple references:
//! - DNS Service Discovery Programming Guide:
//!   <https://developer.apple.com/library/archive/documentation/Networking/Conceptual/dns_discovery_api/Introduction.html>
//! - Resolving and socket-loop integration (`DNSServiceRefSockFD` + `DNSServiceProcessResult`):
//!   <https://developer.apple.com/library/archive/documentation/Networking/Conceptual/dns_discovery_api/Articles/resolving.html>
//! - DNS-SD C API reference / `dns_sd.h` landing page:
//!   <https://developer.apple.com/documentation/dnssd/dns_sd_h>
//!
//! Implementation notes:
//! - `A`, `AAAA`, and `TXT` lookups are all backed by `DNSServiceQueryRecord`.
//! - Each lookup owns its own `DNSServiceRef`.
//! - A worker thread waits on `DNSServiceRefSockFD`, calls
//!   `DNSServiceProcessResult`, and forwards decoded records into the
//!   asynchronous stream returned to Rama.
//! - Lookups are bounded by a configurable timeout, defaulting to 5 seconds.
//!
//! For the platform header itself, see the SDK copy at:
//! `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/dns_sd.h`

use std::ffi::{CString, c_char, c_int, c_void};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use libc::{EINTR, POLLIN, poll, pollfd};
use rama_core::bytes::Bytes;
use rama_core::error::BoxError;
use rama_core::futures::{Stream, async_stream::stream_fn};
use rama_net::address::Domain;
use rama_utils::macros::generate_set_and_with;
use tokio::sync::mpsc;

use super::resolver::{DnsAddressResolver, DnsResolver, DnsTxtResolver};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Apple-native [`DnsResolver`] implementation using `dns_sd.h`.
///
/// The default timeout is 5 seconds. Use [`Self::with_timeout`] to override it.
pub struct AppleDnsResolver {
    timeout: Duration,
}

impl Default for AppleDnsResolver {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

impl AppleDnsResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    generate_set_and_with! {
        pub fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }
    }
}

impl DnsAddressResolver for AppleDnsResolver {
    type Error = BoxError;

    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        query_record_stream::<Ipv4Addr, _>(domain, self.timeout, ffi::K_DNS_SERVICE_TYPE_A, parse_a)
    }

    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        query_record_stream::<Ipv6Addr, _>(
            domain,
            self.timeout,
            ffi::K_DNS_SERVICE_TYPE_AAAA,
            parse_aaaa,
        )
    }
}

impl DnsTxtResolver for AppleDnsResolver {
    type Error = BoxError;

    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_ {
        query_record_stream::<Bytes, _>(
            domain,
            self.timeout,
            ffi::K_DNS_SERVICE_TYPE_TXT,
            parse_txt,
        )
    }
}

impl DnsResolver for AppleDnsResolver {}

#[allow(clippy::needless_pass_by_value)]
fn query_record_stream<T, P>(
    domain: Domain,
    timeout: Duration,
    rrtype: u16,
    parser: P,
) -> impl Stream<Item = Result<T, BoxError>> + Send
where
    T: Send + 'static,
    P: Fn(&[u8]) -> Result<Vec<T>, BoxError> + Send + Sync + 'static,
{
    let (tx, mut rx) = mpsc::unbounded_channel();
    let parser = Arc::new(parser);
    let domain = domain.as_ref().to_owned();

    std::thread::spawn(move || {
        run_query(domain, timeout, rrtype, parser, tx);
    });

    stream_fn(async move |mut yielder| {
        while let Some(item) = rx.recv().await {
            yielder.yield_item(item).await;
        }
    })
}

#[allow(clippy::needless_pass_by_value)]
fn run_query<T>(
    domain: String,
    timeout: Duration,
    rrtype: u16,
    parser: Arc<dyn Fn(&[u8]) -> Result<Vec<T>, BoxError> + Send + Sync>,
    tx: mpsc::UnboundedSender<Result<T, BoxError>>,
) where
    T: Send + 'static,
{
    let name = match dns_name_from_domain(&domain) {
        Ok(name) => name,
        Err(err) => {
            let _ = tx.send(Err(err));
            return;
        }
    };

    let state = Box::new(QueryState {
        tx,
        done: AtomicBool::new(false),
        parser,
    });
    let state_ptr = Box::into_raw(state);

    let mut service_ref: ffi::DNSServiceRef = ptr::null_mut();
    let err = unsafe {
        ffi::DNSServiceQueryRecord(
            &mut service_ref,
            0,
            0,
            name.as_ptr(),
            rrtype,
            ffi::K_DNS_SERVICE_CLASS_IN,
            Some(query_record_callback::<T>),
            state_ptr.cast(),
        )
    };

    if err != ffi::K_DNS_SERVICE_ERR_NO_ERROR {
        unsafe {
            send_terminal_error(
                &*state_ptr,
                AppleDnsResolverError::dns_service("DNSServiceQueryRecord", err),
            );
            drop(Box::from_raw(state_ptr));
        }
        return;
    }

    let fd = unsafe { ffi::DNSServiceRefSockFD(service_ref) };
    if fd < 0 {
        unsafe {
            ffi::DNSServiceRefDeallocate(service_ref);
            send_terminal_error(
                &*state_ptr,
                AppleDnsResolverError::message("DNSServiceRefSockFD returned an invalid fd"),
            );
            drop(Box::from_raw(state_ptr));
        }
        return;
    }

    let deadline = Instant::now() + timeout;
    loop {
        let state = unsafe { &*state_ptr };
        if state.done.load(Ordering::SeqCst) {
            break;
        }

        let now = Instant::now();
        if now >= deadline {
            send_terminal_error(state, AppleDnsResolverError::timeout(timeout));
            break;
        }

        let remaining = deadline.saturating_duration_since(now);
        let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as c_int;
        let mut pfd = pollfd {
            fd,
            events: POLLIN,
            revents: 0,
        };

        let poll_result = unsafe { poll(&mut pfd, 1, timeout_ms) };
        if poll_result == 0 {
            send_terminal_error(state, AppleDnsResolverError::timeout(timeout));
            break;
        }
        if poll_result < 0 {
            let errno = std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or_default();
            if errno == EINTR {
                continue;
            }
            send_terminal_error(
                state,
                AppleDnsResolverError::message(format!("poll failed with errno {errno}")),
            );
            break;
        }
        if (pfd.revents & POLLIN) == 0 {
            continue;
        }

        let process_err = unsafe { ffi::DNSServiceProcessResult(service_ref) };
        if process_err != ffi::K_DNS_SERVICE_ERR_NO_ERROR {
            send_terminal_error(
                state,
                AppleDnsResolverError::dns_service("DNSServiceProcessResult", process_err),
            );
            break;
        }
    }

    unsafe {
        ffi::DNSServiceRefDeallocate(service_ref);
        drop(Box::from_raw(state_ptr));
    }
}

fn dns_name_from_domain(domain: &str) -> Result<CString, BoxError> {
    let name = domain.trim_end_matches('.');
    CString::new(name).map_err(|_| {
        AppleDnsResolverError::message(format!("domain contains interior NUL byte: {name}")).into()
    })
}

fn send_terminal_error<T>(state: &QueryState<T>, err: AppleDnsResolverError)
where
    T: Send + 'static,
{
    state.done.store(true, Ordering::SeqCst);
    let _ = state.tx.send(Err(BoxError::from(err)));
}

unsafe extern "C" fn query_record_callback<T>(
    _sd_ref: ffi::DNSServiceRef,
    flags: ffi::DNSServiceFlags,
    _interface_index: u32,
    error_code: ffi::DNSServiceErrorType,
    _fullname: *const c_char,
    _rrtype: u16,
    _rrclass: u16,
    rdlen: u16,
    rdata: *const c_void,
    _ttl: u32,
    context: *mut c_void,
) where
    T: Send + 'static,
{
    let Some(state) = (unsafe { context.cast::<QueryState<T>>().as_ref() }) else {
        return;
    };

    if error_code != ffi::K_DNS_SERVICE_ERR_NO_ERROR {
        send_terminal_error(
            state,
            AppleDnsResolverError::dns_service("query callback", error_code),
        );
        return;
    }

    if rdata.is_null() {
        send_terminal_error(
            state,
            AppleDnsResolverError::message("query callback received null rdata"),
        );
        return;
    }

    let rdata = unsafe { std::slice::from_raw_parts(rdata.cast::<u8>(), rdlen as usize) };
    match (state.parser)(rdata) {
        Ok(records) => {
            for record in records {
                if state.tx.send(Ok(record)).is_err() {
                    state.done.store(true, Ordering::SeqCst);
                    return;
                }
            }
        }
        Err(err) => {
            let _ = state.tx.send(Err(err));
            state.done.store(true, Ordering::SeqCst);
            return;
        }
    }

    if (flags & ffi::K_DNS_SERVICE_FLAGS_MORE_COMING) == 0 {
        state.done.store(true, Ordering::SeqCst);
    }
}

struct QueryState<T> {
    tx: mpsc::UnboundedSender<Result<T, BoxError>>,
    done: AtomicBool,
    parser: Arc<dyn Fn(&[u8]) -> Result<Vec<T>, BoxError> + Send + Sync>,
}

fn parse_a(rdata: &[u8]) -> Result<Vec<Ipv4Addr>, BoxError> {
    if rdata.len() != 4 {
        return Err(AppleDnsResolverError::message(format!(
            "invalid A record length: {}",
            rdata.len()
        ))
        .into());
    }
    Ok(vec![Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])])
}

fn parse_aaaa(rdata: &[u8]) -> Result<Vec<Ipv6Addr>, BoxError> {
    if rdata.len() != 16 {
        return Err(AppleDnsResolverError::message(format!(
            "invalid AAAA record length: {}",
            rdata.len()
        ))
        .into());
    }
    let mut octets = [0_u8; 16];
    octets.copy_from_slice(rdata);
    Ok(vec![Ipv6Addr::from(octets)])
}

fn parse_txt(rdata: &[u8]) -> Result<Vec<Bytes>, BoxError> {
    let mut out = Vec::new();
    let mut offset = 0;

    while offset < rdata.len() {
        let len = rdata[offset] as usize;
        offset += 1;
        if offset + len > rdata.len() {
            return Err(AppleDnsResolverError::message("invalid TXT record payload").into());
        }
        out.push(Bytes::copy_from_slice(&rdata[offset..offset + len]));
        offset += len;
    }

    Ok(out)
}

#[derive(Debug)]
struct AppleDnsResolverError(String);

impl AppleDnsResolverError {
    fn message(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    fn timeout(timeout: Duration) -> Self {
        Self(format!("apple dns query timed out after {timeout:?}"))
    }

    fn dns_service(operation: &str, code: ffi::DNSServiceErrorType) -> Self {
        Self(format!(
            "{operation} failed with DNSService error code {code}"
        ))
    }
}

impl fmt::Display for AppleDnsResolverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AppleDnsResolverError {}

mod ffi {
    use super::*;

    pub(super) type DNSServiceRef = *mut c_void;
    pub(super) type DNSServiceFlags = u32;
    pub(super) type DNSServiceErrorType = i32;

    pub(super) const K_DNS_SERVICE_CLASS_IN: u16 = 1;
    pub(super) const K_DNS_SERVICE_TYPE_A: u16 = 1;
    pub(super) const K_DNS_SERVICE_TYPE_TXT: u16 = 16;
    pub(super) const K_DNS_SERVICE_TYPE_AAAA: u16 = 28;

    pub(super) const K_DNS_SERVICE_FLAGS_MORE_COMING: DNSServiceFlags = 1;
    pub(super) const K_DNS_SERVICE_ERR_NO_ERROR: DNSServiceErrorType = 0;

    pub(super) type DNSServiceQueryRecordReply = Option<
        unsafe extern "C" fn(
            sd_ref: DNSServiceRef,
            flags: DNSServiceFlags,
            interface_index: u32,
            error_code: DNSServiceErrorType,
            fullname: *const c_char,
            rrtype: u16,
            rrclass: u16,
            rdlen: u16,
            rdata: *const c_void,
            ttl: u32,
            context: *mut c_void,
        ),
    >;

    unsafe extern "C" {
        pub(super) fn DNSServiceQueryRecord(
            sd_ref: *mut DNSServiceRef,
            flags: DNSServiceFlags,
            interface_index: u32,
            fullname: *const c_char,
            rrtype: u16,
            rrclass: u16,
            callback: DNSServiceQueryRecordReply,
            context: *mut c_void,
        ) -> DNSServiceErrorType;

        pub(super) fn DNSServiceRefSockFD(sd_ref: DNSServiceRef) -> c_int;
        pub(super) fn DNSServiceProcessResult(sd_ref: DNSServiceRef) -> DNSServiceErrorType;
        pub(super) fn DNSServiceRefDeallocate(sd_ref: DNSServiceRef);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apple_resolver_defaults_to_five_second_timeout() {
        assert_eq!(AppleDnsResolver::new().timeout(), Duration::from_secs(5));
    }

    #[test]
    fn apple_resolver_timeout_is_configurable() {
        assert_eq!(
            AppleDnsResolver::new()
                .with_timeout(Duration::from_millis(250))
                .timeout(),
            Duration::from_millis(250)
        );
    }

    #[test]
    fn parse_a_record() {
        assert_eq!(parse_a(&[127, 0, 0, 1]).unwrap(), vec![Ipv4Addr::LOCALHOST]);
    }

    #[test]
    fn parse_aaaa_record() {
        assert_eq!(
            parse_aaaa(&Ipv6Addr::LOCALHOST.octets()).unwrap(),
            vec![Ipv6Addr::LOCALHOST]
        );
    }

    #[test]
    fn parse_txt_record_chunks() {
        let txt = parse_txt(&[3, b'f', b'o', b'o', 3, b'b', b'a', b'r']).unwrap();
        assert_eq!(
            txt,
            vec![Bytes::from_static(b"foo"), Bytes::from_static(b"bar")]
        );
    }
}
