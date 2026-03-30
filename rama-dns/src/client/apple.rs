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
//! - The returned asynchronous stream integrates the `DNSServiceRef` socket with
//!   Tokio using `AsyncFd`, calling `DNSServiceProcessResult` whenever the fd
//!   becomes readable.
//! - The DNS-SD callback decodes records into an in-memory queue that is then
//!   drained by the polling future.
//! - Lookups are bounded by a configurable timeout, defaulting to 5 seconds.
//!
//! For the platform header itself, see the SDK copy at:
//! `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/dns_sd.h`

use std::collections::VecDeque;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, RawFd};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use rama_core::bytes::Bytes;
use rama_core::error::BoxError;
use rama_core::futures::{Stream, async_stream::stream_fn};
use rama_core::telemetry::tracing;
use rama_net::address::Domain;
use rama_utils::macros::generate_set_and_with;
use rama_utils::str::arcstr::ArcStr;
use tokio::io::unix::AsyncFd;
use tokio::time::Instant;

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

fn query_record_stream<T, P>(
    domain: Domain,
    timeout: Duration,
    rrtype: u16,
    parser: P,
) -> impl Stream<Item = Result<T, BoxError>> + Send
where
    T: fmt::Debug + Send + 'static,
    P: Fn(&[u8], &mut dyn FnMut(T)) -> Result<(), BoxError> + Send + Sync + 'static,
{
    stream_fn(async move |mut yielder| {
        let name = match dns_name_from_domain(domain.as_str()) {
            Ok(name) => name,
            Err(err) => {
                yielder.yield_item(Err(err)).await;
                return;
            }
        };

        tracing::debug!(?timeout, rrtype, %domain, "dns::apple: query");

        let mut state = Box::new(QueryState {
            queue: Mutex::new(VecDeque::new()),
            done: AtomicBool::new(false),
            parser,
        });

        let service_ref_result = {
            let mut raw_service_ref: ffi::DNSServiceRef = ptr::null_mut();
            // SAFETY:
            // - `raw_service_ref` points to valid writable storage for the out-parameter.
            // - `name` is a live NUL-terminated C string for the duration of the call.
            // - `query_record_callback` has the ABI and signature required by `dns_sd.h`.
            // - `state` is boxed, so the context pointer remains stable until the stream ends.
            let err = unsafe {
                ffi::DNSServiceQueryRecord(
                    &mut raw_service_ref,
                    0,
                    0,
                    name.as_ptr(),
                    rrtype,
                    ffi::K_DNS_SERVICE_CLASS_IN,
                    Some(query_record_callback::<T, P>),
                    state.as_mut() as *mut QueryState<T, P> as *mut c_void,
                )
            };

            if err != ffi::K_DNS_SERVICE_ERR_NO_ERROR {
                Err(AppleDnsResolverError::dns_service("DNSServiceQueryRecord", err).into())
            } else {
                Ok(ServiceRef(raw_service_ref))
            }
        };

        let service_ref = match service_ref_result {
            Ok(service_ref) => service_ref,
            Err(err) => {
                yielder.yield_item(Err(err)).await;
                return;
            }
        };
        // SAFETY: `service_ref` was successfully initialized by `DNSServiceQueryRecord`
        // above and remains owned by this stream until `ServiceRef` is dropped.
        let fd = unsafe { ffi::DNSServiceRefSockFD(service_ref.0) };
        if fd < 0 {
            yielder
                .yield_item(Err(AppleDnsResolverError::message(
                    "DNSServiceRefSockFD returned an invalid fd",
                )
                .into()))
                .await;
            return;
        }

        let async_fd = match AsyncFd::new(DnsServiceSocketFd(fd)) {
            Ok(async_fd) => async_fd,
            Err(err) => {
                yielder
                    .yield_item(Err(AppleDnsResolverError::message(format!(
                        "failed to register DNSServiceRef fd with tokio: {err}"
                    ))
                    .into()))
                    .await;
                return;
            }
        };

        let deadline = Instant::now() + timeout;

        loop {
            for item in drain_queue(&state) {
                yielder.yield_item(item).await;
            }

            if state.done.load(Ordering::SeqCst) {
                break;
            }

            let now = Instant::now();
            if now >= deadline {
                queue_error(&state, AppleDnsResolverError::timeout(timeout));
                continue;
            }

            let mut ready = match tokio::time::timeout_at(deadline, async_fd.readable()).await {
                Ok(Ok(ready)) => ready,
                Ok(Err(err)) => {
                    queue_error(
                        &state,
                        AppleDnsResolverError::message(format!(
                            "failed waiting on DNSServiceRef fd readiness: {err}"
                        )),
                    );
                    continue;
                }
                Err(_) => {
                    queue_error(&state, AppleDnsResolverError::timeout(timeout));
                    continue;
                }
            };

            // SAFETY: `service_ref` is still valid and registered with DNS-SD, and Apple
            // requires callers to invoke `DNSServiceProcessResult` when the socket becomes
            // readable to dispatch callbacks for pending records.
            let process_err = unsafe { ffi::DNSServiceProcessResult(service_ref.0) };
            ready.clear_ready();

            if process_err != ffi::K_DNS_SERVICE_ERR_NO_ERROR {
                queue_error(
                    &state,
                    AppleDnsResolverError::dns_service("DNSServiceProcessResult", process_err),
                );
            }
        }

        for item in drain_queue(&state) {
            yielder.yield_item(item).await;
        }
    })
}

fn dns_name_from_domain(domain: &str) -> Result<CString, BoxError> {
    let name = domain.trim_end_matches('.');
    CString::new(name).map_err(|_| {
        AppleDnsResolverError::message(format!("domain contains interior NUL byte: {name}")).into()
    })
}

fn queue_error<T, P>(state: &QueryState<T, P>, err: AppleDnsResolverError)
where
    T: Send + 'static,
    P: Fn(&[u8], &mut dyn FnMut(T)) -> Result<(), BoxError> + Send + Sync,
{
    state.done.store(true, Ordering::SeqCst);
    state.queue.lock().push_back(Err(BoxError::from(err)));
}

fn finish_empty<T, P>(
    state: &QueryState<T, P>,
    operation: &'static str,
    code: ffi::DNSServiceErrorType,
) where
    T: Send + 'static,
    P: Fn(&[u8], &mut dyn FnMut(T)) -> Result<(), BoxError> + Send + Sync,
{
    state.done.store(true, Ordering::SeqCst);
    tracing::debug!(operation, code, "dns::apple: finish with empty result");
}

const fn is_empty_result_error(code: ffi::DNSServiceErrorType) -> bool {
    matches!(
        code,
        ffi::K_DNS_SERVICE_ERR_NO_SUCH_NAME | ffi::K_DNS_SERVICE_ERR_NO_SUCH_RECORD
    )
}

/// SAFETY: `ptr` must either be null or point to a valid NUL-terminated C string
/// for the duration of this call.
unsafe fn c_char_ptr_to_str_lossy<'a>(ptr: *const c_char) -> std::borrow::Cow<'a, str> {
    if ptr.is_null() {
        return "".into();
    }

    // SAFETY: upheld by the function contract above.
    unsafe { CStr::from_ptr(ptr) }.to_string_lossy()
}

/// SAFETY:
/// - `context` must be either null or a pointer to a live `QueryState<T, P>`.
/// - `fullname` must be either null or a valid NUL-terminated C string.
/// - `rdata` must point to `rdlen` bytes whenever it is non-null.
/// - The callback is only valid while the owning stream keeps `state` alive.
unsafe extern "C" fn query_record_callback<T, P>(
    _sd_ref: ffi::DNSServiceRef,
    flags: ffi::DNSServiceFlags,
    _interface_index: u32,
    error_code: ffi::DNSServiceErrorType,
    fullname: *const c_char,
    rrtype: u16,
    _rrclass: u16,
    rdlen: u16,
    rdata: *const c_void,
    _ttl: u32,
    context: *mut c_void,
) where
    T: fmt::Debug + Send + 'static,
    P: Fn(&[u8], &mut dyn FnMut(T)) -> Result<(), BoxError> + Send + Sync,
{
    // SAFETY: guaranteed by the callback contract documented above.
    let Some(state) = (unsafe { context.cast::<QueryState<T, P>>().as_ref() }) else {
        return;
    };

    if error_code != ffi::K_DNS_SERVICE_ERR_NO_ERROR {
        if is_empty_result_error(error_code) {
            finish_empty(state, "query callback", error_code);
            return;
        }
        queue_error(
            state,
            AppleDnsResolverError::dns_service("query callback", error_code),
        );
        return;
    }

    if rdata.is_null() {
        queue_error(
            state,
            AppleDnsResolverError::message("query callback received null rdata"),
        );
        return;
    }

    // SAFETY: guaranteed by the callback contract documented above.
    let domain = unsafe { c_char_ptr_to_str_lossy(fullname) };

    // SAFETY: guaranteed by the callback contract documented above.
    let rdata = unsafe { std::slice::from_raw_parts(rdata.cast::<u8>(), rdlen as usize) };
    let mut emit_record = |record| {
        tracing::debug!(
            rrtype,
            %domain,
            "dns::apple: answer: {record:?}"
        );
        state.queue.lock().push_back(Ok(record));
    };

    match (state.parser)(rdata, &mut emit_record) {
        Ok(()) => {}
        Err(err) => {
            state.queue.lock().push_back(Err(err));
            state.done.store(true, Ordering::SeqCst);
            return;
        }
    }

    if (flags & ffi::K_DNS_SERVICE_FLAGS_MORE_COMING) == 0 {
        state.done.store(true, Ordering::SeqCst);
    }
}

#[derive(Debug)]
struct QueryState<T, P> {
    queue: Mutex<VecDeque<Result<T, BoxError>>>,
    done: AtomicBool,
    parser: P,
}

fn drain_queue<T, P>(state: &QueryState<T, P>) -> Vec<Result<T, BoxError>> {
    state.queue.lock().drain(..).collect()
}

#[derive(Debug)]
struct DnsServiceSocketFd(c_int);

impl AsRawFd for DnsServiceSocketFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

#[derive(Debug)]
struct ServiceRef(ffi::DNSServiceRef);

// SAFETY: `ServiceRef` is an opaque handle. We only access it through the DNS-SD C API,
// and ownership is unique to the stream driving the query, so sending the handle across
// threads does not permit unsynchronized Rust aliasing of the pointee.
unsafe impl Send for ServiceRef {}

impl Drop for ServiceRef {
    fn drop(&mut self) {
        // SAFETY: this `ServiceRef` uniquely owns the DNSService handle and deallocates it
        // exactly once here on drop.
        unsafe { ffi::DNSServiceRefDeallocate(self.0) };
    }
}

fn parse_a(rdata: &[u8], emit: &mut dyn FnMut(Ipv4Addr)) -> Result<(), BoxError> {
    if rdata.len() != 4 {
        return Err(AppleDnsResolverError::message(format!(
            "invalid A record length: {}",
            rdata.len()
        ))
        .into());
    }
    emit(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
    Ok(())
}

fn parse_aaaa(rdata: &[u8], emit: &mut dyn FnMut(Ipv6Addr)) -> Result<(), BoxError> {
    if rdata.len() != 16 {
        return Err(AppleDnsResolverError::message(format!(
            "invalid AAAA record length: {}",
            rdata.len()
        ))
        .into());
    }
    let mut octets = [0_u8; 16];
    octets.copy_from_slice(rdata);
    emit(Ipv6Addr::from(octets));
    Ok(())
}

fn parse_txt(rdata: &[u8], emit: &mut dyn FnMut(Bytes)) -> Result<(), BoxError> {
    let mut offset = 0;

    while offset < rdata.len() {
        let len = rdata[offset] as usize;
        offset += 1;
        if offset + len > rdata.len() {
            return Err(AppleDnsResolverError::message("invalid TXT record payload").into());
        }
        emit(Bytes::copy_from_slice(&rdata[offset..offset + len]));
        offset += len;
    }

    Ok(())
}

#[derive(Debug)]
struct AppleDnsResolverError(ArcStr);

impl AppleDnsResolverError {
    fn message(message: impl Into<ArcStr>) -> Self {
        Self(message.into())
    }

    fn timeout(timeout: Duration) -> Self {
        Self::message(format!("apple dns query timed out after {timeout:?}"))
    }

    fn dns_service(operation: &str, code: ffi::DNSServiceErrorType) -> Self {
        Self::message(format!(
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

    // see for reference original C header:
    // <https://github.com/apple-oss-distributions/mDNSResponder/blob/d4658af3f5f291311c6aee4210aa6d39bda82bbe/mDNSShared/dns_sd.h>

    // Internet
    pub(super) const K_DNS_SERVICE_CLASS_IN: u16 = 1;

    // Host address.
    pub(super) const K_DNS_SERVICE_TYPE_A: u16 = 1;
    // One or more text strings (NOT "zero or more...").
    pub(super) const K_DNS_SERVICE_TYPE_TXT: u16 = 16;
    // IPv6 Address.
    pub(super) const K_DNS_SERVICE_TYPE_AAAA: u16 = 28;

    // MoreComing indicates to a callback that at least one more result is
    // queued and will be delivered following immediately after this one.
    // When the MoreComing flag is set, applications should not immediately
    // update their UI, because this can result in a great deal of ugly flickering
    // on the screen, and can waste a great deal of CPU time repeatedly updating
    // the screen with content that is then immediately erased, over and over.
    // Applications should wait until MoreComing is not set, and then
    // update their UI when no more changes are imminent.
    // When MoreComing is not set, that doesn't mean there will be no more
    // answers EVER, just that there are no more answers immediately
    // available right now at this instant. If more answers become available
    // in the future they will be delivered as usual.
    pub(super) const K_DNS_SERVICE_FLAGS_MORE_COMING: DNSServiceFlags = 0x1;

    pub(super) const K_DNS_SERVICE_ERR_NO_ERROR: DNSServiceErrorType = 0;
    pub(super) const K_DNS_SERVICE_ERR_NO_SUCH_NAME: DNSServiceErrorType = -65538;
    pub(super) const K_DNS_SERVICE_ERR_NO_SUCH_RECORD: DNSServiceErrorType = -65554;

    // The definition of the DNSServiceQueryRecord callback function.
    //
    //  @param sdRef
    //   The DNSServiceRef initialized by DNSServiceQueryRecord().
    //
    //  @param flags
    //   Possible values are kDNSServiceFlagsMoreComing and
    //   kDNSServiceFlagsAdd. The Add flag is NOT set for PTR records
    //   with a ttl of 0, i.e. "Remove" events.
    //
    //  @param interfaceIndex
    //   The interface on which the query was resolved (the index for a given
    //   interface is determined via the if_nametoindex() family of calls).
    //   See "Constants for specifying an interface index" for more details.
    //
    //  @param errorCode
    //   Will be kDNSServiceErr_NoError on success, otherwise will
    //   indicate the failure that occurred. Other parameters are undefined if
    //   errorCode is nonzero.
    //
    //  @param fullname
    //   The resource record's full domain name.
    //
    //  @param rrtype
    //   The resource record's type (e.g. kDNSServiceType_PTR, kDNSServiceType_SRV, etc)
    //
    //  @param rrclass
    //   The class of the resource record (usually kDNSServiceClass_IN).
    //
    //  @param rdlen
    //   The length, in bytes, of the resource record rdata.
    //
    //  @param rdata
    //   The raw rdata of the resource record.
    //
    //  @param ttl
    //   If the client wishes to cache the result for performance reasons,
    //   the TTL indicates how long the client may legitimately hold onto
    //   this result, in seconds. After the TTL expires, the client should
    //   consider the result no longer valid, and if it requires this data
    //   again, it should be re-fetched with a new query. Of course, this
    //   only applies to clients that cancel the asynchronous operation when
    //   they get a result. Clients that leave the asynchronous operation
    //   running can safely assume that the data remains valid until they
    //   get another callback telling them otherwise. The ttl value is not
    //   updated when the daemon answers from the cache, hence relying on
    //   the accuracy of the ttl value is not recommended.
    //
    //  @param context
    //   The context pointer that was passed to the callout.
    //
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
        // Query for an arbitrary DNS record.
        //
        //  @param sdRef
        //   A pointer to an uninitialized DNSServiceRef
        //   (or, if the kDNSServiceFlagsShareConnection flag is used,
        //   a copy of the shared connection reference that is to be used).
        //   If the call succeeds then it initializes (or updates) the DNSServiceRef,
        //   returns kDNSServiceErr_NoError, and the query operation
        //   will remain active indefinitely until the client terminates it
        //   by passing this DNSServiceRef to DNSServiceRefDeallocate()
        //   (or by closing the underlying shared connection, if used).
        //
        //  @param flags
        //   Possible values are:
        //   kDNSServiceFlagsShareConnection to use a shared connection.
        //   kDNSServiceFlagsForceMulticast or kDNSServiceFlagsLongLivedQuery.
        //   Pass kDNSServiceFlagsLongLivedQuery to create a "long-lived" unicast
        //   query to a unicast DNS server that implements the protocol. This flag
        //   has no effect on link-local multicast queries.
        //
        //  @param interfaceIndex
        //   If non-zero, specifies the interface on which to issue the query
        //   (the index for a given interface is determined via the if_nametoindex()
        //   family of calls.) Passing 0 causes the name to be queried for on all
        //   interfaces. See "Constants for specifying an interface index" for more details.
        //
        //  @param fullname
        //   The full domain name of the resource record to be queried for.
        //
        //  @param rrtype
        //   The numerical type of the resource record to be queried for
        //   (e.g. kDNSServiceType_PTR, kDNSServiceType_SRV, etc)
        //
        //  @param rrclass
        //   The class of the resource record (usually kDNSServiceClass_IN).
        //
        //  @param callBack
        //    The function to be called when a result is found, or if the call
        //    asynchronously fails.
        //
        //  @param context
        //   An application context pointer which is passed to the callback function
        //   (may be NULL).
        //
        //  @result:
        //   Returns kDNSServiceErr_NoError on success (any subsequent, asynchronous
        //   errors are delivered to the callback), otherwise returns an error code indicating
        //   the error that occurred (the callback is never invoked and the DNSServiceRef
        //   is not initialized).
        //
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

        // Access underlying Unix domain socket for an initialized DNSServiceRef.
        //
        // @param sdRef
        //   A DNSServiceRef initialized by any of the DNSService calls.
        //
        // @result
        //   The DNSServiceRef's underlying socket descriptor, or -1 on error.
        //
        // @discussion
        //   The DNS Service Discovery implementation uses this socket to communicate between the client and
        //   the daemon. The application MUST NOT directly read from or write to this socket.
        //   Access to the socket is provided so that it can be used as a kqueue event source, a CFRunLoop
        //   event source, in a select() loop, etc. When the underlying event management subsystem (kqueue/
        //   select/CFRunLoop etc.) indicates to the client that data is available for reading on the
        //   socket, the client should call DNSServiceProcessResult(), which will extract the daemon's
        //   reply from the socket, and pass it to the appropriate application callback. By using a run
        //   loop or select(), results from the daemon can be processed asynchronously. Alternatively,
        //   a client can choose to fork a thread and have it loop calling "DNSServiceProcessResult(ref);"
        //   If DNSServiceProcessResult() is called when no data is available for reading on the socket, it
        //   will block until data does become available, and then process the data and return to the caller.
        //   The application is responsible for checking the return value of DNSServiceProcessResult()
        //   to determine if the socket is valid and if it should continue to process data on the socket.
        //   When data arrives on the socket, the client is responsible for calling DNSServiceProcessResult(ref)
        //   in a timely fashion -- if the client allows a large backlog of data to build up the daemon
        //   may terminate the connection.
        //
        pub(super) fn DNSServiceRefSockFD(sd_ref: DNSServiceRef) -> c_int;

        // Read a reply from the daemon, calling the appropriate application callback.
        //
        //  @param sdRef
        //    A DNSServiceRef initialized by any of the DNSService calls
        //    that take a callback parameter.
        //
        //  @result
        //   Returns kDNSServiceErr_NoError on success, otherwise returns
        //   an error code indicating the specific failure that occurred.
        //
        //  @discussion
        //   This call will block until the daemon's response is received. Use DNSServiceRefSockFD() in
        //   conjunction with a run loop or select() to determine the presence of a response from the
        //   server before calling this function to process the reply without blocking. Call this function
        //   at any point if it is acceptable to block until the daemon's response arrives. Note that the
        //   client is responsible for ensuring that DNSServiceProcessResult() is called whenever there is
        //   a reply from the daemon - the daemon may terminate its connection with a client that does not
        //   process the daemon's responses.
        pub(super) fn DNSServiceProcessResult(sd_ref: DNSServiceRef) -> DNSServiceErrorType;

        // Terminate a connection with the daemon and free memory associated with the DNSServiceRef.
        //
        // @param sdRef
        //   A DNSServiceRef initialized by any of the DNSService calls.
        //
        // @discussion
        //   Any services or records registered with this DNSServiceRef will be deregistered. Any
        //   Browse, Resolve, or Query operations called with this reference will be terminated.
        //
        //   Note: If the reference's underlying socket is used in a run loop or select() call, it should
        //   be removed BEFORE DNSServiceRefDeallocate() is called, as this function closes the reference's
        //   socket.
        //
        //   Note: If the reference was initialized with DNSServiceCreateConnection(), any DNSRecordRefs
        //   created via this reference will be invalidated by this call - the resource records are
        //   deregistered, and their DNSRecordRefs may not be used in subsequent functions. Similarly,
        //   if the reference was initialized with DNSServiceRegister, and an extra resource record was
        //   added to the service via DNSServiceAddRecord(), the DNSRecordRef created by the Add() call
        //   is invalidated when this function is called - the DNSRecordRef may not be used in subsequent
        //   functions.
        //
        //   If the reference was passed to DNSServiceSetDispatchQueue(), DNSServiceRefDeallocate() must
        //   be called on the same queue originally passed as an argument to DNSServiceSetDispatchQueue().
        //
        //   Note: This call is to be used only with the DNSServiceRef defined by this API.
        //
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
        let mut records = Vec::new();
        parse_a(&[127, 0, 0, 1], &mut |record| records.push(record)).unwrap();
        assert_eq!(records, vec![Ipv4Addr::LOCALHOST]);
    }

    #[test]
    fn parse_aaaa_record() {
        let mut records = Vec::new();
        parse_aaaa(&Ipv6Addr::LOCALHOST.octets(), &mut |record| {
            records.push(record)
        })
        .unwrap();
        assert_eq!(records, vec![Ipv6Addr::LOCALHOST]);
    }

    #[test]
    fn parse_txt_record_chunks() {
        let mut txt = Vec::new();
        parse_txt(&[3, b'f', b'o', b'o', 3, b'b', b'a', b'r'], &mut |record| {
            txt.push(record);
        })
        .unwrap();
        assert_eq!(
            txt,
            vec![Bytes::from_static(b"foo"), Bytes::from_static(b"bar")]
        );
    }

    #[test]
    fn empty_result_errors_are_classified() {
        assert!(is_empty_result_error(ffi::K_DNS_SERVICE_ERR_NO_SUCH_NAME));
        assert!(is_empty_result_error(ffi::K_DNS_SERVICE_ERR_NO_SUCH_RECORD));
        assert!(!is_empty_result_error(ffi::K_DNS_SERVICE_ERR_NO_ERROR));
    }
}
