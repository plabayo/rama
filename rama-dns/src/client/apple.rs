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
//!   - <https://developer.apple.com/documentation/dnssd>
//!   - <https://developer.apple.com/documentation/dnssd/dns_sd_h>
//!
//! Implementation notes:
//! - `A`, `AAAA`, `CNAME`, `TXT`, `SVCB`, and `HTTPS` lookups are backed by
//!   `DNSServiceQueryRecord`.
//! - All lookups of a resolver share one mDNSResponder connection
//!   (`kDNSServiceFlagsShareConnection`), so a burst costs one file descriptor
//!   instead of one per query. One task watches its socket with `AsyncFd` and
//!   calls `DNSServiceProcessResult` whenever it becomes readable.
//! - The DNS-SD callback decodes records into a per-query queue, drained by
//!   that query's stream once the batch that carried them has been read.
//! - Lookups are bounded by a configurable timeout, defaulting to 5 seconds.
//! - Concurrent lookups of the same name and record type share one query,
//!   cancelled once every caller stopped waiting; how many run at once, and
//!   how many a burst leaves unanswered, are bounded (configurable).
//!
//! For the platform header itself, see the SDK copy at:
//! `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/dns_sd.h`

use std::collections::VecDeque;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::fmt;
use std::mem::ManuallyDrop;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, RawFd};
use std::pin::pin;
use std::ptr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Duration;

use parking_lot::Mutex;
use rama_core::error::BoxError;
use rama_core::futures::{Stream, StreamExt as _, async_stream::stream_fn, future::Either, stream};
use rama_core::{rt, telemetry::tracing};
use rama_net::address::Domain;
use rama_utils::macros::generate_set_and_with;
use rama_utils::str::arcstr::ArcStr;
use tokio::io::unix::AsyncFd;
use tokio::sync::Notify;
use tokio::time::Instant;

use super::{
    in_flight::{Abandoned, InFlight, coalesced_stream, leading_dot_refusal},
    limit::{DnsTimeoutError, Limits, LookupLimit, deadline_after},
    resolver::{
        DnsAddressResolver, DnsCnameResolver, DnsResolver, DnsServiceBindingResolver,
        DnsTxtResolver,
    },
};
use crate::wire::{Name, RecordType, ServiceBinding, Txt, parse_a_rdata, parse_aaaa_rdata};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Apple-native [`DnsResolver`] implementation using `dns_sd.h`.
///
/// The default timeout is 5 seconds. Use [`Self::with_timeout`] to override it.
pub struct AppleDnsResolver {
    timeout: Duration,
    limit: LookupLimit,
    in_flight: InFlight<(Domain, u16)>,
    connection: Arc<SharedConnection>,
}

impl Default for AppleDnsResolver {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            limit: LookupLimit::new(Limits::ONE_QUERY),
            in_flight: InFlight::new(Abandoned::Cancel),
            connection: Arc::default(),
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
        /// Concurrent lookups are only shared between resolvers with the
        /// same timeout.
        pub fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self.in_flight = InFlight::new(Abandoned::Cancel);
            self
        }
    }

    #[must_use]
    pub fn max_concurrency(&self) -> usize {
        self.limit.limits().max_concurrency
    }

    generate_set_and_with! {
        /// Maximum concurrent DNS-SD queries (default 384), all over one
        /// shared mDNSResponder connection.
        pub fn max_concurrency(mut self, max: usize) -> Self {
            self.limit = self.limit.with(|limits| limits.max_concurrency = max);
            self
        }
    }

    #[must_use]
    pub fn burst_limit(&self) -> usize {
        self.limit.limits().burst_limit
    }

    generate_set_and_with! {
        /// Maximum queries started within one [burst window](Self::burst_window)
        /// and still unanswered (default 128); an answer frees its place at
        /// once, a query waiting on a slow upstream once the window has passed.
        pub fn burst_limit(mut self, max: usize) -> Self {
            self.limit = self.limit.with(|limits| limits.burst_limit = max);
            self
        }
    }

    #[must_use]
    pub fn burst_window(&self) -> Duration {
        self.limit.limits().burst_window
    }

    generate_set_and_with! {
        /// The window of [`Self::burst_limit`] (default 50ms).
        pub fn burst_window(mut self, window: Duration) -> Self {
            self.limit = self.limit.with(|limits| limits.burst_window = window);
            self
        }
    }

    fn query<T, P>(
        &self,
        domain: Domain,
        rrtype: u16,
        parser: P,
    ) -> impl Stream<Item = Result<T, BoxError>> + Send + '_
    where
        T: fmt::Debug + Clone + Send + Sync + 'static,
        P: Fn(&[u8], &mut dyn FnMut(T)) -> Result<(), BoxError> + Send + Sync + 'static,
    {
        if let Some(err) = leading_dot_refusal(&domain) {
            return Either::Left(stream::once(std::future::ready(Err(err))));
        }
        let (timeout, limit) = (self.timeout, self.limit.clone());
        let connection = self.connection.clone();
        // the name goes out without its root dot: `x` and `x.` are one query
        let key = (domain.clone(), rrtype);
        Either::Right(coalesced_stream(
            self.in_flight.clone(),
            key,
            timeout,
            move || limited_query_stream(domain, timeout, limit, connection, rrtype, parser),
        ))
    }
}

/// [`query_record_stream`] once a query slot is free, all within `timeout`.
fn limited_query_stream<T, P>(
    domain: Domain,
    timeout: Duration,
    limit: LookupLimit,
    connection: Arc<SharedConnection>,
    rrtype: u16,
    parser: P,
) -> impl Stream<Item = Result<T, BoxError>> + Send
where
    T: fmt::Debug + Send + 'static,
    P: Fn(&[u8], &mut dyn FnMut(T)) -> Result<(), BoxError> + Send + Sync + 'static,
{
    stream_fn(async move |mut yielder| {
        let deadline = deadline_after(timeout);
        let Some(_slot) = limit.acquire(deadline).await else {
            yielder
                .yield_item(Err(DnsTimeoutError::new(timeout).into()))
                .await;
            return;
        };
        let mut records = std::pin::pin!(query_record_stream(
            domain,
            &connection,
            deadline,
            timeout,
            rrtype,
            parser
        ));
        while let Some(record) = records.next().await {
            yielder.yield_item(record).await;
        }
    })
}

impl DnsAddressResolver for AppleDnsResolver {
    type Error = BoxError;

    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        self.query(domain, ffi::K_DNS_SERVICE_TYPE_A, parse_a)
    }

    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        self.query(domain, ffi::K_DNS_SERVICE_TYPE_AAAA, parse_aaaa)
    }
}

impl DnsTxtResolver for AppleDnsResolver {
    type Error = BoxError;

    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Txt, Self::Error>> + Send + '_ {
        self.query(domain, ffi::K_DNS_SERVICE_TYPE_TXT, parse_txt)
    }
}

impl DnsCnameResolver for AppleDnsResolver {
    type Error = BoxError;

    fn lookup_cname(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Name, Self::Error>> + Send + '_ {
        self.query(domain, ffi::K_DNS_SERVICE_TYPE_CNAME, parse_cname)
    }
}

impl DnsServiceBindingResolver for AppleDnsResolver {
    type Error = BoxError;

    fn lookup_svcb(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, BoxError>> + Send + '_ {
        self.query(domain, RecordType::SVCB.into(), parse_service_binding)
    }

    fn lookup_https(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, BoxError>> + Send + '_ {
        self.query(domain, RecordType::HTTPS.into(), parse_service_binding)
    }
}

impl DnsResolver for AppleDnsResolver {}

/// `timeout` is the caller's whole budget, reported on expiry of `deadline`.
fn query_record_stream<'a, T, P>(
    domain: Domain,
    connection: &'a SharedConnection,
    deadline: Instant,
    timeout: Duration,
    rrtype: u16,
    parser: P,
) -> impl Stream<Item = Result<T, BoxError>> + Send + 'a
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
        let connection = match connection.get() {
            Ok(connection) => connection,
            Err(err) => {
                yielder.yield_item(Err(err)).await;
                return;
            }
        };

        tracing::debug!(?timeout, rrtype, %domain, "dns::apple: query");

        // SAFETY (drop order, callback lifetime): the callback only runs inside
        // `DNSServiceProcessResult`, under the connection's API lock. `query`
        // drops first and deallocates its `DNSServiceRef` under that same lock,
        // so no callback can run once `state` drops after it. Do not reorder.
        let state = Box::new(QueryState {
            queue: Mutex::new(VecDeque::new()),
            done: AtomicBool::new(false),
            touched_in: AtomicU64::new(UNTOUCHED),
            batch: connection.batch.clone(),
            answered: Notify::new(),
            parser,
        });
        let query = match connection.query(
            &name,
            rrtype,
            Some(query_record_callback::<T, P>),
            &*state as *const QueryState<T, P> as *mut c_void,
        ) {
            Ok(query) => query,
            Err(err) => {
                yielder.yield_item(Err(err)).await;
                return;
            }
        };

        loop {
            let mut answered = pin!(state.answered.notified());
            answered.as_mut().enable();
            let mut ended = pin!(connection.ended.notified());
            ended.as_mut().enable();
            let touched_in = state.touched_in.load(Ordering::Acquire);
            // its records are complete once the batch that carried them was read
            let mut read = pin!(connection.batch_read.notified());
            if touched_in != UNTOUCHED {
                read.as_mut().enable();
                if connection.batch.load(Ordering::Acquire) > touched_in {
                    state.done.store(true, Ordering::Release);
                }
            }

            if state.done.load(Ordering::Acquire) {
                break;
            }
            if connection.dead.load(Ordering::Acquire) {
                queue_error(
                    &state,
                    AppleDnsResolverError::message("mDNSResponder connection lost"),
                );
                break;
            }
            if Instant::now() >= deadline {
                queue_error(&state, DnsTimeoutError::new(timeout));
                break;
            }

            tokio::select! {
                () = answered => {}
                () = ended => {}
                () = read, if touched_in != UNTOUCHED => {}
                () = tokio::time::sleep_until(deadline) => {}
            }
        }
        drop(query);

        for item in drain_queue(&state) {
            yielder.yield_item(item).await;
        }
    })
}

/// `QueryState::touched_in` before its first callback.
const UNTOUCHED: u64 = u64::MAX;

/// The resolver's mDNSResponder connection, opened on first use and again
/// after the daemon dropped it. Its last clone closes it.
#[derive(Debug, Default)]
struct SharedConnection {
    current: Mutex<Option<Arc<Connection>>>,
}

impl SharedConnection {
    fn get(&self) -> Result<Arc<Connection>, BoxError> {
        let mut current = self.current.lock();
        if let Some(connection) = current
            .as_ref()
            .filter(|connection| !connection.dead.load(Ordering::Acquire))
        {
            return Ok(connection.clone());
        }
        let connection = Connection::open()?;
        if let Some(stale) = current.replace(connection.clone()) {
            stale.close();
        }
        Ok(connection)
    }
}

impl Drop for SharedConnection {
    fn drop(&mut self) {
        if let Some(connection) = self.current.get_mut().take() {
            connection.close();
        }
    }
}

/// One mDNSResponder connection that every query shares.
struct Connection {
    /// dns_sd.h does no locking of its own: every call on the shared
    /// reference and its queries goes through this lock.
    api: Mutex<()>,
    main: ffi::DNSServiceRef,
    /// Deregistered before `main` closes its socket.
    fd: ManuallyDrop<AsyncFd<DnsServiceSocketFd>>,
    /// Bumped after each `DNSServiceProcessResult`, which reads everything
    /// the socket holds: callbacks seen before a bump are a complete batch.
    batch: Arc<AtomicU64>,
    batch_read: Notify,
    /// Set once the driver stopped: no more callbacks will come.
    dead: AtomicBool,
    ended: Notify,
    closed: Notify,
}

// SAFETY: `main` is an opaque handle, only used under `api`.
unsafe impl Send for Connection {}
// SAFETY: as above, every use of `main` is serialized by `api`.
unsafe impl Sync for Connection {}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("batch", &self.batch)
            .field("dead", &self.dead)
            .finish_non_exhaustive()
    }
}

impl Connection {
    fn open() -> Result<Arc<Self>, BoxError> {
        let mut main: ffi::DNSServiceRef = ptr::null_mut();
        // SAFETY: `main` is writable storage for the out-parameter.
        let err = unsafe { ffi::DNSServiceCreateConnection(&mut main) };
        if err != ffi::K_DNS_SERVICE_ERR_NO_ERROR {
            return Err(
                AppleDnsResolverError::dns_service("DNSServiceCreateConnection", err).into(),
            );
        }
        // SAFETY: `main` was just initialized by `DNSServiceCreateConnection`.
        let fd = unsafe { ffi::DNSServiceRefSockFD(main) };
        let fd = match AsyncFd::new(DnsServiceSocketFd(fd)) {
            Ok(fd) => fd,
            Err(err) => {
                // SAFETY: `main` is valid and not registered anywhere.
                unsafe { ffi::DNSServiceRefDeallocate(main) };
                return Err(AppleDnsResolverError::message(format!(
                    "failed to register DNSServiceRef fd with tokio: {err}"
                ))
                .into());
            }
        };
        let connection = Arc::new(Self {
            api: Mutex::new(()),
            main,
            fd: ManuallyDrop::new(fd),
            batch: Arc::default(),
            batch_read: Notify::new(),
            dead: AtomicBool::new(false),
            ended: Notify::new(),
            closed: Notify::new(),
        });
        rt::spawn(drive(connection.clone()));
        Ok(connection)
    }

    /// Start a query sharing this connection, ended by dropping it.
    fn query(
        self: &Arc<Self>,
        name: &CStr,
        rrtype: u16,
        callback: ffi::DNSServiceQueryRecordReply,
        context: *mut c_void,
    ) -> Result<SharedQuery, BoxError> {
        let _api = self.api.lock();
        // a copy of the shared reference, turned into this query's own
        let mut sd_ref = self.main;
        // SAFETY:
        // - `sd_ref` copies the live shared reference, as ShareConnection requires.
        // - `name` is a live NUL-terminated C string for the duration of the call.
        // - `callback` has the ABI and signature required by `dns_sd.h`.
        // - `context` outlives the query: its owner drops the query first.
        let err = unsafe {
            ffi::DNSServiceQueryRecord(
                &mut sd_ref,
                ffi::K_DNS_SERVICE_FLAGS_SHARE_CONNECTION,
                0,
                name.as_ptr(),
                rrtype,
                ffi::K_DNS_SERVICE_CLASS_IN,
                callback,
                context,
            )
        };
        if err != ffi::K_DNS_SERVICE_ERR_NO_ERROR {
            return Err(AppleDnsResolverError::dns_service("DNSServiceQueryRecord", err).into());
        }
        Ok(SharedQuery {
            connection: self.clone(),
            sd_ref,
        })
    }

    fn close(&self) {
        self.closed.notify_one();
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // SAFETY: dropped once, here, before the socket it watches closes.
        unsafe { ManuallyDrop::drop(&mut self.fd) };
        let _api = self.api.lock();
        // SAFETY: every query holds this connection, so none is left to use it.
        unsafe { ffi::DNSServiceRefDeallocate(self.main) };
    }
}

/// Reads the shared socket and dispatches every query's callbacks.
async fn drive(connection: Arc<Connection>) {
    /// However the driver ends, waiting queries learn no answers are coming.
    struct Ended<'a>(&'a Connection);
    impl Drop for Ended<'_> {
        fn drop(&mut self) {
            self.0.dead.store(true, Ordering::Release);
            self.0.ended.notify_waiters();
        }
    }
    let _ended = Ended(&connection);

    loop {
        let mut ready = tokio::select! {
            ready = connection.fd.readable() => match ready {
                Ok(ready) => ready,
                Err(err) => {
                    tracing::debug!("dns::apple: shared connection unreadable: {err}");
                    return;
                }
            },
            () = connection.closed.notified() => return,
        };
        // readiness may be stale, and on an empty socket the blocking
        // `DNSServiceProcessResult` would block, holding the API lock
        if !has_data(connection.fd.get_ref().0) {
            ready.clear_ready();
            continue;
        }
        let err = {
            let _api = connection.api.lock();
            // SAFETY: the socket is readable, so this reads what is there
            // (all of it) without blocking; callbacks run under `api`.
            unsafe { ffi::DNSServiceProcessResult(connection.main) }
        };
        ready.clear_ready();
        connection.batch.fetch_add(1, Ordering::AcqRel);
        connection.batch_read.notify_waiters();
        if err != ffi::K_DNS_SERVICE_ERR_NO_ERROR {
            tracing::debug!(err, "dns::apple: shared connection lost");
            return;
        }
    }
}

fn has_data(fd: c_int) -> bool {
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid `pollfd`, and a zero timeout never waits
    unsafe { libc::poll(&mut poll, 1, 0) > 0 }
}

/// One query on the shared connection, cancelled when dropped.
struct SharedQuery {
    connection: Arc<Connection>,
    sd_ref: ffi::DNSServiceRef,
}

// SAFETY: `sd_ref` is an opaque handle, only used under the connection's lock.
unsafe impl Send for SharedQuery {}

impl Drop for SharedQuery {
    fn drop(&mut self) {
        let _api = self.connection.api.lock();
        // SAFETY: `sd_ref` is this query's own, deallocated once, here, while
        // the shared reference it belongs to is still alive.
        unsafe { ffi::DNSServiceRefDeallocate(self.sd_ref) };
    }
}

fn dns_name_from_domain(domain: &str) -> Result<CString, BoxError> {
    let name = domain.trim_end_matches('.');
    CString::new(name).map_err(|_e| {
        AppleDnsResolverError::message(format!("domain contains interior NUL byte: {name}")).into()
    })
}

fn queue_error<T, P>(state: &QueryState<T, P>, err: impl Into<BoxError>)
where
    T: Send + 'static,
    P: Fn(&[u8], &mut dyn FnMut(T)) -> Result<(), BoxError> + Send + Sync,
{
    state.done.store(true, Ordering::SeqCst);
    let mut queue = state.queue.lock();
    queue.clear();
    queue.push_back(Err(err.into()));
    drop(queue);
    state.answered.notify_one();
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
    state.queue.lock().clear();
    state.answered.notify_one();
    tracing::debug!(operation, code, "dns::apple: finish with empty result");
}

const fn is_empty_result_error(code: ffi::DNSServiceErrorType) -> bool {
    matches!(
        code,
        ffi::K_DNS_SERVICE_ERR_NO_SUCH_NAME | ffi::K_DNS_SERVICE_ERR_NO_SUCH_RECORD
    )
}

/// # Safety
///
/// `ptr` must either be null or point to a valid NUL-terminated C string
/// for the duration of this call.
unsafe fn c_char_ptr_to_str_lossy<'a>(ptr: *const c_char) -> std::borrow::Cow<'a, str> {
    if ptr.is_null() {
        return "".into();
    }

    // SAFETY: upheld by the function contract above.
    unsafe { CStr::from_ptr(ptr) }.to_string_lossy()
}

/// # Safety
///
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

    // `DNSServiceProcessResult` can dispatch callbacks that were already
    // queued after an earlier callback made this batch terminal. Never let a
    // later callback append records after an error or completed response.
    if state.done.load(Ordering::SeqCst) {
        return;
    }

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
    let mut parsed = Vec::new();
    match (state.parser)(rdata, &mut |record| parsed.push(record)) {
        Ok(()) => {
            let mut queue = state.queue.lock();
            if state.done.load(Ordering::SeqCst) {
                return;
            }
            for record in parsed {
                tracing::debug!(
                    rrtype,
                    %domain,
                    "dns::apple: answer: {record:?}"
                );
                queue.push_back(Ok(record));
            }
        }
        Err(err) => {
            let mut queue = state.queue.lock();
            queue.clear();
            queue.push_back(Err(err));
            state.done.store(true, Ordering::SeqCst);
            drop(queue);
            state.answered.notify_one();
            return;
        }
    }

    // `kDNSServiceFlagsMoreComing` covers every query on the shared
    // connection: without it the socket is drained and these records are
    // complete, with it the batch counter tells when they are
    if flags & ffi::K_DNS_SERVICE_FLAGS_MORE_COMING == 0 {
        state.done.store(true, Ordering::Release);
    } else {
        state
            .touched_in
            .store(state.batch.load(Ordering::Acquire), Ordering::Release);
    }
    state.answered.notify_one();
}

#[derive(Debug)]
struct QueryState<T, P> {
    queue: Mutex<VecDeque<Result<T, BoxError>>>,
    done: AtomicBool,
    /// The batch its first records came in, or [`UNTOUCHED`].
    touched_in: AtomicU64,
    /// The connection's batch counter.
    batch: Arc<AtomicU64>,
    answered: Notify,
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

fn parse_a(rdata: &[u8], emit: &mut dyn FnMut(Ipv4Addr)) -> Result<(), BoxError> {
    emit(parse_a_rdata(rdata)?);
    Ok(())
}

fn parse_aaaa(rdata: &[u8], emit: &mut dyn FnMut(Ipv6Addr)) -> Result<(), BoxError> {
    emit(parse_aaaa_rdata(rdata)?);
    Ok(())
}

fn parse_txt(rdata: &[u8], emit: &mut dyn FnMut(Txt)) -> Result<(), BoxError> {
    emit(Txt::parse_rdata(rdata)?);
    Ok(())
}

fn parse_cname(rdata: &[u8], emit: &mut dyn FnMut(Name)) -> Result<(), BoxError> {
    emit(Name::from_wire(rdata)?);
    Ok(())
}

fn parse_service_binding(
    rdata: &[u8],
    emit: &mut dyn FnMut(ServiceBinding),
) -> Result<(), BoxError> {
    emit(ServiceBinding::parse_rdata(rdata)?);
    Ok(())
}

#[derive(Debug)]
struct AppleDnsResolverError(ArcStr);

impl AppleDnsResolverError {
    fn message(message: impl Into<ArcStr>) -> Self {
        Self(message.into())
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
    // Canonical name for an alias.
    pub(super) const K_DNS_SERVICE_TYPE_CNAME: u16 = 5;
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

    // Run an operation over the connection of an existing
    // `DNSServiceCreateConnection` reference, instead of a socket of its own.
    pub(super) const K_DNS_SERVICE_FLAGS_SHARE_CONNECTION: DNSServiceFlags = 0x4000;

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
        // Create a connection to the daemon allowing efficient registration of
        // multiple individual records, and operations sharing it via
        // kDNSServiceFlagsShareConnection.
        //
        //  @param sdRef
        //   A pointer to an uninitialized DNSServiceRef. Deallocating the
        //   reference terminates the connection and every operation on it.
        pub(super) fn DNSServiceCreateConnection(sd_ref: *mut DNSServiceRef)
        -> DNSServiceErrorType;

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
    use rama_core::{error::error_chain, futures::future::join_all};

    use super::*;

    #[tokio::test]
    async fn burst_of_lookups_for_one_name_all_resolve() {
        let resolver = AppleDnsResolver::new();
        let domain = Domain::from_static("localhost");

        let lookups = (0..256).map(|_| resolver.lookup_ipv4(domain.clone()).collect::<Vec<_>>());
        for addrs in join_all(lookups).await {
            assert!(!addrs.is_empty(), "localhost resolves");
            assert!(
                addrs
                    .iter()
                    .all(|addr| addr.as_ref().is_ok_and(Ipv4Addr::is_loopback))
            );
        }
    }

    #[tokio::test]
    async fn lookup_waiting_for_a_busy_slot_times_out() {
        let resolver = AppleDnsResolver::new()
            .with_max_concurrency(1)
            .with_timeout(Duration::from_millis(100));
        assert_eq!(resolver.max_concurrency(), 1);
        let _busy = resolver
            .limit
            .acquire(deadline_after(Duration::from_secs(5)))
            .await
            .expect("the only slot");

        let started = Instant::now();
        let items: Vec<_> = resolver
            .lookup_ipv4(Domain::from_static("localhost"))
            .collect()
            .await;
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(matches!(
            items.as_slice(),
            [Err(err)] if error_chain(err.as_ref()).any(|cause| cause.is::<DnsTimeoutError>())
        ));
    }

    #[tokio::test]
    async fn leading_dot_name_is_refused_before_sharing() {
        let resolver = AppleDnsResolver::new();
        let (bare, dotted) = tokio::join!(
            resolver
                .lookup_ipv4(Domain::from_static("localhost"))
                .collect::<Vec<_>>(),
            resolver
                .lookup_ipv4(Domain::from_static(".localhost"))
                .collect::<Vec<_>>(),
        );
        assert!(bare.iter().any(Result::is_ok), "{bare:?}");
        assert!(
            matches!(dotted.as_slice(), [Err(err)] if err.to_string().contains("starts with a dot")),
            "{dotted:?}"
        );
    }

    #[tokio::test]
    async fn rooted_and_relative_names_share_one_query() {
        let resolver = AppleDnsResolver::new().with_timeout(Duration::from_millis(500));
        // the root dot is dropped before the query: both ask the same thing
        let lookups = [
            "unanswered.rama-dns-test.local",
            "unanswered.rama-dns-test.local.",
        ]
        .map(|name| {
            resolver
                .lookup_ipv4(name.try_into().expect("valid domain"))
                .collect::<Vec<_>>()
        });
        // both lookups have joined by the time this is first polled
        let running = async { resolver.in_flight.running() };
        let (_, running) = tokio::join!(join_all(lookups), running);
        assert_eq!(running, 1);
    }

    /// An mDNS name nobody answers, so its query stays open.
    fn unanswered(i: usize) -> Domain {
        format!("unanswered-{i}.rama-dns-test.local")
            .try_into()
            .expect("valid domain")
    }

    fn connection(resolver: &AppleDnsResolver) -> Option<Arc<Connection>> {
        resolver.connection.current.lock().clone()
    }

    #[tokio::test]
    async fn concurrent_queries_share_one_connection() {
        let resolver = AppleDnsResolver::new().with_timeout(Duration::from_millis(300));
        let lookups = (0..64).map(|i| resolver.lookup_ipv4(unanswered(i)).collect::<Vec<_>>());
        let watch = async {
            let deadline = Instant::now() + Duration::from_millis(250);
            while resolver.in_flight.running() != 64 && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let shared = connection(&resolver).expect("an open connection");
            (
                resolver.in_flight.running(),
                Arc::strong_count(&shared),
                shared,
            )
        };
        let (_, (running, users, shared)) = tokio::join!(join_all(lookups), watch);

        assert_eq!(running, 64);
        // every running query holds the one connection
        assert!(users > 64, "{users}");
        assert!(
            Arc::ptr_eq(&shared, &connection(&resolver).expect("still open")),
            "one connection for the whole burst",
        );
    }

    #[tokio::test]
    async fn a_lost_connection_fails_its_queries_and_is_replaced() {
        let resolver = AppleDnsResolver::new().with_timeout(Duration::from_secs(5));
        let pending = resolver.lookup_ipv4(unanswered(0)).collect::<Vec<_>>();
        let lose = async {
            let deadline = Instant::now() + Duration::from_secs(1);
            while connection(&resolver).is_none() && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let lost = connection(&resolver).expect("an open connection");
            // as when the driver ends: the daemon went away, or its runtime did
            lost.close();
            lost
        };
        let started = Instant::now();
        let (items, lost) = tokio::join!(pending, lose);

        assert!(started.elapsed() < Duration::from_secs(1), "failed at once");
        assert!(
            matches!(items.as_slice(), [Err(err)] if err.to_string().contains("connection lost")),
            "{items:?}"
        );
        let addrs: Vec<_> = resolver
            .lookup_ipv4(Domain::from_static("localhost"))
            .collect()
            .await;
        assert!(addrs.iter().any(Result::is_ok), "{addrs:?}");
        let fresh = connection(&resolver).expect("a new connection");
        assert!(!Arc::ptr_eq(&lost, &fresh));
    }

    #[tokio::test]
    async fn the_last_resolver_clone_closes_the_connection() {
        let resolver = AppleDnsResolver::new();
        let addrs: Vec<_> = resolver
            .lookup_ipv4(Domain::from_static("localhost"))
            .collect()
            .await;
        assert!(addrs.iter().any(Result::is_ok), "{addrs:?}");
        let open = Arc::downgrade(&connection(&resolver).expect("an open connection"));

        let clone = resolver.clone();
        drop(resolver);
        assert!(open.upgrade().is_some(), "a clone still uses it");
        drop(clone);
        tokio::time::timeout(Duration::from_secs(1), async {
            while open.upgrade().is_some() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the driver lets the connection go");
    }

    #[tokio::test]
    async fn queued_lookup_reports_its_whole_budget() {
        let resolver = AppleDnsResolver::new()
            .with_max_concurrency(1)
            .with_timeout(Duration::from_millis(300));
        let slot = resolver
            .limit
            .acquire(deadline_after(Duration::from_secs(5)))
            .await
            .expect("the only slot");
        let release = async {
            tokio::time::sleep(Duration::from_millis(150)).await;
            drop(slot);
        };
        // an mDNS name nobody answers, so the query itself runs out the budget
        let lookup = resolver
            .lookup_ipv4(Domain::from_static("unanswered.rama-dns-test.local"))
            .collect::<Vec<_>>();
        let (items, ()) = tokio::join!(lookup, release);

        let timeout = items
            .iter()
            .find_map(|item| item.as_ref().err())
            .and_then(|err| {
                error_chain(err.as_ref()).find_map(|cause| cause.downcast_ref::<DnsTimeoutError>())
            })
            .map(DnsTimeoutError::timeout);
        assert_eq!(timeout, Some(Duration::from_millis(300)), "{items:?}");
    }

    #[test]
    fn only_resolvers_with_the_same_timeout_share_lookups() {
        let resolver = AppleDnsResolver::new();
        assert!(resolver.clone().in_flight.shares_with(&resolver.in_flight));
        let hasty = resolver.clone().with_timeout(Duration::from_millis(100));
        assert!(!hasty.in_flight.shares_with(&resolver.in_flight));
    }

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
        assert_eq!(txt.len(), 1);
        assert_eq!(
            txt[0].iter().collect::<Vec<_>>(),
            vec![&b"foo"[..], &b"bar"[..]]
        );
    }

    #[test]
    fn parse_cname_record() {
        let mut records = Vec::new();
        parse_cname(b"\x05alias\x07example\x03com\0", &mut |record| {
            records.push(record)
        })
        .expect("valid CNAME");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].to_string(), "alias.example.com.");

        parse_cname(&[0xc0, 0x0c], &mut |_| {}).expect_err("standalone RDATA is uncompressed");
    }

    #[test]
    fn malformed_txt_record_is_rejected_without_emitting() {
        let mut emitted = false;
        parse_txt(&[3, b'f', b'o'], &mut |_| emitted = true).expect_err("truncated TXT string");
        assert!(!emitted);
    }

    #[test]
    fn parse_service_binding_record() {
        let mut records = Vec::new();
        parse_service_binding(&[0, 1, 0, 0, 3, 0, 2, 0x20, 0xfb], &mut |record| {
            records.push(record)
        })
        .expect("valid service binding");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].priority(), 1);
        assert_eq!(records[0].port(), Some(8443));
    }

    #[test]
    fn malformed_service_binding_record_is_rejected() {
        let err = parse_service_binding(&[0, 1], &mut |_| {}).expect_err("target name is required");
        assert!(err.to_string().contains("target name"), "got: {err}");
    }

    fn test_state<T, P>(
        parser: P,
        queued: impl IntoIterator<Item = Result<T, BoxError>>,
    ) -> QueryState<T, P> {
        QueryState {
            queue: Mutex::new(queued.into_iter().collect()),
            done: AtomicBool::new(false),
            touched_in: AtomicU64::new(UNTOUCHED),
            batch: Arc::default(),
            answered: Notify::new(),
            parser,
        }
    }

    #[test]
    fn malformed_service_binding_discards_the_pending_rrset() {
        type Parser = fn(&[u8], &mut dyn FnMut(ServiceBinding)) -> Result<(), BoxError>;

        let mut state = test_state::<ServiceBinding, Parser>(parse_service_binding, []);
        let fullname = CString::new("example.com.").expect("valid C string");
        let valid: [u8; 9] = [0, 1, 0, 0, 3, 0, 2, 0x20, 0xfb];
        let malformed: [u8; 2] = [0, 1];

        // SAFETY: every pointer passed to the callback remains live for the
        // duration of each synchronous test invocation.
        unsafe {
            query_record_callback::<ServiceBinding, Parser>(
                ptr::null_mut(),
                ffi::K_DNS_SERVICE_FLAGS_MORE_COMING,
                0,
                ffi::K_DNS_SERVICE_ERR_NO_ERROR,
                fullname.as_ptr(),
                RecordType::SVCB.into(),
                ffi::K_DNS_SERVICE_CLASS_IN,
                valid.len() as u16,
                valid.as_ptr().cast(),
                60,
                ptr::from_mut(&mut state).cast(),
            );
        }
        assert!(
            !state.done.load(Ordering::SeqCst),
            "callback ended early: queue={:?}",
            state.queue.lock(),
        );
        assert_eq!(
            state.touched_in.load(Ordering::SeqCst),
            0,
            "touched in batch 0"
        );
        assert_eq!(state.queue.lock().len(), 1);

        // SAFETY: same live test storage as above.
        unsafe {
            query_record_callback::<ServiceBinding, Parser>(
                ptr::null_mut(),
                0,
                0,
                ffi::K_DNS_SERVICE_ERR_NO_ERROR,
                fullname.as_ptr(),
                RecordType::SVCB.into(),
                ffi::K_DNS_SERVICE_CLASS_IN,
                malformed.len() as u16,
                malformed.as_ptr().cast(),
                60,
                ptr::from_mut(&mut state).cast(),
            );
        }

        // A callback already queued by DNSServiceProcessResult after the
        // malformed member must observe the terminal latch and do nothing.
        // SAFETY: same live test storage as above.
        unsafe {
            query_record_callback::<ServiceBinding, Parser>(
                ptr::null_mut(),
                0,
                0,
                ffi::K_DNS_SERVICE_ERR_NO_ERROR,
                fullname.as_ptr(),
                RecordType::SVCB.into(),
                ffi::K_DNS_SERVICE_CLASS_IN,
                valid.len() as u16,
                valid.as_ptr().cast(),
                60,
                ptr::from_mut(&mut state).cast(),
            );
        }

        let items = drain_queue(&state);
        assert_eq!(items.len(), 1);
        items[0]
            .as_ref()
            .expect_err("malformed RRset must yield an error");
        assert!(state.done.load(Ordering::SeqCst));
    }

    #[test]
    fn terminal_callback_outcomes_discard_pending_records() {
        type Parser = fn(&[u8], &mut dyn FnMut(ServiceBinding)) -> Result<(), BoxError>;

        let pending = || {
            ServiceBinding::parse_rdata(&[0, 1, 0, 0, 3, 0, 2, 0x20, 0xfb])
                .expect("valid pending record")
        };
        let state = test_state::<ServiceBinding, Parser>(parse_service_binding, [Ok(pending())]);
        queue_error(&state, AppleDnsResolverError::message("callback failed"));
        let items = drain_queue(&state);
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0]
                .as_ref()
                .expect_err("callback failure must replace pending records")
                .to_string(),
            "callback failed"
        );
        assert!(state.done.load(Ordering::SeqCst));

        let state = test_state::<ServiceBinding, Parser>(parse_service_binding, [Ok(pending())]);
        finish_empty(&state, "test", ffi::K_DNS_SERVICE_ERR_NO_SUCH_RECORD);
        assert!(drain_queue(&state).is_empty());
        assert!(state.done.load(Ordering::SeqCst));
    }

    #[test]
    fn empty_result_errors_are_classified() {
        assert!(is_empty_result_error(ffi::K_DNS_SERVICE_ERR_NO_SUCH_NAME));
        assert!(is_empty_result_error(ffi::K_DNS_SERVICE_ERR_NO_SUCH_RECORD));
        assert!(!is_empty_result_error(ffi::K_DNS_SERVICE_ERR_NO_ERROR));
    }
}
