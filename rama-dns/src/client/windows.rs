//! Windows-native DNS resolver backed by `DnsQueryEx` from `Dnsapi.dll`.

use std::{
    collections::VecDeque,
    ffi::c_void,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::pin,
    ptr::{self, NonNull},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use rama_core::{
    error::BoxError,
    futures::{Stream, StreamExt as _, async_stream::stream_fn, future::Either, stream},
    telemetry::tracing,
};
use rama_net::address::Domain;
use rama_utils::{macros::generate_set_and_with, str::arcstr::ArcStr};

use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio::time::Instant;

#[cfg(test)]
use std::sync::atomic::{AtomicU16, AtomicUsize};

use super::{
    in_flight::{Abandoned, InFlight, coalesced_stream, leading_dot_refusal},
    limit::{DnsTimeoutError, Limits, LookupLimit, deadline_after},
    resolver::{
        DnsAddressResolver, DnsCnameResolver, DnsResolver, DnsServiceBindingResolver,
        DnsTxtResolver,
    },
};
use crate::wire::{Name, RecordType, ServiceBinding, Txt};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
enum DnsBackend {
    System,
    #[cfg(test)]
    Fake(Arc<FakeDnsBackend>),
}

impl DnsBackend {
    /// Start a query with `DnsQueryEx`, or with the test fake.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// - `request` points to an initialized version-1 `DNS_QUERY_REQUEST`
    ///   whose `QueryName` points to a NUL-terminated UTF-16 name, whose
    ///   completion routine is [`query_completion_callback`] and whose
    ///   context meets that routine's `# Safety` contract for this query;
    /// - `result` points to a writable version-1 `DNS_QUERY_RESULT` whose
    ///   other members are null or 0, and `cancel` to a writable
    ///   `DNS_QUERY_CANCEL`;
    /// - if the call returns [`ffi::DNS_REQUEST_PENDING`], the request with
    ///   its name, the result and the cancel handle stay allocated, and are
    ///   accessed only by dnsapi, the completion routine and
    ///   [`DnsBackend::cancel`], until the completion routine was invoked
    ///   and every [`DnsBackend::cancel`] with that handle returned. The
    ///   completion routine itself may free them once it no longer uses them.
    ///
    /// Any other return value means the query finished synchronously:
    /// `result` holds its outcome, the completion routine is never called and
    /// no pointer is retained (`DnsQueryEx` docs).
    unsafe fn query(
        &self,
        request: *const ffi::DNS_QUERY_REQUEST,
        result: *mut ffi::DNS_QUERY_RESULT,
        cancel: *mut ffi::DNS_QUERY_CANCEL,
    ) -> i32 {
        match self {
            // SAFETY: `DnsQueryEx` needs a valid request, a version-1 result
            // and a cancel handle that a pending query keeps until its
            // completion routine is invoked: this function's contract.
            Self::System => unsafe { ffi::DnsQueryEx(request, result, cancel) },
            #[cfg(test)]
            // SAFETY: the `FakeDnsBackend::query` contract is this one.
            Self::Fake(fake) => unsafe { fake.query(request, result, cancel) },
        }
    }

    /// Ask to cancel a pending query; returns its `DNS_STATUS`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `cancel` is the cancel handle of a query
    /// whose [`DnsBackend::query`] call on this backend returned
    /// [`ffi::DNS_REQUEST_PENDING`], and that it stays allocated until this
    /// call returned.
    unsafe fn cancel(&self, cancel: *mut ffi::DNS_QUERY_CANCEL) -> i32 {
        match self {
            // SAFETY: `DnsCancelQuery` needs the cancel handle of a pending
            // `DnsQueryEx` call that stays allocated while it runs (DnsQueryEx
            // and DnsCancelQuery docs): this function's contract.
            Self::System => unsafe { ffi::DnsCancelQuery(cancel.cast_const()) },
            #[cfg(test)]
            Self::Fake(fake) => {
                // SAFETY: the `FakeDnsBackend::cancel` contract is this one.
                unsafe { fake.cancel(cancel) };
                ffi::ERROR_SUCCESS
            }
        }
    }

    /// Free a record list, as `DnsFree` with `DnsFreeRecordList` does.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `records` is the head of a record list a
    /// [`DnsBackend::query`] on this backend returned, not freed yet and not
    /// used by anything once this call returns.
    unsafe fn free_records(&self, records: *mut ffi::DNS_RECORDA) {
        match self {
            // SAFETY: `DnsFree` with `DnsFreeRecordList` frees a record list
            // returned by a DNS query function (DnsFree docs). By this
            // function's contract the list is such a list, unfreed and unused
            // afterwards.
            Self::System => unsafe {
                ffi::DnsFree(records.cast_const().cast(), ffi::DnsFreeRecordList)
            },
            #[cfg(test)]
            // SAFETY: the `FakeDnsBackend::free` contract is this one.
            Self::Fake(fake) => unsafe { fake.free(records) },
        }
    }

    #[cfg(test)]
    fn note_wait_loop_iteration(&self) {
        if let Self::Fake(fake) = self {
            fake.wait_loop_iterations.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[cfg(test)]
    fn note_block_dropped(&self) {
        if let Self::Fake(fake) = self {
            fake.blocks_dropped.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[cfg(not(test))]
const _: () = assert!(std::mem::size_of::<DnsBackend>() == 0);

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Windows-native [`DnsResolver`] implementation using `DnsQueryEx`.
///
/// Windows exposes TXT strings through `DNS_TXT_DATAW` as UTF-16. This
/// resolver stores their UTF-8 encoding in [`Txt`], so its TXT results preserve
/// string and record boundaries but cannot guarantee the original arbitrary
/// wire octets are binary-transparent. Use a wire-native resolver such as
/// Hickory when exact TXT octets are required on Windows.
///
/// Concurrent lookups of one name and record type share one query. Lookups
/// are unbounded by default: the DNS Client service queues them itself.
///
/// A and AAAA lookups of this computer's own name are answered from its
/// unicast addresses without a DNS query, as getaddrinfo does; see
/// [`Self::local_hostname`].
pub struct WindowsDnsResolver {
    timeout: Duration,
    local_hostname: bool,
    limit: LookupLimit,
    in_flight: InFlight<(Domain, u16)>,
}

impl Default for WindowsDnsResolver {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            local_hostname: true,
            limit: LookupLimit::new(Limits::UNBOUNDED),
            in_flight: InFlight::new(Abandoned::Cancel),
        }
    }
}

impl WindowsDnsResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    generate_set_and_with! {
        /// The budget of one lookup, including any wait for a free slot
        /// (default 5s). Clones made before this call no longer share
        /// lookups with this resolver.
        pub fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self.in_flight = InFlight::new(Abandoned::Cancel);
            self
        }
    }

    #[must_use]
    pub const fn local_hostname(&self) -> bool {
        self.local_hostname
    }

    generate_set_and_with! {
        /// Answer A and AAAA lookups of this computer's DNS host name, fully
        /// qualified DNS name or NetBIOS name (ignoring ASCII case) from its
        /// preferred, non-loopback unicast addresses without a DNS query, as
        /// getaddrinfo checks the local host name before the hosts file and
        /// DNS (default true). IPv6 link-local addresses are left out, as an
        /// answer has no scope id; `false` sends every lookup to DNS. Clones
        /// made before this call no longer share lookups with this resolver.
        pub fn local_hostname(mut self, enabled: bool) -> Self {
            self.local_hostname = enabled;
            self.in_flight = InFlight::new(Abandoned::Cancel);
            self
        }
    }

    #[must_use]
    pub fn max_concurrency(&self) -> Option<usize> {
        self.limit.limits().max_concurrency
    }

    generate_set_and_with! {
        /// Maximum concurrent `DnsQueryEx` queries (default unbounded: the
        /// DNS Client service queues them itself; at least 1). Lookups past
        /// the bound wait for a slot within their timeout. Clones made before
        /// this call keep their own bounds.
        pub fn max_concurrency(mut self, max: Option<usize>) -> Self {
            self.limit = self.limit.with(|limits| limits.max_concurrency = max);
            self
        }
    }

    #[must_use]
    pub fn burst_limit(&self) -> Option<usize> {
        self.limit.limits().burst_limit
    }

    generate_set_and_with! {
        /// Maximum queries started within one [burst window](Self::burst_window)
        /// and still unanswered (default unbounded, at least 1); an answer
        /// frees its place at once, a query waiting on a slow upstream once
        /// the window has passed. Clones made before this call keep their own
        /// bounds.
        pub fn burst_limit(mut self, max: Option<usize>) -> Self {
            self.limit = self.limit.with(|limits| limits.burst_limit = max);
            self
        }
    }

    #[must_use]
    pub fn burst_window(&self) -> Duration {
        self.limit.limits().burst_window
    }

    generate_set_and_with! {
        /// The window of [`Self::burst_limit`] (default 20ms). Windows' default
        /// 15.6ms timer tick stretches a 20ms window to about 31ms. Clones
        /// made before this call keep their own bounds.
        pub fn burst_window(mut self, window: Duration) -> Self {
            self.limit = self.limit.with(|limits| limits.burst_window = window);
            self
        }
    }

    /// Concurrent lookups of one name and record type share one query.
    fn coalesced<T, S>(
        &self,
        domain: Domain,
        rrtype: u16,
        lookup: impl FnOnce(Domain, Instant, Duration) -> S + Send + 'static,
    ) -> impl Stream<Item = Result<T, BoxError>> + Send + '_
    where
        T: Clone + Send + Sync + 'static,
        S: Stream<Item = Result<T, BoxError>> + Send + 'static,
    {
        if let Some(err) = leading_dot_refusal(&domain) {
            return Either::Left(stream::once(std::future::ready(Err(err))));
        }
        let (timeout, limit) = (self.timeout, self.limit.clone());
        // the name goes out without its root dot: `x` and `x.` are one query
        let key = (domain.clone(), rrtype);
        Either::Right(coalesced_stream(
            self.in_flight.clone(),
            key,
            timeout,
            move || {
                limited_stream(limit, timeout, move |deadline| {
                    lookup(domain, deadline, timeout)
                })
            },
        ))
    }

    /// An A or AAAA lookup, answered locally when `domain` names this computer.
    fn address_lookup<T: HostAddress>(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<T, BoxError>> + Send + '_ {
        let local_host = self.local_hostname.then_some(LocalHost::System);
        self.address_lookup_on(domain, local_host, DnsBackend::System)
    }

    /// [`Self::address_lookup`] with names and addresses from `local_host`
    /// (`None` is DNS only) and queries on `backend`.
    fn address_lookup_on<T: HostAddress>(
        &self,
        domain: Domain,
        local_host: Option<LocalHost>,
        backend: DnsBackend,
    ) -> impl Stream<Item = Result<T, BoxError>> + Send + '_ {
        match own_name_stream(local_host, &domain) {
            // a local answer takes no query slot
            Some(answer) => Either::Left(answer),
            None => Either::Right(self.coalesced(
                domain,
                T::RRTYPE,
                move |domain, deadline, timeout| {
                    query_record_stream_with_backend(
                        domain,
                        deadline,
                        timeout,
                        T::RRTYPE,
                        T::PARSER,
                        backend,
                    )
                },
            )),
        }
    }
}

/// `lookup` once `limit` has a slot for it, holding the slot until it ends.
///
/// `lookup` gets the deadline `timeout` sets for the whole lookup.
fn limited_stream<T, S>(
    limit: LookupLimit,
    timeout: Duration,
    lookup: impl FnOnce(Instant) -> S + Send + 'static,
) -> impl Stream<Item = Result<T, BoxError>> + Send
where
    T: Send + 'static,
    S: Stream<Item = Result<T, BoxError>> + Send,
{
    stream_fn(async move |mut yielder| {
        let deadline = deadline_after(timeout);
        let Some(mut slot) = limit.acquire(deadline).await else {
            yielder
                .yield_item(Err(DnsTimeoutError::new(timeout).into()))
                .await;
            return;
        };
        let mut items = pin!(lookup(deadline));
        while let Some(item) = items.next().await {
            slot.saw(&item);
            yielder.yield_item(item).await;
        }
        slot.answered();
    })
}

impl DnsAddressResolver for WindowsDnsResolver {
    type Error = BoxError;

    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        self.address_lookup(domain)
    }

    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        self.address_lookup(domain)
    }
}

impl DnsTxtResolver for WindowsDnsResolver {
    type Error = BoxError;

    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Txt, Self::Error>> + Send + '_ {
        self.coalesced(domain, ffi::DNS_TYPE_TEXT, |domain, deadline, timeout| {
            query_record_stream(
                domain,
                deadline,
                timeout,
                ffi::DNS_TYPE_TEXT,
                parse_txt_records,
            )
        })
    }
}

impl DnsCnameResolver for WindowsDnsResolver {
    type Error = BoxError;

    fn lookup_cname(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Name, Self::Error>> + Send + '_ {
        self.coalesced(domain, ffi::DNS_TYPE_CNAME, |domain, deadline, timeout| {
            query_record_stream(
                domain,
                deadline,
                timeout,
                ffi::DNS_TYPE_CNAME,
                parse_cname_records,
            )
        })
    }
}

impl DnsServiceBindingResolver for WindowsDnsResolver {
    type Error = BoxError;

    fn lookup_svcb(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
        self.coalesced(
            domain,
            RecordType::SVCB.into(),
            |domain, deadline, timeout| {
                query_record_stream(
                    domain,
                    deadline,
                    timeout,
                    RecordType::SVCB.into(),
                    parse_svcb_records,
                )
            },
        )
    }

    fn lookup_https(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
        self.coalesced(
            domain,
            RecordType::HTTPS.into(),
            |domain, deadline, timeout| {
                query_record_stream(
                    domain,
                    deadline,
                    timeout,
                    RecordType::HTTPS.into(),
                    parse_https_records,
                )
            },
        )
    }
}

impl DnsResolver for WindowsDnsResolver {}

/// An address type, looked up as A or AAAA records.
trait HostAddress: fmt::Debug + Clone + Send + Sync + 'static {
    const RRTYPE: u16;
    const PARSER: RecordParser<Self>;

    /// `ip` if it is of this family.
    fn from_ip(ip: IpAddr) -> Option<Self>;
}

impl HostAddress for Ipv4Addr {
    const RRTYPE: u16 = ffi::DNS_TYPE_A;
    const PARSER: RecordParser<Self> = parse_a_records;

    fn from_ip(ip: IpAddr) -> Option<Self> {
        match ip {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        }
    }
}

impl HostAddress for Ipv6Addr {
    const RRTYPE: u16 = ffi::DNS_TYPE_AAAA;
    const PARSER: RecordParser<Self> = parse_aaaa_records;

    fn from_ip(ip: IpAddr) -> Option<Self> {
        match ip {
            IpAddr::V4(_) => None,
            IpAddr::V6(ip) => Some(ip),
        }
    }
}

/// This computer's addresses of family `T`, in table order, if `domain` is
/// one of the names of `local_host`; `None` otherwise. The address table is
/// read when the stream is first polled.
fn own_name_stream<T: HostAddress>(
    local_host: Option<LocalHost>,
    domain: &Domain,
) -> Option<impl Stream<Item = Result<T, BoxError>> + Send + use<T>> {
    let host =
        local_host.filter(|host| is_computer_name(domain.as_str(), &host.computer_names()))?;
    tracing::debug!(%domain, "dns::windows: own computer name, answered locally");
    Some(
        stream::once(async move { host.unicast_addresses() }).flat_map(|rows| {
            let items: Vec<_> = match rows {
                Ok(rows) => rows
                    .iter()
                    .filter(|row| row.answers_own_name())
                    .filter_map(|row| T::from_ip(row.ip))
                    .map(Ok)
                    .collect(),
                Err(err) => vec![Err(err)],
            };
            stream::iter(items)
        }),
    )
}

/// Whether `domain`, less one root dot, equals one of the non-empty `names`,
/// ignoring ASCII case.
fn is_computer_name(domain: &str, names: &[Box<str>]) -> bool {
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    !domain.is_empty()
        && names
            .iter()
            .any(|name| !name.is_empty() && name.eq_ignore_ascii_case(domain))
}

/// Where this computer's names and unicast addresses are read from.
#[derive(Clone)]
enum LocalHost {
    System,
    #[cfg(test)]
    Fake(Arc<FakeLocalHost>),
}

impl LocalHost {
    /// The non-empty DNS host, fully qualified DNS and NetBIOS names.
    fn computer_names(&self) -> Arc<[Box<str>]> {
        match self {
            Self::System => local_host::cached_computer_names(),
            #[cfg(test)]
            Self::Fake(fake) => fake.names.clone(),
        }
    }

    /// Every IPv4 and IPv6 row of the unicast address table, in table order.
    fn unicast_addresses(&self) -> Result<Vec<UnicastAddress>, BoxError> {
        match self {
            Self::System => local_host::unicast_addresses(),
            #[cfg(test)]
            Self::Fake(fake) => Ok(fake.addresses.clone()),
        }
    }
}

/// One IPv4 or IPv6 row of the unicast address table.
#[derive(Debug, Clone, Copy)]
struct UnicastAddress {
    ip: IpAddr,
    skip_as_source: bool,
    dad_state: ffi::NL_DAD_STATE,
}

impl UnicastAddress {
    /// getaddrinfo answers a computer name with the addresses that are not
    /// `SkipAsSource`; IPv6 link-local ones would need a scope id.
    fn answers_own_name(&self) -> bool {
        !self.skip_as_source
            && self.dad_state == ffi::IpDadStatePreferred
            && !self.ip.is_loopback()
            && !matches!(self.ip, IpAddr::V6(ip) if ip.is_unicast_link_local())
    }
}

#[cfg(test)]
struct FakeLocalHost {
    names: Arc<[Box<str>]>,
    addresses: Vec<UnicastAddress>,
}

/// Parses the record list of a finished query, emitting each value of the
/// parser's record type; an error discards the whole RRset.
///
/// # Safety
///
/// The caller must pass a `records` list that meets the
/// [`walk_record_pointers`] `# Safety` contract for the duration of the call.
type RecordParser<T> = unsafe fn(*const ffi::DnsRecord, &mut dyn FnMut(T)) -> Result<(), BoxError>;

fn query_record_stream<T>(
    domain: Domain,
    deadline: Instant,
    timeout: Duration,
    rrtype: u16,
    parser: RecordParser<T>,
) -> impl Stream<Item = Result<T, BoxError>> + Send
where
    T: fmt::Debug + Send + 'static,
{
    query_record_stream_with_backend(
        domain,
        deadline,
        timeout,
        rrtype,
        parser,
        DnsBackend::System,
    )
}

/// `timeout` is the caller's whole budget, reported on expiry of `deadline`.
fn query_record_stream_with_backend<T>(
    domain: Domain,
    deadline: Instant,
    timeout: Duration,
    rrtype: u16,
    parser: RecordParser<T>,
    backend: DnsBackend,
) -> impl Stream<Item = Result<T, BoxError>> + Send
where
    T: fmt::Debug + Send + 'static,
{
    stream_fn(async move |mut yielder| {
        let state = Arc::new(QueryState {
            queue: Mutex::new(VecDeque::new()),
            done: AtomicBool::new(false),
            timeout,
            timed_out: AtomicBool::new(false),
            suppress_results: AtomicBool::new(false),
            cancel_requested: AtomicBool::new(false),
            notify: Notify::new(),
            inflight: Mutex::new(None),
            parser,
            backend,
        });

        let _cancel_guard = QueryCancelGuard {
            state: state.clone(),
        };

        let name = match dns_name_from_domain(domain.as_str()) {
            Ok(name) => name,
            Err(err) => {
                yielder.yield_item(Err(err)).await;
                return;
            }
        };

        tracing::debug!(?timeout, rrtype, %domain, "dns::windows: query");

        start_query(&state, name, rrtype);

        loop {
            #[cfg(test)]
            state.backend.note_wait_loop_iteration();

            for item in drain_queue(&state) {
                yielder.yield_item(item).await;
            }

            if state.done.load(Ordering::SeqCst) {
                break;
            }

            if state.timed_out.load(Ordering::SeqCst) {
                // cancel already requested; only the completion callback ends the query now
                state.notify.notified().await;
                continue;
            }

            if let Err(err) = tokio::time::timeout_at(deadline, state.notify.notified()).await {
                tracing::trace!("windows query record stream: timeout reached: {err}");
                state.timed_out.store(true, Ordering::SeqCst);
                request_cancel(&state);
            }
        }

        for item in drain_queue(&state) {
            yielder.yield_item(item).await;
        }
    })
}

fn start_query<T>(state: &Arc<QueryState<T>>, name: Vec<u16>, rrtype: u16)
where
    T: fmt::Debug + Send + 'static,
{
    let context = Arc::into_raw(state.clone());
    let block = NonNull::from(Box::leak(Box::new(InFlightQuery::new(
        name,
        rrtype,
        context.cast_mut().cast(),
        query_completion_callback::<T>,
        state.backend.clone(),
    ))));
    let inflight = block.as_ptr();

    // SAFETY: `inflight` comes from `Box::leak` above: aligned and live, so
    // the field projection stays in bounds. No reference to the block is made.
    let request = unsafe { &raw const (*inflight).request };
    // SAFETY: as above.
    let result = unsafe { &raw mut (*inflight).result };
    // SAFETY: as above.
    let cancel = unsafe { &raw mut (*inflight).cancel };

    // SAFETY: the `DnsBackend::query` contract:
    // - `request`, `result` and `cancel` point into the live block built by
    //   `InFlightQuery::new`, whose safety-usable invariant makes it a
    //   version-1 request with a NUL-terminated name held by the block, a
    //   version-1 result with null members and a zeroed cancel handle.
    // - The callback is `query_completion_callback::<T>` and the context the
    //   `Arc<QueryState<T>>` from `Arc::into_raw` above, as its `# Safety`
    //   requires; each pending query completes at most once.
    // - A pending block is only freed by its `InFlightBox`, owned by `state`,
    //   which lives as the `InFlightBox` invariant requires. Until then this
    //   module reaches the block only through raw field pointers.
    let status = unsafe { state.backend.query(request, result, cancel) };

    if status == ffi::DNS_REQUEST_PENDING {
        // Safety invariant of `InFlightBox`: the block is owned by `state`
        // from here on, and the query returned `DNS_REQUEST_PENDING`.
        *state.inflight.lock() = Some(InFlightBox(block));
        return;
    }

    // Per the `DnsBackend::query` postcondition the callback never runs and
    // dnsapi keeps no pointer into the block for a call that is not pending.
    // SAFETY: `Arc::from_raw`: `context` came from `Arc::into_raw` of an
    // `Arc<QueryState<T>>` above and its only other consumer, the callback,
    // never runs, so this reclaims that strong count exactly once.
    drop(unsafe { Arc::from_raw(context) });
    // SAFETY: `Box::from_raw`: `inflight` came from `Box::leak` of a
    // `Box<InFlightQuery>` above, was not freed, and nothing else holds it.
    let mut inflight = unsafe { Box::from_raw(inflight) };
    // SAFETY: the `handle_query_result` contract: `DnsQueryEx` returned
    // synchronously, so `result` holds the finished outcome, and the field
    // invariant of `InFlightQuery::result` gives its record list. The box is
    // exclusively owned here.
    unsafe { handle_query_result(state, &mut inflight.result, status) };
}

fn request_cancel<T>(state: &Arc<QueryState<T>>) {
    if state.cancel_requested.swap(true, Ordering::SeqCst) {
        return;
    }

    if state.done.load(Ordering::SeqCst) {
        return;
    }

    // never hold the lock across FFI: the completion callback takes locks on this state.
    // DnsCancelQuery docs: "DnsCancelQuery does not wait for a query to complete before
    // cancelling", so the callback may run on another thread during the call.
    let cancel = match state.inflight.lock().as_ref() {
        Some(query) => query.cancel_handle(),
        None => return,
    };

    // SAFETY: the `DnsBackend::cancel` contract: an `InFlightBox` is only
    // stored for a query whose start returned `DNS_REQUEST_PENDING`, and it
    // stays in `state`, borrowed for this whole call, so the handle stays
    // allocated until this call returned. The callback may have finished
    // before this call starts, so the handle may be of a completed query;
    // Microsoft's asynchronous `DnsQueryEx` sample cancels under the same race
    // (wait with a timeout, then cancel), and this relies on that documented
    // use with the handle kept allocated:
    // <https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/DNSAsyncQuery/cpp/DnsQueryEx.cpp>.
    _ = unsafe { state.backend.cancel(cancel) };
}

fn drain_queue<T>(state: &QueryState<T>) -> Vec<Result<T, BoxError>> {
    state.queue.lock().drain(..).collect()
}

/// Queue the outcome of a finished query and free its records.
///
/// # Safety
///
/// The caller must ensure that `result` is the `DNS_QUERY_RESULT` of a
/// finished query on `state.backend`: filled by the query call when it
/// returned synchronously, or the one handed to the completion callback. Its
/// `pQueryRecords` must be null or the head of the record list returned for
/// that query, not freed yet. This call takes over that list and frees it.
unsafe fn handle_query_result<T>(
    state: &QueryState<T>,
    result: &mut ffi::DNS_QUERY_RESULT,
    call_status: i32,
) where
    T: fmt::Debug + Send + 'static,
{
    let query_status = if result.QueryStatus == 0 {
        call_status
    } else {
        result.QueryStatus
    };

    if state.suppress_results.load(Ordering::SeqCst) {
        // SAFETY: the `cleanup_result` contract is this function's own.
        unsafe { cleanup_result(&state.backend, result) };
        mark_done(state);
        return;
    }

    if state.timed_out.load(Ordering::SeqCst) && query_status == ffi::ERROR_CANCELLED {
        state
            .queue
            .lock()
            .push_back(Err(DnsTimeoutError::new(state.timeout).into()));
        // SAFETY: as above.
        unsafe { cleanup_result(&state.backend, result) };
        mark_done(state);
        return;
    }

    if matches!(
        query_status,
        ffi::ERROR_SUCCESS | ffi::DNS_INFO_NO_RECORDS | ffi::DNS_ERROR_RCODE_NAME_ERROR
    ) {
        if query_status == ffi::ERROR_SUCCESS && !result.pQueryRecords.is_null() {
            // SAFETY: the `walk_record_pointers` contract. By this function's
            // contract the list is the unfreed answer of `DnsQueryEx`, which
            // returns `DNS_RECORDW` nodes linked through `pNext` whose `Data`
            // holds `wDataLength` bytes, with the strings of CNAME and TXT
            // data allocated with the list (windns.h, `DNS_RECORD` docs). The
            // list is freed only below, after parsing.
            let parsed = unsafe {
                parse_complete_record_set(state.parser, result.pQueryRecords.cast_const().cast())
            };
            match parsed {
                Ok(records) => {
                    for record in &records {
                        tracing::debug!("dns::windows: answer: {record:?}");
                    }
                    state.queue.lock().extend(records.into_iter().map(Ok));
                }
                Err(err) => state.queue.lock().push_back(Err(err)),
            }
        }

        // SAFETY: as above.
        unsafe { cleanup_result(&state.backend, result) };
        mark_done(state);
        return;
    }

    state
        .queue
        .lock()
        .push_back(Err(WindowsDnsResolverError::dns_status(
            "DnsQueryEx",
            query_status,
        )
        .into()));
    // SAFETY: as above.
    unsafe { cleanup_result(&state.backend, result) };
    mark_done(state);
}

/// Parse a complete record list, so that one bad record discards the RRset.
///
/// # Safety
///
/// The caller must ensure the [`RecordParser`] contract for `records`.
unsafe fn parse_complete_record_set<T>(
    parser: RecordParser<T>,
    records: *const ffi::DnsRecord,
) -> Result<Vec<T>, BoxError> {
    let mut parsed = Vec::new();
    // SAFETY: the `RecordParser` contract is this function's own.
    unsafe { parser(records, &mut |record| parsed.push(record)) }?;
    Ok(parsed)
}

/// Free the record list of `result`, if any, and clear the field.
///
/// # Safety
///
/// The caller must ensure that `result.pQueryRecords` is null or the head of
/// a record list a query on `backend` returned, not freed yet and not used by
/// anything once this call returns.
unsafe fn cleanup_result(backend: &DnsBackend, result: &mut ffi::DNS_QUERY_RESULT) {
    if !result.pQueryRecords.is_null() {
        // SAFETY: the `DnsBackend::free_records` contract is this function's
        // own; the field is cleared below so the list is freed once.
        unsafe { backend.free_records(result.pQueryRecords) };
        result.pQueryRecords = ptr::null_mut();
    }
}

fn mark_done<T>(state: &QueryState<T>) {
    state.done.store(true, Ordering::SeqCst);
    // notify_one stores a permit, so a completion racing the consumer's registration still wakes it
    state.notify.notify_one();
}

fn dns_name_from_domain(domain: &str) -> Result<Vec<u16>, BoxError> {
    let name = domain.trim_end_matches('.');
    if name.encode_utf16().any(|unit| unit == 0) {
        return Err(WindowsDnsResolverError::message(format!(
            "domain contains interior NUL code unit: {name}"
        ))
        .into());
    }

    let mut utf16: Vec<u16> = name.encode_utf16().collect();
    utf16.push(0);
    Ok(utf16)
}

/// Copy the fixed-size `Data` payload `D` out of `record`.
///
/// Fails when `wDataLength` is shorter than `D`, since the node's allocation
/// ends with its `Data` bytes.
///
/// # Safety
///
/// The caller must ensure that `record` is a node meeting the
/// [`walk_record_pointers`] contract for the duration of the call, and that
/// every initialized `size_of::<D>()`-byte pattern is a valid `D`.
unsafe fn read_payload<D: Copy>(record: *const ffi::DnsRecord) -> Result<D, BoxError> {
    // SAFETY: a place read of the `wDataLength` field: `record` is aligned and
    // its header is initialized, readable and unwritten (this function's
    // contract). No reference to the node is made.
    let data_length = usize::from(unsafe { (*record).data_length });
    if data_length < std::mem::size_of::<D>() {
        return Err(WindowsDnsResolverError::message(
            "DNS record data is shorter than its record type",
        )
        .into());
    }
    let data = record
        .cast::<u8>()
        .wrapping_add(std::mem::offset_of!(ffi::DnsRecord, data))
        .cast::<D>();
    // SAFETY: `ptr::read_unaligned` needs `data` valid for reads of
    // `size_of::<D>()` initialized bytes forming a valid `D`. Those bytes lie
    // within the node's first `offset_of!(DnsRecord, data) + wDataLength`
    // bytes (checked above), which the contract makes initialized, readable
    // and part of the allocation `record` points into; `wrapping_add` kept
    // that provenance. The caller guarantees the bytes form a valid `D`.
    Ok(unsafe { data.read_unaligned() })
}

/// [`RecordParser`] for A records.
///
/// # Safety
///
/// See [`RecordParser`].
unsafe fn parse_a_records(
    records: *const ffi::DnsRecord,
    emit: &mut dyn FnMut(Ipv4Addr),
) -> Result<(), BoxError> {
    let visit = |record| {
        // SAFETY: `walk_record_pointers` only visits nodes meeting its
        // contract, and any 4 initialized bytes are a valid `DNS_A_DATA`.
        let data = unsafe { read_payload::<ffi::DNS_A_DATA>(record) }?;
        emit(Ipv4Addr::from(u32::from_be(data.ip_address)));
        Ok(())
    };
    // SAFETY: the walk contract is this function's own.
    unsafe { walk_record_pointers(records, ffi::DNS_TYPE_A, visit) }
}

/// [`RecordParser`] for AAAA records.
///
/// # Safety
///
/// See [`RecordParser`].
unsafe fn parse_aaaa_records(
    records: *const ffi::DnsRecord,
    emit: &mut dyn FnMut(Ipv6Addr),
) -> Result<(), BoxError> {
    let visit = |record| {
        // SAFETY: `walk_record_pointers` only visits nodes meeting its
        // contract, and any 16 initialized bytes are a valid `DNS_AAAA_DATA`.
        let data = unsafe { read_payload::<ffi::DNS_AAAA_DATA>(record) }?;
        emit(Ipv6Addr::from(data.ip6_address.ip6_byte));
        Ok(())
    };
    // SAFETY: the walk contract is this function's own.
    unsafe { walk_record_pointers(records, ffi::DNS_TYPE_AAAA, visit) }
}

/// [`RecordParser`] for CNAME records.
///
/// # Safety
///
/// See [`RecordParser`].
unsafe fn parse_cname_records(
    records: *const ffi::DnsRecord,
    emit: &mut dyn FnMut(Name),
) -> Result<(), BoxError> {
    let visit = |record| {
        // SAFETY: `walk_record_pointers` only visits nodes meeting its
        // contract, and initialized bytes are a valid raw pointer.
        let data = unsafe { read_payload::<ffi::DNS_PTR_DATAW>(record) }?;
        if data.name_host.is_null() {
            return Err(WindowsDnsResolverError::message("CNAME target pointer is null").into());
        }
        // SAFETY: the walk contract makes a CNAME node's `pNameHost` an
        // aligned NUL-terminated UTF-16 string, readable and unwritten during
        // the walk, which is the `wide_ptr_to_string` contract.
        let target = unsafe { wide_ptr_to_string(data.name_host) };
        if target == "." {
            emit(Name::root());
        } else {
            emit(Name::from(Domain::try_from(target)?));
        }
        Ok(())
    };
    // SAFETY: the walk contract is this function's own.
    unsafe { walk_record_pointers(records, ffi::DNS_TYPE_CNAME, visit) }
}

/// [`RecordParser`] for TXT records.
///
/// # Safety
///
/// See [`RecordParser`].
unsafe fn parse_txt_records(
    records: *const ffi::DnsRecord,
    emit: &mut dyn FnMut(Txt),
) -> Result<(), BoxError> {
    let visit = |record: *const ffi::DnsRecord| {
        // DNS_TXT_DATAW ends in pStringArray[1], but Windows extends that
        // pointer array to dwStringCount entries in the DNS_RECORD allocation.
        // Keep provenance for the complete allocation and validate the flexible
        // tail against wDataLength before reading any pointer from it.
        // The docs do not say whether wDataLength covers that extended array;
        // if it does not, a multi-string record fails here instead of being read.
        // SAFETY: a place read of the `wDataLength` field of a node meeting
        // the walk contract: aligned, header initialized, readable, unwritten.
        let data_length = usize::from(unsafe { (*record).data_length });
        let data = record
            .cast::<u8>()
            .wrapping_add(std::mem::offset_of!(ffi::DnsRecord, data));
        let count_offset = std::mem::offset_of!(ffi::DNS_TXT_DATAW, string_count);
        let strings_offset = std::mem::offset_of!(ffi::DNS_TXT_DATAW, strings);
        let count_end = count_offset + std::mem::size_of::<u32>();
        if data_length < count_end {
            return Err(WindowsDnsResolverError::message(format!(
                "invalid TXT record data length: {data_length}",
            ))
            .into());
        }

        #[expect(
            clippy::cast_ptr_alignment,
            reason = "the node is aligned for `DnsRecord` and the SDK-checked offset keeps the count aligned for `u32`"
        )]
        let string_count = data.wrapping_add(count_offset).cast::<u32>();
        // SAFETY: `ptr::read`: the count lies within the node's `wDataLength`
        // data bytes (checked above), which the walk contract makes
        // initialized and readable; the node is aligned for `DnsRecord`, and
        // the SDK-checked offsets keep the field aligned for `u32`.
        let string_count = unsafe { string_count.read() } as usize;
        if string_count == 0 {
            return Err(WindowsDnsResolverError::message(
                "TXT record must contain at least one string",
            )
            .into());
        }
        let pointers_length = string_count
            .checked_mul(std::mem::size_of::<*const u16>())
            .and_then(|length| strings_offset.checked_add(length))
            .ok_or_else(|| WindowsDnsResolverError::message("TXT string array length overflow"))?;
        if pointers_length > data_length {
            return Err(WindowsDnsResolverError::message(format!(
                "invalid TXT string array: count={string_count} data_length={data_length}",
            ))
            .into());
        }

        #[expect(
            clippy::cast_ptr_alignment,
            reason = "the node is aligned for `DnsRecord` and the SDK-checked offset keeps the array pointer-aligned"
        )]
        let strings = data.wrapping_add(strings_offset).cast::<*const u16>();
        for idx in 0..string_count {
            // SAFETY: `ptr::read`: entry `idx` lies within the data bytes
            // validated above, initialized and readable per the walk contract,
            // and the SDK-checked offset keeps it pointer-aligned.
            let string = unsafe { strings.wrapping_add(idx).read() };
            if string.is_null() {
                return Err(WindowsDnsResolverError::message(format!(
                    "TXT string pointer {idx} is null",
                ))
                .into());
            }
        }

        // Validate every pointer before decoding so a malformed later entry
        // cannot emit a partial record. Decode one string at a time into the
        // common buffer instead of retaining an intermediate `Vec<String>`.
        let values = (0..string_count).map(|idx| {
            // SAFETY: as in the validation pass above.
            let string = unsafe { strings.wrapping_add(idx).read() };
            // SAFETY: the walk contract makes each of the `dwStringCount`
            // TXT string pointers null or an aligned NUL-terminated UTF-16
            // string, readable and unwritten during the walk.
            unsafe { wide_ptr_to_string(string) }
        });
        emit(Txt::try_from_strings(values)?);
        Ok(())
    };
    // SAFETY: the walk contract is this function's own.
    unsafe { walk_record_pointers(records, ffi::DNS_TYPE_TEXT, visit) }
}

/// [`RecordParser`] for SVCB records.
///
/// # Safety
///
/// See [`RecordParser`].
unsafe fn parse_svcb_records(
    records: *const ffi::DnsRecord,
    emit: &mut dyn FnMut(ServiceBinding),
) -> Result<(), BoxError> {
    // SAFETY: the walk contract is this function's own.
    unsafe { parse_service_binding_records(records, RecordType::SVCB, emit) }
}

/// [`RecordParser`] for HTTPS records.
///
/// # Safety
///
/// See [`RecordParser`].
unsafe fn parse_https_records(
    records: *const ffi::DnsRecord,
    emit: &mut dyn FnMut(ServiceBinding),
) -> Result<(), BoxError> {
    // SAFETY: the walk contract is this function's own.
    unsafe { parse_service_binding_records(records, RecordType::HTTPS, emit) }
}

/// Parse the flat RDATA of the `expected_type` records in `records`.
///
/// # Safety
///
/// The caller must ensure the [`walk_record_pointers`] contract for `records`.
unsafe fn parse_service_binding_records(
    records: *const ffi::DnsRecord,
    expected_type: RecordType,
    emit: &mut dyn FnMut(ServiceBinding),
) -> Result<(), BoxError> {
    let visit = |record: *const ffi::DnsRecord| {
        // DNS_QUERY_REQUEST_VERSION1 cannot request
        // DNS_QUERY_PARSE_ALL_RECORDS. Microsoft therefore guarantees
        // SVCB and HTTPS are returned in backward-compatible flat form:
        // `data_length` octets of original RDATA begin at `data`.
        // <https://learn.microsoft.com/en-us/windows/win32/dns/dns-constants#dns-query-options>
        // SAFETY: a place read of the `wDataLength` field of a node meeting
        // the walk contract: aligned, header initialized, readable, unwritten.
        let rdata_len = usize::from(unsafe { (*record).data_length });
        let rdata = record
            .cast::<u8>()
            .wrapping_add(std::mem::offset_of!(ffi::DnsRecord, data));
        // SAFETY: `slice::from_raw_parts`: `rdata` is non-null and aligned
        // for `u8`, and its `rdata_len` bytes are the node's data bytes, which
        // the walk contract makes initialized, readable, within the node's
        // allocation (whose provenance `wrapping_add` kept) and unwritten
        // while the walk runs, which outlasts the slice. `rdata_len` is a
        // `u16`, far below `isize::MAX`.
        let rdata = unsafe { std::slice::from_raw_parts(rdata, rdata_len) };
        emit(ServiceBinding::parse_rdata(rdata)?);
        Ok(())
    };
    // SAFETY: the walk contract is this function's own.
    unsafe { walk_record_pointers(records, expected_type.into(), visit) }
}

/// Visit every node of type `rrtype` in a `DNS_RECORDW` list, in list order,
/// stopping at the first error.
///
/// # Safety
///
/// The caller must ensure that `record` is null or the head of a finite list
/// of `DNS_RECORDW` nodes in which, for the duration of the call, every node
/// reachable through `pNext`:
/// - is aligned for [`ffi::DnsRecord`], and its first
///   `offset_of!(DnsRecord, data) + wDataLength` bytes are initialized,
///   readable, within one allocation and not written by anything;
/// - has a `pNext` that is null or the next such node;
/// - if it is a CNAME node, has a `pNameHost`, and if it is a TXT node, has
///   `dwStringCount` string pointers, each of which is null or points to an
///   aligned, NUL-terminated UTF-16 string that is initialized, readable,
///   within one allocation and not written by anything.
///
/// `visit` then receives exactly the nodes of type `rrtype` outside the
/// authority and additional sections, each meeting these conditions.
unsafe fn walk_record_pointers<F>(
    mut record: *const ffi::DnsRecord,
    rrtype: u16,
    mut visit: F,
) -> Result<(), BoxError>
where
    F: FnMut(*const ffi::DnsRecord) -> Result<(), BoxError>,
{
    while !record.is_null() {
        // SAFETY: a place read of the `wType` field: by this function's
        // contract the non-null `record` is an aligned node whose header is
        // initialized, readable and unwritten. No reference is made.
        let record_type = unsafe { (*record).record_type };
        // SAFETY: as above, for the `pNext` field.
        let next = unsafe { (*record).next };
        // SAFETY: as above, for the `Flags` field.
        let section = unsafe { (*record).flags } & ffi::DNSREC_SECTION;
        // local answers (hosts file, own name) come in the question section
        let answer = section == ffi::DNSREC_ANSWER || section == ffi::DNSREC_QUESTION;
        if record_type == rrtype && answer {
            visit(record)?;
        }
        record = next.cast_const();
    }
    Ok(())
}

/// Decode a NUL-terminated UTF-16 string, replacing invalid code units.
///
/// # Safety
///
/// The caller must ensure that `ptr` is null, or aligned for `u16` and points
/// to `u16` units up to and including a 0 unit, all initialized, readable,
/// within one allocation and not written by anything during the call.
unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }

    let mut len = 0;
    // SAFETY: `ptr::read`: units `0..len` are not 0, so by the contract unit
    // `len` is at most the terminating 0 unit: aligned, initialized, readable
    // and within the allocation `ptr` points into.
    while unsafe { ptr.wrapping_add(len).read() } != 0 {
        len += 1;
    }
    // SAFETY: `slice::from_raw_parts`: `ptr` is non-null (checked) and
    // aligned, and the `len` units before the terminator are initialized,
    // readable and within one allocation, so `len * 2 <= isize::MAX`. Nothing
    // writes them while the slice lives, which ends with this call.
    let units = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(units)
}

struct QueryState<T> {
    queue: Mutex<VecDeque<Result<T, BoxError>>>,
    done: AtomicBool,
    timeout: Duration,
    timed_out: AtomicBool,
    suppress_results: AtomicBool,
    cancel_requested: AtomicBool,
    notify: Notify,
    inflight: Mutex<Option<InFlightBox>>,
    parser: RecordParser<T>,
    backend: DnsBackend,
}

struct QueryCancelGuard<T> {
    state: Arc<QueryState<T>>,
}

impl<T> Drop for QueryCancelGuard<T> {
    fn drop(&mut self) {
        if self.state.done.load(Ordering::SeqCst) {
            return;
        }

        request_cancel(&self.state);
        self.state.suppress_results.store(true, Ordering::SeqCst);
    }
}

/// The request, result and cancel handle of one query, kept at a stable
/// address for dnsapi.
struct InFlightQuery {
    // Safety invariant: a version-1 request whose `QueryName` points to the
    // buffer of `name`.
    request: ffi::DNS_QUERY_REQUEST,
    // Safety invariant: `pQueryRecords` is null or the head of the record
    // list `backend` returned for this query, not freed yet and owned by this
    // value.
    result: ffi::DNS_QUERY_RESULT,
    cancel: ffi::DNS_QUERY_CANCEL,
    // Safety invariant: NUL-terminated and never modified.
    name: Vec<u16>,
    backend: DnsBackend,
}

impl InFlightQuery {
    /// # Safety-usable invariant
    ///
    /// Returns a version-1 `DnsQueryEx` request for `rrtype` with `callback`
    /// and `context`, whose `QueryName` points to the returned `name`, which
    /// ends in a 0 unit; a version-1 result with all other members null or 0;
    /// and a zeroed cancel handle.
    fn new(
        mut name: Vec<u16>,
        rrtype: u16,
        context: *mut c_void,
        callback: unsafe extern "system" fn(*const c_void, *mut ffi::DNS_QUERY_RESULT),
        backend: DnsBackend,
    ) -> Self {
        if name.last() != Some(&0) {
            name.push(0);
        }
        let request = ffi::DNS_QUERY_REQUEST {
            Version: ffi::DNS_QUERY_REQUEST_VERSION1,
            QueryName: ptr::null(),
            QueryType: rrtype,
            QueryOptions: u64::from(ffi::DNS_QUERY_STANDARD),
            pDnsServerList: ptr::null_mut(),
            InterfaceIndex: 0,
            pQueryCompletionCallback: Some(callback),
            pQueryContext: context,
        };

        let result = ffi::DNS_QUERY_RESULT {
            Version: ffi::DNS_QUERY_RESULTS_VERSION1,
            QueryStatus: 0,
            QueryOptions: 0,
            pQueryRecords: ptr::null_mut(),
            Reserved: ptr::null_mut(),
        };

        let mut query = Self {
            request,
            result,
            cancel: ffi::DNS_QUERY_CANCEL { Reserved: [0; 32] },
            name,
            backend,
        };
        // Moving `query` keeps the heap buffer of `name` in place.
        query.request.QueryName = query.name.as_ptr();
        query
    }
}

impl Drop for InFlightQuery {
    fn drop(&mut self) {
        // SAFETY: the `cleanup_result` contract is the field invariant of
        // `result`; the value is being dropped, so nothing uses the list after.
        unsafe { cleanup_result(&self.backend, &mut self.result) };
        #[cfg(test)]
        self.backend.note_block_dropped();
    }
}

/// Owns a boxed [`InFlightQuery`] whose fields dnsapi uses through raw
/// pointers, so no `Box` asserts unique access while the query is pending.
struct InFlightBox(
    // Safety invariant: comes from leaking a `Box<InFlightQuery>`, owned by
    // this value; no reference to the whole block exists. The query it holds
    // was started and returned `DNS_REQUEST_PENDING`, so dnsapi may use its
    // request, result and cancel handle until the completion callback is
    // invoked (DnsQueryEx docs: "should not free this structure until the
    // DNS_QUERY_COMPLETION_ROUTINE callback is invoked"), and the cancel
    // handle until any `DnsCancelQuery` with it returned. The `QueryState`
    // owning this value drops only after both: the callback holds the context
    // `Arc`, and `request_cancel` runs on a borrowed `Arc`. The last `Arc`
    // may drop inside the callback, after its last use of the result.
    NonNull<InFlightQuery>,
);

impl InFlightBox {
    fn cancel_handle(&self) -> *mut ffi::DNS_QUERY_CANCEL {
        // SAFETY: the field invariant makes the pointer aligned and live, so
        // the field projection stays in bounds. No reference is made.
        unsafe { &raw mut (*self.0.as_ptr()).cancel }
    }
}

impl Drop for InFlightBox {
    fn drop(&mut self) {
        // SAFETY: `Box::from_raw`: by the field invariant the pointer comes
        // from a leaked `Box<InFlightQuery>` owned by this value, which drops
        // once. The owning `QueryState` is dropping, so the callback was
        // invoked and no `DnsCancelQuery` runs (the field invariant), and
        // dnsapi no longer uses the block.
        drop(unsafe { Box::from_raw(self.0.as_ptr()) });
    }
}

// SAFETY: `InFlightBox` uniquely owns its block. The raw pointers inside are
// `request.QueryName` into its own `name`, `request.pQueryContext` (an
// `Arc<QueryState<T>>` reference that only the callback reconstructs, and the
// state is `Send + Sync`), and `result.pQueryRecords`, a record list that
// `DnsFree` frees: completion callbacks run on dnsapi's own threads and the
// docs have the application free their records, so the list is not tied to a
// thread. dnsapi itself uses the block from its own threads.
unsafe impl Send for InFlightBox {}

/// Completion routine handed to `DnsQueryEx` by [`start_query`].
///
/// # Safety
///
/// The caller (dnsapi) must ensure that:
/// - `query_context` is the `pQueryContext` of a pending query, the result of
///   `Arc::into_raw` of an `Arc<QueryState<T>>`, whose strong count this call
///   takes over; it runs at most once per query;
/// - `query_result` is null, or the `DNS_QUERY_RESULT` passed to that
///   `DnsQueryEx` call, holding the finished outcome as
///   [`handle_query_result`] requires, and nothing else accesses it during the
///   call.
unsafe extern "system" fn query_completion_callback<T>(
    query_context: *const c_void,
    query_result: *mut ffi::DNS_QUERY_RESULT,
) where
    T: fmt::Debug + Send + 'static,
{
    if query_context.is_null() {
        return;
    }

    // SAFETY: `Arc::from_raw`: by this function's contract the context came
    // from `Arc::into_raw` of an `Arc<QueryState<T>>` and its strong count is
    // reclaimed here once.
    let state = unsafe { Arc::from_raw(query_context.cast::<QueryState<T>>()) };

    if query_result.is_null() {
        state
            .queue
            .lock()
            .push_back(Err(WindowsDnsResolverError::message(
                "DnsQueryEx callback received null result",
            )
            .into()));
        mark_done(&state);
        return;
    }

    // SAFETY: reference creation: by this function's contract the non-null
    // `query_result` is the `result` field of the query's `InFlightQuery`,
    // aligned and initialized, and nothing else accesses it during the call.
    // The block stays allocated while `result` is used: it is freed only with
    // `state`, held here until the end of this call.
    let result = unsafe { &mut *query_result };
    let call_status = result.QueryStatus;
    // SAFETY: the `handle_query_result` contract is this function's own.
    unsafe { handle_query_result(&state, result, call_status) };
}

#[cfg(test)]
struct FakePendingQuery {
    callback: ffi::PDNS_QUERY_COMPLETION_ROUTINE,
    context: usize,
    result: usize,
}

/// How [`FakeDnsBackend`] answers a query.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum FakeMode {
    /// Pending; `cancel` completes it as cancelled on a thread of its own.
    CancelOnThread,
    /// Pending; `cancel` only records the request.
    DeferCancel,
    /// Answers synchronously with records.
    AnswerSync,
    /// Answers synchronously with NXDOMAIN.
    NameErrorSync,
    /// Invokes the callback with records inside `query`, then returns pending.
    AnswerInsideQuery,
    /// Pending; `cancel` first completes it with records, then reads the handle.
    AnswerBeforeCancel,
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum FakeAnswer {
    Cancelled,
    Records,
}

/// Written into the cancel handle by `query`, checked by `cancel`.
#[cfg(test)]
const FAKE_CANCEL_TAG: i8 = 0x5a;

#[cfg(test)]
struct FakeDnsBackend {
    mode: FakeMode,
    // Safety invariant: `Some` only with a query recorded by
    // `FakeDnsBackend::query`, whose callback was not invoked yet.
    pending: Mutex<Option<FakePendingQuery>>,
    started: Notify,
    cancel_requested: Notify,
    cancel_called: AtomicBool,
    callback_completed_during_cancel: AtomicBool,
    wait_loop_iterations: AtomicUsize,
    queries: AtomicUsize,
    query_type: AtomicU16,
    callback_threads: Mutex<Vec<std::thread::JoinHandle<()>>>,
    /// Address of the cancel handle of the last pending query.
    query_cancel_handle: AtomicUsize,
    /// Address of the handle of each `cancel` call.
    cancel_handles: Mutex<Vec<usize>>,
    callbacks: AtomicUsize,
    /// Heads of the record lists handed out and not freed yet.
    live_lists: Mutex<Vec<usize>>,
    lists_freed: AtomicUsize,
    blocks_dropped: AtomicUsize,
}

#[cfg(test)]
impl FakeDnsBackend {
    fn new() -> Self {
        Self::with_mode(FakeMode::CancelOnThread)
    }

    fn with_mode(mode: FakeMode) -> Self {
        Self {
            mode,
            pending: Mutex::new(None),
            started: Notify::new(),
            cancel_requested: Notify::new(),
            cancel_called: AtomicBool::new(false),
            callback_completed_during_cancel: AtomicBool::new(false),
            wait_loop_iterations: AtomicUsize::new(0),
            queries: AtomicUsize::new(0),
            query_type: AtomicU16::new(0),
            callback_threads: Mutex::new(Vec::new()),
            query_cancel_handle: AtomicUsize::new(0),
            cancel_handles: Mutex::new(Vec::new()),
            callbacks: AtomicUsize::new(0),
            live_lists: Mutex::new(Vec::new()),
            lists_freed: AtomicUsize::new(0),
            blocks_dropped: AtomicUsize::new(0),
        }
    }

    /// Start a query as [`FakeMode`] says. A pending query is completed by
    /// [`Self::cancel`] or [`Self::fire_pending_callback`].
    ///
    /// # Safety
    ///
    /// The caller must meet the [`DnsBackend::query`] contract.
    unsafe fn query(
        &self,
        request: *const ffi::DNS_QUERY_REQUEST,
        result: *mut ffi::DNS_QUERY_RESULT,
        cancel: *mut ffi::DNS_QUERY_CANCEL,
    ) -> i32 {
        // SAFETY: reference creation: the `DnsBackend::query` contract makes
        // `request` an aligned, initialized request that nothing writes.
        let request = unsafe { &*request };
        self.queries.fetch_add(1, Ordering::SeqCst);
        self.query_type.store(request.QueryType, Ordering::SeqCst);

        if self.mode == FakeMode::NameErrorSync {
            // SAFETY: a place write: the contract makes `result` an aligned,
            // writable result; a synchronous answer keeps no pointer to it.
            unsafe { (*result).QueryStatus = ffi::DNS_ERROR_RCODE_NAME_ERROR };
            return ffi::DNS_ERROR_RCODE_NAME_ERROR;
        }

        if self.mode == FakeMode::AnswerSync {
            // SAFETY: a place write: the contract makes `result` an aligned,
            // writable result; a synchronous answer keeps no pointer to it.
            unsafe { (*result).QueryStatus = ffi::ERROR_SUCCESS };
            // SAFETY: as above.
            unsafe { (*result).pQueryRecords = self.answer().cast() };
            return ffi::ERROR_SUCCESS;
        }

        // SAFETY: `ptr::write`: the contract makes `cancel` an aligned,
        // writable handle, which dnsapi fills for a pending query.
        unsafe {
            cancel.write(ffi::DNS_QUERY_CANCEL {
                Reserved: [FAKE_CANCEL_TAG; 32],
            })
        };
        self.query_cancel_handle
            .store(cancel.addr(), Ordering::SeqCst);
        // This returns pending, so the contract keeps the result and context
        // valid until the callback is invoked.
        let pending = FakePendingQuery {
            callback: request.pQueryCompletionCallback,
            context: request.pQueryContext as usize,
            result: result as usize,
        };
        if self.mode == FakeMode::AnswerInsideQuery {
            // SAFETY: the `complete` contract: this query returns pending
            // below and its callback was not invoked.
            unsafe { self.complete(&pending, FakeAnswer::Records) };
        } else {
            // Safety invariant of `pending`: as above.
            *self.pending.lock() = Some(pending);
        }
        self.started.notify_one();
        ffi::DNS_REQUEST_PENDING
    }

    /// Record a cancel request; [`FakeMode`] decides how the query completes.
    ///
    /// # Safety
    ///
    /// The caller must meet the [`DnsBackend::cancel`] contract.
    unsafe fn cancel(&self, cancel: *mut ffi::DNS_QUERY_CANCEL) {
        if self.mode == FakeMode::AnswerBeforeCancel {
            // the race `DnsCancelQuery` allows: the callback already finished
            self.fire_pending_callback(FakeAnswer::Records);
        }
        // SAFETY: a place read: the contract keeps the handle allocated until
        // this call returns, and only `query` wrote it.
        let tag = unsafe { (*cancel).Reserved[0] };
        assert_eq!(
            tag, FAKE_CANCEL_TAG,
            "cancel handle not filled by its query"
        );
        self.cancel_handles.lock().push(cancel.addr());
        self.cancel_called.store(true, Ordering::SeqCst);
        self.cancel_requested.notify_one();
        if self.mode != FakeMode::CancelOnThread {
            return;
        }

        let pending = self
            .pending
            .lock()
            .take()
            .expect("fake cancellation requires a pending query");
        self.callbacks.fetch_add(1, Ordering::SeqCst);
        let (done_tx, done_rx) = std::sync::mpsc::channel();

        let callback_thread = std::thread::spawn(move || {
            // SAFETY: the `invoke_fake_callback` contract: the field invariant
            // of `pending`, from which this query was just taken, and no list.
            unsafe { invoke_fake_callback(&pending, ffi::ERROR_CANCELLED, ptr::null_mut()) };
            _ = done_tx.send(());
        });

        let completed = done_rx.recv_timeout(Duration::from_secs(2)).is_ok();
        self.callback_completed_during_cancel
            .store(completed, Ordering::SeqCst);
        self.callback_threads.lock().push(callback_thread);
    }

    /// Complete the pending query with `answer` on this thread.
    fn fire_pending_callback(&self, answer: FakeAnswer) {
        let pending = self
            .pending
            .lock()
            .take()
            .expect("firing the fake callback requires a pending query");
        // SAFETY: the `complete` contract is the field invariant of `pending`,
        // from which this query was just taken.
        unsafe { self.complete(&pending, answer) };
    }

    /// Complete `pending` with `answer`, invoking its callback on this thread.
    ///
    /// # Safety
    ///
    /// The caller must ensure that [`Self::query`] started `pending` and
    /// returns or returned [`ffi::DNS_REQUEST_PENDING`] for it, and that its
    /// callback was not invoked yet.
    unsafe fn complete(&self, pending: &FakePendingQuery, answer: FakeAnswer) {
        let (status, records) = match answer {
            FakeAnswer::Cancelled => (ffi::ERROR_CANCELLED, ptr::null_mut()),
            FakeAnswer::Records => (ffi::ERROR_SUCCESS, self.answer()),
        };
        self.callbacks.fetch_add(1, Ordering::SeqCst);
        // SAFETY: the `invoke_fake_callback` contract: `pending` as this
        // function's contract says, and a fresh list from `answer`.
        unsafe { invoke_fake_callback(pending, status, records) };
    }

    /// A fresh record list, owned by the caller until [`Self::free`] takes it.
    fn answer(&self) -> *mut ffi::DnsRecord {
        let head = tests::alloc_answer();
        self.live_lists.lock().push(head.addr());
        head
    }

    /// `DnsFree` of a list from [`Self::answer`].
    ///
    /// # Safety
    ///
    /// The caller must meet the [`DnsBackend::free_records`] contract.
    unsafe fn free(&self, records: *mut ffi::DNS_RECORDA) {
        let mut live = self.live_lists.lock();
        let idx = live
            .iter()
            .position(|&head| head == records.addr())
            .expect("DnsFree of a record list not handed out, or freed twice");
        live.swap_remove(idx);
        drop(live);
        self.lists_freed.fetch_add(1, Ordering::SeqCst);
        // SAFETY: the `free_answer` contract: the contract makes `records` a
        // list from `answer`, still in `live_lists` until now so not freed,
        // and unused after this call.
        unsafe { tests::free_answer(records.cast()) };
    }

    fn join_callback_threads(&self) {
        for thread in self.callback_threads.lock().drain(..) {
            thread.join().expect("fake DNS callback thread panicked");
        }
    }
}

/// Complete a recorded query with `status` and `records`.
///
/// # Safety
///
/// The caller must ensure that [`FakeDnsBackend::query`] started `pending`
/// and returns or returned [`ffi::DNS_REQUEST_PENDING`] for it, that its
/// callback was not invoked before, and that `records` is null or a list from
/// [`FakeDnsBackend::answer`] that nothing else owns.
#[cfg(test)]
unsafe fn invoke_fake_callback(
    pending: &FakePendingQuery,
    status: i32,
    records: *mut ffi::DnsRecord,
) {
    let result = pending.result as *mut ffi::DNS_QUERY_RESULT;
    // SAFETY: a place write: by the contract `result` is the pending query's
    // result, aligned and live until its callback was invoked, which happens
    // only below; nothing else accesses it until then.
    unsafe { (*result).QueryStatus = status };
    // SAFETY: as above.
    unsafe { (*result).pQueryRecords = records.cast() };
    let callback = pending.callback.expect("pending query requires a callback");
    // SAFETY: the `query_completion_callback` contract: the context and
    // result belong to the pending query recorded with this callback, whose
    // context strong count is handed over once, here. The result holds the
    // finished outcome: `status` and a list of `DNS_RECORDW`-shaped nodes the
    // fake's `free` takes.
    unsafe { callback(pending.context as *const c_void, result) };
}

#[derive(Debug)]
struct WindowsDnsResolverError(ArcStr);

impl WindowsDnsResolverError {
    fn message(message: impl Into<ArcStr>) -> Self {
        Self(message.into())
    }

    fn dns_status(operation: &str, status: i32) -> Self {
        Self::message(format!("{operation} failed with DNS status {status}"))
    }
}

impl fmt::Display for WindowsDnsResolverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WindowsDnsResolverError {}

/// Reads this computer's names and unicast addresses from the OS.
mod local_host {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        ptr::{self, NonNull},
        sync::Arc,
        time::{Duration, Instant},
    };

    use parking_lot::Mutex;
    use rama_core::{
        error::{BoxError, BoxErrorExt as _, ErrorExt as _},
        telemetry::tracing,
    };

    use super::{UnicastAddress, ffi};

    /// The names a queried name is compared with.
    const NAME_FORMATS: [ffi::COMPUTER_NAME_FORMAT; 3] = [
        ffi::ComputerNameDnsHostname,
        ffi::ComputerNameDnsFullyQualified,
        ffi::ComputerNameNetBIOS,
    ];

    /// How long [`cached_computer_names`] reuses names: they change only at
    /// restart (SetComputerNameExW docs), and a failed read is retried.
    const NAMES_TTL: Duration = Duration::from_secs(5);

    static NAMES: Mutex<Option<(Instant, Arc<[Box<str>]>)>> = Mutex::new(None);

    /// [`computer_names`], read again once older than [`NAMES_TTL`].
    pub(super) fn cached_computer_names() -> Arc<[Box<str>]> {
        let mut cached = NAMES.lock();
        if let Some((read_at, names)) = &*cached
            && read_at.elapsed() < NAMES_TTL
        {
            return names.clone();
        }
        let names: Arc<[Box<str>]> = computer_names().into();
        *cached = Some((Instant::now(), names.clone()));
        names
    }

    /// The non-empty names of [`NAME_FORMATS`], in that order.
    pub(super) fn computer_names() -> Vec<Box<str>> {
        NAME_FORMATS.into_iter().filter_map(computer_name).collect()
    }

    /// The computer's name in `format`; `None` if empty or unreadable.
    pub(super) fn computer_name(format: ffi::COMPUTER_NAME_FORMAT) -> Option<Box<str>> {
        let mut size = 0_u32;
        // SAFETY: with a null `lpBuffer`, `GetComputerNameExW` needs `nSize`
        // to be zero ("If lpBuffer is NULL, this parameter must be zero") and
        // writes the required size through it; `size` is a writable local.
        let ok = unsafe { ffi::GetComputerNameExW(format, ptr::null_mut(), &raw mut size) };
        if ok != 0 || size == 0 {
            // nothing to copy: an empty name
            return None;
        }

        let mut buffer = vec![0_u16; usize::try_from(size).ok()?];
        let mut len = size;
        // SAFETY: `GetComputerNameExW` writes at most `nSize` UTF-16 units,
        // NUL included, to `lpBuffer`; `buffer` holds exactly `len` units and
        // `len` is a writable local.
        let ok = unsafe { ffi::GetComputerNameExW(format, buffer.as_mut_ptr(), &raw mut len) };
        if ok == 0 {
            tracing::debug!(
                format,
                error = %std::io::Error::last_os_error(),
                "dns::windows: computer name unavailable",
            );
            return None;
        }
        // on success `nSize` is the units copied, NUL excluded
        let name = buffer.get(..usize::try_from(len).ok()?)?;
        (!name.is_empty()).then(|| String::from_utf16_lossy(name).into_boxed_str())
    }

    /// Every IPv4 and IPv6 row of the unicast address table, in table order.
    pub(super) fn unicast_addresses() -> Result<Vec<UnicastAddress>, BoxError> {
        let Some(table) = UnicastTable::read()? else {
            return Ok(Vec::new());
        };
        // SAFETY: the `table_rows` contract is the field invariant of
        // `UnicastTable`; `table` lives, unfreed, until the end of this call.
        Ok(unsafe { table_rows(table.0.as_ptr()) })
    }

    /// A table from `GetUnicastIpAddressTable`, freed with `FreeMibTable` on
    /// drop.
    struct UnicastTable(
        // Safety invariant: the table a `GetUnicastIpAddressTable` call that
        // returned `NO_ERROR` wrote, owned by this value and not freed yet.
        // Per the API docs it is a `NumEntries` count followed by that many
        // initialized rows, which nothing else writes.
        NonNull<ffi::MIB_UNICASTIPADDRESS_TABLE>,
    );

    impl UnicastTable {
        /// The current table; `None` if the computer has no unicast address.
        fn read() -> Result<Option<Self>, BoxError> {
            let mut table = ptr::null_mut();
            // SAFETY: `GetUnicastIpAddressTable` needs a supported family
            // (`AF_UNSPEC` is one) and a writable table pointer, here a local.
            let status = unsafe { ffi::GetUnicastIpAddressTable(ffi::AF_UNSPEC, &raw mut table) };
            match status {
                // field invariant of `UnicastTable`: a `NO_ERROR` table, owned here
                ffi::NO_ERROR => NonNull::new(table).map(Self).map(Some).ok_or_else(|| {
                    BoxError::from_static_str("GetUnicastIpAddressTable returned no table")
                }),
                ffi::ERROR_NOT_FOUND => Ok(None),
                status => Err(BoxError::from_static_str("GetUnicastIpAddressTable failed")
                    .context_field("status", status)),
            }
        }
    }

    impl Drop for UnicastTable {
        fn drop(&mut self) {
            // SAFETY: `FreeMibTable` frees the buffer `GetUnicastIpAddressTable`
            // returned (both API docs); the field invariant makes this pointer
            // that buffer, unfreed, and this drop runs once.
            unsafe { ffi::FreeMibTable(self.0.as_ptr().cast_const().cast()) };
        }
    }

    /// The IPv4 and IPv6 rows of a unicast address table, in table order.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `table` is aligned and points to a
    /// `NumEntries` count followed by that many `MIB_UNICASTIPADDRESS_ROW`s
    /// laid out as the `Table` array of [`ffi::MIB_UNICASTIPADDRESS_TABLE`],
    /// all within one allocation, initialized, readable and not written
    /// during the call.
    pub(super) unsafe fn table_rows(
        table: *const ffi::MIB_UNICASTIPADDRESS_TABLE,
    ) -> Vec<UnicastAddress> {
        // SAFETY: a place read of `NumEntries` of the aligned, initialized
        // table (this function's contract). No reference is made.
        let count = unsafe { (*table).NumEntries };
        // SAFETY: a field projection within the live table (this function's
        // contract); the raw pointer keeps the provenance of `table`.
        let rows = unsafe { &raw const (*table).Table }.cast::<ffi::MIB_UNICASTIPADDRESS_ROW>();
        (0..count)
            .filter_map(|idx| {
                // `idx < NumEntries`: the row lies in the table
                let row = rows.wrapping_add(idx as usize);
                // SAFETY: the `unicast_address` contract: row `idx` is one of
                // the table's `NumEntries` initialized rows, aligned as an
                // array element and not written (this function's contract).
                unsafe { unicast_address(row) }
            })
            .collect()
    }

    /// The address, `SkipAsSource` and DAD state of `row`; `None` for a
    /// family other than IPv4 and IPv6.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `row` is aligned and points to an
    /// initialized, readable `MIB_UNICASTIPADDRESS_ROW` that nothing writes
    /// during the call.
    unsafe fn unicast_address(row: *const ffi::MIB_UNICASTIPADDRESS_ROW) -> Option<UnicastAddress> {
        // SAFETY: a field projection within the live row (this function's
        // contract). No reference is made.
        let address = unsafe { &raw const (*row).Address };
        // SAFETY: `ptr::read` of an aligned, initialized `SOCKADDR_INET`
        // (this function's contract); a union has no validity requirement.
        let address = unsafe { address.read() };
        // SAFETY: a union field read: every member starts with the family,
        // and any initialized `u16` is valid.
        let family = unsafe { address.si_family };
        let ip = match family {
            ffi::AF_INET => {
                // SAFETY: a union field read: the family says the union holds
                // a `SOCKADDR_IN`, whose integer fields are initialized.
                let v4 = unsafe { address.Ipv4 };
                // SAFETY: a union field read of the 4 initialized address
                // bytes; any of them form a valid `u32`.
                let raw = unsafe { v4.sin_addr.S_un.S_addr };
                // `S_addr` holds the address in network order
                IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes()))
            }
            ffi::AF_INET6 => {
                // SAFETY: a union field read: the family says the union holds
                // a `SOCKADDR_IN6`, whose integer fields are initialized.
                let v6 = unsafe { address.Ipv6 };
                // SAFETY: a union field read of the 16 initialized address
                // bytes; any of them form a valid `[u8; 16]`.
                IpAddr::V6(Ipv6Addr::from(unsafe { v6.sin6_addr.u.Byte }))
            }
            _ => return None,
        };
        // SAFETY: a field projection within the live row, as above.
        let skip_as_source = unsafe { &raw const (*row).SkipAsSource }.cast::<u8>();
        // SAFETY: `ptr::read` of one initialized byte of the row. The C type
        // is `BOOLEAN`, a `UCHAR`: read it as `u8` rather than assume the
        // `bool` windows-sys declares holds 0 or 1.
        let skip_as_source = unsafe { skip_as_source.read() } != 0;
        // SAFETY: a place read of the `DadState` integer of the aligned,
        // initialized row. No reference is made.
        let dad_state = unsafe { (*row).DadState };
        Some(UnicastAddress {
            ip,
            skip_as_source,
            dad_state,
        })
    }
}

mod ffi {
    // Official docs index for DNS structures and functions:
    // <https://learn.microsoft.com/en-us/windows/win32/dns/dns-structures>
    // <https://learn.microsoft.com/en-us/windows/win32/api/windns/>

    pub(super) use windows_sys::Win32::{
        Foundation::{DNS_INFO_NO_RECORDS, DNS_REQUEST_PENDING, ERROR_NOT_FOUND, NO_ERROR},
        NetworkManagement::Dns::{
            DNS_QUERY_CANCEL, DNS_QUERY_REQUEST, DNS_QUERY_REQUEST_VERSION1, DNS_QUERY_RESULT,
            DNS_QUERY_RESULTS_VERSION1, DNS_QUERY_STANDARD, DNS_RECORDA, DNS_TYPE_A, DNS_TYPE_AAAA,
            DNS_TYPE_CNAME, DNS_TYPE_TEXT, DNSREC_ANSWER, DNSREC_QUESTION, DNSREC_SECTION,
            DnsCancelQuery, DnsFree, DnsFreeRecordList, DnsQueryEx,
        },
        NetworkManagement::IpHelper::{
            FreeMibTable, GetUnicastIpAddressTable, MIB_UNICASTIPADDRESS_ROW,
            MIB_UNICASTIPADDRESS_TABLE,
        },
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, IpDadStatePreferred, NL_DAD_STATE},
        System::SystemInformation::{
            COMPUTER_NAME_FORMAT, ComputerNameDnsFullyQualified, ComputerNameDnsHostname,
            ComputerNameNetBIOS, GetComputerNameExW,
        },
    };

    #[cfg(test)]
    pub(super) use windows_sys::Win32::NetworkManagement::Dns::PDNS_QUERY_COMPLETION_ROUTINE;

    /// `DNS_STATUS` values, which windns.h types as `LONG`.
    pub(super) const ERROR_SUCCESS: i32 =
        windows_sys::Win32::Foundation::ERROR_SUCCESS.cast_signed();
    pub(super) const ERROR_CANCELLED: i32 =
        windows_sys::Win32::Foundation::ERROR_CANCELLED.cast_signed();
    pub(super) const DNS_ERROR_RCODE_NAME_ERROR: i32 =
        windows_sys::Win32::Foundation::DNS_ERROR_RCODE_NAME_ERROR.cast_signed();

    /// DNS_RECORDW:
    /// Official docs:
    /// <https://learn.microsoft.com/en-us/windows/win32/api/windnsdef/ns-windnsdef-dns_recordw>
    /// This backend only models the common header plus the RR union members it reads.
    #[repr(C)]
    pub(super) struct DnsRecord {
        /// A pointer to the next DNS_RECORD structure.
        pub(super) next: *mut Self,
        /// A pointer to a string that represents the domain name of the record set.
        /// This must be in the string format that corresponds to the function called,
        /// such as ANSI, Unicode, or UTF8.
        pub(super) name: *mut u16,
        /// A value that represents the RR DNS Record Type.
        /// wType determines the format of Data. For example,
        /// if the value of wType is DNS_TYPE_A, the data type of Data is DNS_A_DATA.
        pub(super) record_type: u16,
        /// The length, in bytes, of Data. For fixed-length data types,
        /// this value is the size of the corresponding data type,
        /// such as sizeof(DNS_A_DATA).
        pub(super) data_length: u16,
        /// One of:
        /// - A value that contains a bitmap of DNS Record Flags.
        /// - A set of flags in the form of a DNS_RECORD_FLAGS structure.
        pub(super) flags: u32,
        /// The DNS RR's Time To Live value (TTL), in seconds.
        pub(super) ttl: u32,
        /// Reserved. Do not use.
        pub(super) reserved: u32,
        /// The DNS RR data type is determined by wType. A record's
        /// allocation ends after `data_length` bytes of it, which may be
        /// fewer than this union holds: never read it as a whole.
        pub(super) data: DnsRecordData,
    }

    // Keep the hand-written projection pinned to windows-sys' SDK-derived
    // DNS_RECORDW header. Its Data union is intentionally a smaller subset,
    // so only alignment and every field offset through Data are comparable.
    const _: () = {
        use windows_sys::Win32::NetworkManagement::Dns::DNS_RECORDW;

        assert!(std::mem::align_of::<DnsRecord>() == std::mem::align_of::<DNS_RECORDW>());
        assert!(std::mem::offset_of!(DnsRecord, next) == std::mem::offset_of!(DNS_RECORDW, pNext));
        assert!(std::mem::offset_of!(DnsRecord, name) == std::mem::offset_of!(DNS_RECORDW, pName));
        assert!(
            std::mem::offset_of!(DnsRecord, record_type)
                == std::mem::offset_of!(DNS_RECORDW, wType)
        );
        assert!(
            std::mem::offset_of!(DnsRecord, data_length)
                == std::mem::offset_of!(DNS_RECORDW, wDataLength)
        );
        assert!(std::mem::offset_of!(DnsRecord, flags) == std::mem::offset_of!(DNS_RECORDW, Flags));
        assert!(std::mem::offset_of!(DnsRecord, ttl) == std::mem::offset_of!(DNS_RECORDW, dwTtl));
        assert!(
            std::mem::offset_of!(DnsRecord, reserved)
                == std::mem::offset_of!(DNS_RECORDW, dwReserved)
        );
        assert!(std::mem::offset_of!(DnsRecord, data) == std::mem::offset_of!(DNS_RECORDW, Data));
        // `DNS_QUERY_RESULT` types its list as `DNS_RECORDA`, the same header.
        assert!(
            std::mem::offset_of!(
                windows_sys::Win32::NetworkManagement::Dns::DNS_RECORDA,
                Data
            ) == std::mem::offset_of!(DNS_RECORDW, Data)
        );
    };

    /// DNS_RECORDW::Data union subset used by this backend.
    #[repr(C)]
    pub(super) union DnsRecordData {
        pub(super) a: DNS_A_DATA,
        pub(super) aaaa: DNS_AAAA_DATA,
        pub(super) ptr: DNS_PTR_DATAW,
        pub(super) txt: DNS_TXT_DATAW,
        #[cfg(test)]
        pub(super) flat: [u8; 16],
    }

    /// DNS_PTR_DATAW, also used for CNAME records.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) struct DNS_PTR_DATAW {
        /// Canonical target name as a NUL-terminated UTF-16 string.
        pub(super) name_host: *const u16,
    }

    /// DNS_A_DATA:
    /// Official docs:
    /// <https://learn.microsoft.com/en-us/windows/win32/api/windnsdef/ns-windnsdef-dns_a_data>
    ///
    /// ## Note
    ///
    /// The DNS_A_DATA structure is used in conjunction with the DNS_RECORD
    /// structure to programmatically manage DNS entries.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) struct DNS_A_DATA {
        /// An IP4_ADDRESS data type that contains an IPv4 address.
        pub(super) ip_address: u32,
    }

    /// DNS_AAAA_DATA:
    /// Official docs:
    /// <https://learn.microsoft.com/en-us/windows/win32/api/windnsdef/ns-windnsdef-dns_aaaa_data>
    ///
    /// ## Note
    ///
    /// The DNS_AAAA_DATA structure is used in conjunction with the DNS_RECORD
    /// structure to programmatically manage DNS entries.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) struct DNS_AAAA_DATA {
        /// An IP6_ADDRESS data type that contains an IPv6 address.
        pub(super) ip6_address: DNS_IP6_ADDRESS,
    }

    /// IP6_ADDRESS is part of the Windows DNS structure family documented from
    /// the DNS_AAAA_DATA page and the windnsdef.h structure index.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) struct DNS_IP6_ADDRESS {
        pub(super) ip6_byte: [u8; 16],
    }

    // The payload reads copy `size_of` bytes of these out of `Data`, so their
    // sizes and field offsets must be the SDK's. They are read unaligned.
    const _: () = {
        use windows_sys::Win32::NetworkManagement::Dns as sdk;

        assert!(std::mem::size_of::<DNS_A_DATA>() == std::mem::size_of::<sdk::DNS_A_DATA>());
        assert!(std::mem::size_of::<DNS_AAAA_DATA>() == std::mem::size_of::<sdk::DNS_AAAA_DATA>());
        assert!(std::mem::size_of::<DNS_PTR_DATAW>() == std::mem::size_of::<sdk::DNS_PTR_DATAW>());
        assert!(
            std::mem::offset_of!(DNS_PTR_DATAW, name_host)
                == std::mem::offset_of!(sdk::DNS_PTR_DATAW, pNameHost)
        );
    };

    /// DNS_TXT_DATAW:
    /// Official docs:
    /// <https://learn.microsoft.com/en-us/windows/win32/api/windnsdef/ns-windnsdef-dns_txt_dataw>
    ///
    /// Note
    /// <The DNS_TXT_DATA structure is used in conjunction with the DNS_RECORD
    /// structure to programmatically manage DNS entries.>
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) struct DNS_TXT_DATAW {
        /// The number of strings represented in pStringArray.
        pub(super) string_count: u32,
        /// An array of strings representing the descriptive text of the TXT resource record.
        /// Elements:
        /// - (0) An array of strings representing the descriptive text of the TXT resource record.
        pub(super) strings: [*const u16; 1],
    }

    const _: () = {
        use windows_sys::Win32::NetworkManagement::Dns::DNS_TXT_DATAW as SdkDnsTxtDataW;

        assert!(std::mem::align_of::<DNS_TXT_DATAW>() == std::mem::align_of::<SdkDnsTxtDataW>());
        assert!(
            std::mem::offset_of!(DNS_TXT_DATAW, string_count)
                == std::mem::offset_of!(SdkDnsTxtDataW, dwStringCount)
        );
        assert!(
            std::mem::offset_of!(DNS_TXT_DATAW, strings)
                == std::mem::offset_of!(SdkDnsTxtDataW, pStringArray)
        );
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::{
        error::BoxErrorExt as _,
        futures::{StreamExt, future::join_all, stream::BoxStream},
    };
    use std::{
        assert_matches,
        collections::BTreeSet,
        net::ToSocketAddrs as _,
        pin::pin,
        sync::atomic::AtomicUsize,
        task::{Context, Poll, Waker},
        time::{SystemTime, UNIX_EPOCH},
    };
    use windows_sys::Win32::{
        NetworkManagement::Dns::{DNSREC_ADDITIONAL, DNSREC_AUTHORITY},
        Networking::WinSock::{
            IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, IpDadStateDeprecated, IpDadStateTentative,
            SOCKADDR_IN, SOCKADDR_IN6,
        },
    };

    use crate::wire::SvcParam;

    #[test]
    fn windows_resolver_defaults_to_five_second_timeout() {
        assert_eq!(WindowsDnsResolver::new().timeout(), Duration::from_secs(5));
    }

    #[test]
    fn windows_resolver_timeout_is_configurable() {
        assert_eq!(
            WindowsDnsResolver::new()
                .with_timeout(Duration::from_millis(250))
                .timeout(),
            Duration::from_millis(250)
        );
    }

    #[test]
    fn dns_name_from_domain_strips_root_dot_and_nul_terminates() {
        let name = dns_name_from_domain("example.com.").unwrap();
        assert_eq!(name, "example.com\0".encode_utf16().collect::<Vec<u16>>());
    }

    #[test]
    fn dns_name_from_domain_rejects_interior_nul() {
        dns_name_from_domain("exa\0mple.com").unwrap_err();
    }

    /// A full-size node; fixed-size types get their payload length.
    fn record(rrtype: u16, data: ffi::DnsRecordData, next: *mut ffi::DnsRecord) -> ffi::DnsRecord {
        let data_length = match rrtype {
            ffi::DNS_TYPE_A => std::mem::size_of::<ffi::DNS_A_DATA>(),
            ffi::DNS_TYPE_AAAA => std::mem::size_of::<ffi::DNS_AAAA_DATA>(),
            ffi::DNS_TYPE_CNAME => std::mem::size_of::<ffi::DNS_PTR_DATAW>(),
            _ => 0,
        };
        ffi::DnsRecord {
            next,
            name: ptr::null_mut(),
            record_type: rrtype,
            data_length: data_length as u16,
            flags: 0,
            ttl: 0,
            reserved: 0,
            data,
        }
    }

    #[repr(C)]
    struct FlatDnsRecord<const N: usize> {
        next: *mut ffi::DnsRecord,
        name: *mut u16,
        record_type: u16,
        data_length: u16,
        flags: u32,
        ttl: u32,
        reserved: u32,
        data: [u8; N],
    }

    #[repr(C)]
    struct TxtDnsRecord<const N: usize> {
        next: *mut ffi::DnsRecord,
        name: *mut u16,
        record_type: u16,
        data_length: u16,
        flags: u32,
        ttl: u32,
        reserved: u32,
        data: TxtData<N>,
    }

    #[repr(C)]
    struct TxtData<const N: usize> {
        string_count: u32,
        strings: [*const u16; N],
    }

    #[test]
    fn parse_a_records_reads_network_order_and_skips_other_types() {
        let mut aaaa = record(
            ffi::DNS_TYPE_AAAA,
            ffi::DnsRecordData {
                aaaa: ffi::DNS_AAAA_DATA {
                    ip6_address: ffi::DNS_IP6_ADDRESS {
                        ip6_byte: Ipv6Addr::LOCALHOST.octets(),
                    },
                },
            },
            ptr::null_mut(),
        );
        let a = record(
            ffi::DNS_TYPE_A,
            ffi::DnsRecordData {
                a: ffi::DNS_A_DATA {
                    ip_address: u32::from(Ipv4Addr::new(192, 0, 2, 1)).to_be(),
                },
            },
            &raw mut aaaa,
        );

        let mut out = Vec::new();
        // SAFETY: the walk contract: the nodes are live, aligned test locals whose
        // type covers their header plus `data_length` bytes, linked by `next`, with
        // NUL-terminated strings, and nothing writes them during the call.
        unsafe { parse_a_records(&raw const a, &mut |ip| out.push(ip)) }.unwrap();
        assert_eq!(out, vec![Ipv4Addr::new(192, 0, 2, 1)]);
    }

    #[test]
    fn authority_and_additional_records_are_not_answers() {
        let a = |octet: u8, section: u32, next: *mut ffi::DnsRecord| ffi::DnsRecord {
            flags: section,
            ..record(
                ffi::DNS_TYPE_A,
                ffi::DnsRecordData {
                    a: ffi::DNS_A_DATA {
                        ip_address: u32::from(Ipv4Addr::new(192, 0, 2, octet)).to_be(),
                    },
                },
                next,
            )
        };
        let mut additional = a(4, DNSREC_ADDITIONAL, ptr::null_mut());
        let mut authority = a(3, DNSREC_AUTHORITY, &raw mut additional);
        let mut answer = a(2, ffi::DNSREC_ANSWER, &raw mut authority);
        let question = a(1, ffi::DNSREC_QUESTION, &raw mut answer);

        let mut out = Vec::new();
        // SAFETY: the walk contract: the nodes are live, aligned test locals whose
        // type covers their header plus `data_length` bytes, linked by `next`, and
        // nothing writes them during the call.
        unsafe { parse_a_records(&raw const question, &mut |ip| out.push(ip)) }.unwrap();
        assert_eq!(
            out,
            vec![Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)]
        );
    }

    #[test]
    fn parse_cname_records_decodes_utf16_target_and_skips_other_types() {
        let target = "Alias.Example.com.\0".encode_utf16().collect::<Vec<_>>();
        let mut a = record(
            ffi::DNS_TYPE_A,
            ffi::DnsRecordData {
                a: ffi::DNS_A_DATA { ip_address: 0 },
            },
            ptr::null_mut(),
        );
        let cname = record(
            ffi::DNS_TYPE_CNAME,
            ffi::DnsRecordData {
                ptr: ffi::DNS_PTR_DATAW {
                    name_host: target.as_ptr(),
                },
            },
            ptr::from_mut(&mut a),
        );

        let mut out = Vec::new();
        // SAFETY: the walk contract: the nodes are live, aligned test locals whose
        // type covers their header plus `data_length` bytes, linked by `next`, with
        // NUL-terminated strings, and nothing writes them during the call.
        unsafe { parse_cname_records(&raw const cname, &mut |name| out.push(name)) }.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].as_wire(), b"\x05Alias\x07Example\x03com\0");
    }

    #[test]
    fn parse_cname_records_rejects_null_target() {
        let cname = record(
            ffi::DNS_TYPE_CNAME,
            ffi::DnsRecordData {
                ptr: ffi::DNS_PTR_DATAW {
                    name_host: ptr::null(),
                },
            },
            ptr::null_mut(),
        );
        // SAFETY: the walk contract: the nodes are live, aligned test locals whose
        // type covers their header plus `data_length` bytes, linked by `next`, with
        // NUL-terminated strings, and nothing writes them during the call.
        unsafe { parse_cname_records(&raw const cname, &mut |_| {}) }
            .expect_err("null target is invalid");
    }

    #[test]
    fn parse_aaaa_records_reads_octets() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let aaaa = record(
            ffi::DNS_TYPE_AAAA,
            ffi::DnsRecordData {
                aaaa: ffi::DNS_AAAA_DATA {
                    ip6_address: ffi::DNS_IP6_ADDRESS {
                        ip6_byte: addr.octets(),
                    },
                },
            },
            ptr::null_mut(),
        );

        let mut out = Vec::new();
        // SAFETY: the walk contract: the nodes are live, aligned test locals whose
        // type covers their header plus `data_length` bytes, linked by `next`, with
        // NUL-terminated strings, and nothing writes them during the call.
        unsafe { parse_aaaa_records(&raw const aaaa, &mut |ip| out.push(ip)) }.unwrap();
        assert_eq!(out, vec![addr]);
    }

    #[test]
    fn parse_txt_records_decodes_wide_strings() {
        let text: Vec<u16> = "hello world".encode_utf16().chain([0]).collect();
        let mut txt = record(
            ffi::DNS_TYPE_TEXT,
            ffi::DnsRecordData {
                txt: ffi::DNS_TXT_DATAW {
                    string_count: 1,
                    strings: [text.as_ptr()],
                },
            },
            ptr::null_mut(),
        );
        txt.data_length = std::mem::size_of::<ffi::DNS_TXT_DATAW>() as u16;

        let mut out = Vec::new();
        // SAFETY: the walk contract: the nodes are live, aligned test locals whose
        // type covers their header plus `data_length` bytes, linked by `next`, with
        // NUL-terminated strings, and nothing writes them during the call.
        unsafe { parse_txt_records(&raw const txt, &mut |bytes| out.push(bytes)) }.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].iter().collect::<Vec<_>>(), vec![&b"hello world"[..]]);
    }

    #[test]
    fn parse_txt_records_preserves_a_valid_empty_string() {
        let empty = [0_u16];
        let mut txt = record(
            ffi::DNS_TYPE_TEXT,
            ffi::DnsRecordData {
                txt: ffi::DNS_TXT_DATAW {
                    string_count: 1,
                    strings: [empty.as_ptr()],
                },
            },
            ptr::null_mut(),
        );
        txt.data_length = std::mem::size_of::<ffi::DNS_TXT_DATAW>() as u16;

        let mut out = Vec::new();
        // SAFETY: the walk contract: the nodes are live, aligned test locals whose
        // type covers their header plus `data_length` bytes, linked by `next`, with
        // NUL-terminated strings, and nothing writes them during the call.
        unsafe { parse_txt_records(&raw const txt, &mut |value| out.push(value)) }
            .expect("valid empty string");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].iter().collect::<Vec<_>>(), [&b""[..]]);
    }

    #[test]
    fn parse_txt_records_normalizes_utf16_to_utf8() {
        let text: Vec<u16> = "héllo".encode_utf16().chain([0]).collect();
        let mut txt = record(
            ffi::DNS_TYPE_TEXT,
            ffi::DnsRecordData {
                txt: ffi::DNS_TXT_DATAW {
                    string_count: 1,
                    strings: [text.as_ptr()],
                },
            },
            ptr::null_mut(),
        );
        txt.data_length = std::mem::size_of::<ffi::DNS_TXT_DATAW>() as u16;

        let mut out = Vec::new();
        // SAFETY: the walk contract: the nodes are live, aligned test locals whose
        // type covers their header plus `data_length` bytes, linked by `next`, with
        // NUL-terminated strings, and nothing writes them during the call.
        unsafe { parse_txt_records(&raw const txt, &mut |value| out.push(value)) }
            .expect("valid Unicode TXT");
        assert_eq!(out[0].iter().collect::<Vec<_>>(), ["héllo".as_bytes()]);
    }

    #[test]
    fn parse_txt_records_rejects_overlong_utf8_output() {
        let text: Vec<u16> = std::iter::repeat_n(u16::from(b'x'), 256)
            .chain([0])
            .collect();
        let mut txt = record(
            ffi::DNS_TYPE_TEXT,
            ffi::DnsRecordData {
                txt: ffi::DNS_TXT_DATAW {
                    string_count: 1,
                    strings: [text.as_ptr()],
                },
            },
            ptr::null_mut(),
        );
        txt.data_length = std::mem::size_of::<ffi::DNS_TXT_DATAW>() as u16;

        let mut out = Vec::new();
        // SAFETY: the walk contract: the nodes are live, aligned test locals whose
        // type covers their header plus `data_length` bytes, linked by `next`, with
        // NUL-terminated strings, and nothing writes them during the call.
        unsafe { parse_txt_records(&raw const txt, &mut |value| out.push(value)) }
            .expect_err("decoded TXT string exceeds the wire limit");
        assert!(out.is_empty());
    }

    #[test]
    fn parse_txt_records_reads_a_multi_string_flexible_tail() {
        let first: Vec<u16> = "first".encode_utf16().chain([0]).collect();
        let second: Vec<u16> = "second".encode_utf16().chain([0]).collect();
        let third: Vec<u16> = "third".encode_utf16().chain([0]).collect();
        let txt = TxtDnsRecord::<3> {
            next: ptr::null_mut(),
            name: ptr::null_mut(),
            record_type: ffi::DNS_TYPE_TEXT,
            data_length: std::mem::size_of::<TxtData<3>>() as u16,
            flags: 0,
            ttl: 0,
            reserved: 0,
            data: TxtData {
                string_count: 3,
                strings: [first.as_ptr(), second.as_ptr(), third.as_ptr()],
            },
        };
        assert_eq!(
            std::mem::offset_of!(TxtDnsRecord<3>, data),
            std::mem::offset_of!(ffi::DnsRecord, data),
        );
        assert_eq!(
            std::mem::offset_of!(TxtData<3>, strings),
            std::mem::offset_of!(ffi::DNS_TXT_DATAW, strings),
        );

        let mut out = Vec::new();
        // SAFETY: the walk contract: the nodes are live, aligned test locals whose
        // type covers their header plus `data_length` bytes, linked by `next`, with
        // NUL-terminated strings, and nothing writes them during the call.
        unsafe { parse_txt_records((&raw const txt).cast(), &mut |value| out.push(value)) }
            .expect("valid multi-string TXT record");
        assert_eq!(
            out[0].iter().collect::<Vec<_>>(),
            vec![&b"first"[..], &b"second"[..], &b"third"[..]]
        );
    }

    #[test]
    fn parse_txt_records_rejects_zero_strings() {
        let mut txt = record(
            ffi::DNS_TYPE_TEXT,
            ffi::DnsRecordData {
                txt: ffi::DNS_TXT_DATAW {
                    string_count: 0,
                    strings: [ptr::null()],
                },
            },
            ptr::null_mut(),
        );
        txt.data_length = std::mem::size_of::<ffi::DNS_TXT_DATAW>() as u16;

        // SAFETY: the walk contract: the nodes are live, aligned test locals whose
        // type covers their header plus `data_length` bytes, linked by `next`, with
        // NUL-terminated strings, and nothing writes them during the call.
        unsafe { parse_txt_records(&raw const txt, &mut |_| {}) }
            .expect_err("zero strings are invalid TXT RDATA");
    }

    #[test]
    fn parse_txt_records_rejects_a_null_string_pointer() {
        let mut txt = record(
            ffi::DNS_TYPE_TEXT,
            ffi::DnsRecordData {
                txt: ffi::DNS_TXT_DATAW {
                    string_count: 1,
                    strings: [ptr::null()],
                },
            },
            ptr::null_mut(),
        );
        txt.data_length = std::mem::size_of::<ffi::DNS_TXT_DATAW>() as u16;

        // SAFETY: the walk contract: the nodes are live, aligned test locals whose
        // type covers their header plus `data_length` bytes, linked by `next`, with
        // NUL-terminated strings, and nothing writes them during the call.
        unsafe { parse_txt_records(&raw const txt, &mut |_| {}) }
            .expect_err("null TXT string is invalid");
    }

    #[test]
    fn parse_txt_records_rejects_the_whole_record_after_a_null_string() {
        let first: Vec<u16> = "valid".encode_utf16().chain([0]).collect();
        let txt = TxtDnsRecord::<2> {
            next: ptr::null_mut(),
            name: ptr::null_mut(),
            record_type: ffi::DNS_TYPE_TEXT,
            data_length: std::mem::size_of::<TxtData<2>>() as u16,
            flags: 0,
            ttl: 0,
            reserved: 0,
            data: TxtData {
                string_count: 2,
                strings: [first.as_ptr(), ptr::null()],
            },
        };

        let mut out = Vec::new();
        // SAFETY: the walk contract: the nodes are live, aligned test locals whose
        // type covers their header plus `data_length` bytes, linked by `next`, with
        // NUL-terminated strings, and nothing writes them during the call.
        unsafe { parse_txt_records((&raw const txt).cast(), &mut |value| out.push(value)) }
            .expect_err("one null string invalidates the record");
        assert!(out.is_empty());
    }

    #[test]
    fn parse_txt_records_rejects_a_count_beyond_the_flexible_tail() {
        let text: Vec<u16> = "only".encode_utf16().chain([0]).collect();
        let mut txt = record(
            ffi::DNS_TYPE_TEXT,
            ffi::DnsRecordData {
                txt: ffi::DNS_TXT_DATAW {
                    string_count: 2,
                    strings: [text.as_ptr()],
                },
            },
            ptr::null_mut(),
        );
        txt.data_length = std::mem::size_of::<ffi::DNS_TXT_DATAW>() as u16;

        // SAFETY: the walk contract: the nodes are live, aligned test locals whose
        // type covers their header plus `data_length` bytes, linked by `next`, with
        // NUL-terminated strings, and nothing writes them during the call.
        unsafe { parse_txt_records(&raw const txt, &mut |_| {}) }
            .expect_err("the declared count exceeds the one-pointer Data allocation");
    }

    #[test]
    fn parse_service_binding_records_reads_flat_rdata_and_filters_type() {
        let mut https = record(
            RecordType::HTTPS.into(),
            ffi::DnsRecordData {
                flat: [0, 1, 0, 0, 3, 0, 2, 1, 187, 0, 0, 0, 0, 0, 0, 0],
            },
            ptr::null_mut(),
        );
        https.data_length = 9;
        let mut svcb = record(
            RecordType::SVCB.into(),
            ffi::DnsRecordData {
                flat: [0, 1, 0, 0, 3, 0, 2, 32, 251, 0, 0, 0, 0, 0, 0, 0],
            },
            &raw mut https,
        );
        svcb.data_length = 9;

        let mut out = Vec::new();
        // SAFETY: the walk contract: the nodes are live, aligned test locals whose
        // type covers their header plus `data_length` bytes, linked by `next`, with
        // NUL-terminated strings, and nothing writes them during the call.
        unsafe {
            parse_service_binding_records(&raw const svcb, RecordType::SVCB, &mut |value| {
                out.push(value)
            })
        }
        .expect("valid SVCB");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].port(), Some(8443));

        out.clear();
        // SAFETY: the walk contract: the nodes are live, aligned test locals whose
        // type covers their header plus `data_length` bytes, linked by `next`, with
        // NUL-terminated strings, and nothing writes them during the call.
        unsafe {
            parse_service_binding_records(&raw const svcb, RecordType::HTTPS, &mut |value| {
                out.push(value)
            })
        }
        .expect("valid HTTPS");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].port(), Some(443));
    }

    #[test]
    fn parse_service_binding_records_rejects_malformed_flat_rdata() {
        let mut record = record(
            RecordType::SVCB.into(),
            ffi::DnsRecordData { flat: [0; 16] },
            ptr::null_mut(),
        );
        record.data_length = 2;
        // SAFETY: the walk contract: the nodes are live, aligned test locals whose
        // type covers their header plus `data_length` bytes, linked by `next`, with
        // NUL-terminated strings, and nothing writes them during the call.
        unsafe { parse_service_binding_records(&raw const record, RecordType::SVCB, &mut |_| {}) }
            .expect_err("target name is missing");
    }

    #[test]
    fn parse_service_binding_records_reads_a_large_flexible_tail() {
        let opaque = [0x5a; 300];
        let mut rdata = vec![0, 1, 0];
        rdata.extend_from_slice(&65_000_u16.to_be_bytes());
        rdata.extend_from_slice(&(opaque.len() as u16).to_be_bytes());
        rdata.extend_from_slice(&opaque);

        let mut record = FlatDnsRecord::<512> {
            next: ptr::null_mut(),
            name: ptr::null_mut(),
            record_type: RecordType::HTTPS.into(),
            data_length: rdata.len() as u16,
            flags: 0,
            ttl: 0,
            reserved: 0,
            data: [0; 512],
        };
        record.data[..rdata.len()].copy_from_slice(&rdata);
        assert_eq!(
            std::mem::offset_of!(FlatDnsRecord<512>, data),
            std::mem::offset_of!(ffi::DnsRecord, data),
        );

        let mut out = Vec::new();
        // SAFETY: the walk contract: the nodes are live, aligned test locals whose
        // type covers their header plus `data_length` bytes, linked by `next`, with
        // NUL-terminated strings, and nothing writes them during the call.
        unsafe {
            parse_service_binding_records(
                (&raw const record).cast(),
                RecordType::HTTPS,
                &mut |value| out.push(value),
            )
        }
        .expect("valid flexible-tail HTTPS RDATA");

        assert_eq!(out.len(), 1);
        assert_matches!(
            &out[0].params()[0],
            SvcParam::Unknown { value, .. } if value.as_ref() == opaque,
        );
    }

    #[test]
    fn complete_record_set_discards_values_before_a_malformed_record() {
        let mut malformed = record(
            RecordType::SVCB.into(),
            ffi::DnsRecordData { flat: [0; 16] },
            ptr::null_mut(),
        );
        malformed.data_length = 2;
        let mut valid = record(
            RecordType::SVCB.into(),
            ffi::DnsRecordData {
                flat: [0, 1, 0, 0, 3, 0, 2, 32, 251, 0, 0, 0, 0, 0, 0, 0],
            },
            &raw mut malformed,
        );
        valid.data_length = 9;

        // SAFETY: the walk contract: the nodes are live, aligned test locals whose
        // type covers their header plus `data_length` bytes, linked by `next`, with
        // NUL-terminated strings, and nothing writes them during the call.
        unsafe { parse_complete_record_set(parse_svcb_records, &raw const valid) }
            .expect_err("one malformed record invalidates the complete RRset");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn service_binding_queries_use_the_selected_record_type() {
        let parsers: [(RecordType, RecordParser<ServiceBinding>); 2] = [
            (RecordType::SVCB, parse_svcb_records),
            (RecordType::HTTPS, parse_https_records),
        ];
        for (record_type, parser) in parsers {
            let fake = Arc::new(FakeDnsBackend::new());
            let stream = query_record_stream_with_backend(
                Domain::example(),
                deadline_after(Duration::from_secs(30)),
                Duration::from_secs(30),
                record_type.into(),
                parser,
                DnsBackend::Fake(fake.clone()),
            );
            let query_task = tokio::spawn(async move {
                let mut stream = pin!(stream);
                stream.next().await
            });

            tokio::time::timeout(Duration::from_secs(5), fake.started.notified())
                .await
                .expect("fake DNS query did not start");
            assert_eq!(
                fake.query_type.load(Ordering::SeqCst),
                u16::from(record_type)
            );

            query_task.abort();
            _ = query_task.await;
            fake.join_callback_threads();
        }
    }

    /// A node allocated as exactly its header plus a `D` payload, as
    /// `DnsQueryEx` sizes them: smaller than a full `DnsRecord`.
    #[repr(C)]
    struct SizedRecord<D> {
        next: *mut ffi::DnsRecord,
        name: *mut u16,
        record_type: u16,
        data_length: u16,
        flags: u32,
        ttl: u32,
        reserved: u32,
        data: D,
    }

    impl<D> SizedRecord<D> {
        fn new(record_type: u16, data: D) -> Self {
            assert_eq!(
                std::mem::offset_of!(Self, data),
                std::mem::offset_of!(ffi::DnsRecord, data),
            );
            Self {
                next: ptr::null_mut(),
                name: ptr::null_mut(),
                record_type,
                data_length: std::mem::size_of::<D>() as u16,
                flags: 0,
                ttl: 0,
                reserved: 0,
                data,
            }
        }
    }

    fn a_data(octet: u8) -> ffi::DNS_A_DATA {
        ffi::DNS_A_DATA {
            ip_address: u32::from(Ipv4Addr::new(192, 0, 2, octet)).to_be(),
        }
    }

    /// The fake's answer: A 192.0.2.1, an AAAA, A 192.0.2.2, each node its
    /// own heap allocation sized as dnsapi sizes it.
    pub(super) fn alloc_answer() -> *mut ffi::DnsRecord {
        let tail = Box::into_raw(Box::new(SizedRecord::new(ffi::DNS_TYPE_A, a_data(2))));
        let mut aaaa = SizedRecord::new(
            ffi::DNS_TYPE_AAAA,
            ffi::DNS_AAAA_DATA {
                ip6_address: ffi::DNS_IP6_ADDRESS {
                    ip6_byte: Ipv6Addr::LOCALHOST.octets(),
                },
            },
        );
        aaaa.next = tail.cast();
        let aaaa = Box::into_raw(Box::new(aaaa));
        let mut head = SizedRecord::new(ffi::DNS_TYPE_A, a_data(1));
        head.next = aaaa.cast();
        Box::into_raw(Box::new(head)).cast()
    }

    /// Free a list from [`alloc_answer`].
    ///
    /// # Safety
    ///
    /// The caller must ensure that `node` is the head of a list from
    /// [`alloc_answer`], not freed yet and not used once this call returns.
    pub(super) unsafe fn free_answer(mut node: *mut ffi::DnsRecord) {
        while !node.is_null() {
            // SAFETY: a place read of the header of a live, aligned node from
            // `alloc_answer` (this function's contract). No reference is made.
            let record_type = unsafe { (*node).record_type };
            // SAFETY: as above.
            let next = unsafe { (*node).next };
            match record_type {
                ffi::DNS_TYPE_A => {
                    // SAFETY: `Box::from_raw`: `alloc_answer` leaked every A node
                    // as a `Box<SizedRecord<DNS_A_DATA>>`, freed only here, once.
                    drop(unsafe { Box::from_raw(node.cast::<SizedRecord<ffi::DNS_A_DATA>>()) })
                }
                ffi::DNS_TYPE_AAAA => {
                    // SAFETY: as above, for its AAAA node.
                    drop(unsafe { Box::from_raw(node.cast::<SizedRecord<ffi::DNS_AAAA_DATA>>()) })
                }
                other => panic!("alloc_answer made no type {other} node"),
            }
            node = next;
        }
    }

    /// An A query of `example.com` on `fake`.
    fn fake_a_query(
        fake: &Arc<FakeDnsBackend>,
    ) -> impl Stream<Item = Result<Ipv4Addr, BoxError>> + Send + use<> {
        query_record_stream_with_backend(
            Domain::example(),
            deadline_after(Duration::from_secs(30)),
            Duration::from_secs(30),
            ffi::DNS_TYPE_A,
            parse_a_records,
            DnsBackend::Fake(fake.clone()),
        )
    }

    /// Poll `stream` to its end on this thread, without a runtime: it must
    /// never wait.
    fn collect_without_waiting<S: Stream>(stream: S) -> Vec<S::Item> {
        let mut stream = pin!(stream);
        let mut cx = Context::from_waker(Waker::noop());
        let mut items = Vec::new();
        loop {
            match stream.as_mut().poll_next(&mut cx) {
                Poll::Ready(Some(item)) => items.push(item),
                Poll::Ready(None) => return items,
                Poll::Pending => panic!("stream waits although its query finished"),
            }
        }
    }

    fn assert_answer(items: &[Result<Ipv4Addr, BoxError>]) {
        assert_matches!(
            items,
            [Ok(first), Ok(second)]
                if *first == Ipv4Addr::new(192, 0, 2, 1) && *second == Ipv4Addr::new(192, 0, 2, 2),
            "{items:?}",
        );
    }

    #[test]
    fn synchronous_answer_is_parsed_and_freed_once() {
        let fake = Arc::new(FakeDnsBackend::with_mode(FakeMode::AnswerSync));
        assert_answer(&collect_without_waiting(fake_a_query(&fake)));
        assert_eq!(fake.callbacks.load(Ordering::SeqCst), 0);
        assert_eq!(fake.lists_freed.load(Ordering::SeqCst), 1);
        assert!(fake.live_lists.lock().is_empty());
        assert_eq!(fake.blocks_dropped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn callback_inside_query_delivers_its_answer_once() {
        // `DnsQueryEx` may complete before it returns pending
        let fake = Arc::new(FakeDnsBackend::with_mode(FakeMode::AnswerInsideQuery));
        assert_answer(&collect_without_waiting(fake_a_query(&fake)));
        assert_eq!(fake.callbacks.load(Ordering::SeqCst), 1);
        assert_eq!(fake.lists_freed.load(Ordering::SeqCst), 1);
        assert!(fake.live_lists.lock().is_empty());
        assert!(fake.cancel_handles.lock().is_empty());
        assert_eq!(fake.blocks_dropped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn callback_holding_the_last_arc_frees_the_block_once() {
        // a time driver for the stream's deadline, without IOCP
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        let _runtime = runtime.enter();
        let fake = Arc::new(FakeDnsBackend::with_mode(FakeMode::DeferCancel));
        {
            let mut stream = pin!(fake_a_query(&fake));
            let mut cx = Context::from_waker(Waker::noop());
            assert!(stream.as_mut().poll_next(&mut cx).is_pending());
        }
        assert_eq!(
            *fake.cancel_handles.lock(),
            [fake.query_cancel_handle.load(Ordering::SeqCst)],
            "dropping the stream did not cancel its query",
        );
        assert_eq!(fake.blocks_dropped.load(Ordering::SeqCst), 0);

        let completer = fake.clone();
        std::thread::spawn(move || completer.fire_pending_callback(FakeAnswer::Records))
            .join()
            .expect("callback thread panicked");
        assert_eq!(fake.callbacks.load(Ordering::SeqCst), 1);
        assert_eq!(fake.lists_freed.load(Ordering::SeqCst), 1);
        assert!(fake.live_lists.lock().is_empty());
        assert_eq!(fake.blocks_dropped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cancel_after_completion_is_harmless() {
        // the callback finishes between `request_cancel`'s done check and its cancel
        let fake = Arc::new(FakeDnsBackend::with_mode(FakeMode::AnswerBeforeCancel));
        let state = Arc::new(QueryState {
            queue: Mutex::new(VecDeque::new()),
            done: AtomicBool::new(false),
            timeout: Duration::from_secs(30),
            timed_out: AtomicBool::new(false),
            suppress_results: AtomicBool::new(false),
            cancel_requested: AtomicBool::new(false),
            notify: Notify::new(),
            inflight: Mutex::new(None),
            parser: parse_a_records,
            backend: DnsBackend::Fake(fake.clone()),
        });
        let name = dns_name_from_domain("example.com").expect("name");
        start_query(&state, name, ffi::DNS_TYPE_A);
        assert!(!state.done.load(Ordering::SeqCst));

        request_cancel(&state);
        request_cancel(&state);
        assert!(state.done.load(Ordering::SeqCst));
        assert_eq!(
            *fake.cancel_handles.lock(),
            [fake.query_cancel_handle.load(Ordering::SeqCst)],
        );
        assert_answer(&drain_queue(&state));
        assert!(drain_queue(&state).is_empty());
        assert_eq!(fake.callbacks.load(Ordering::SeqCst), 1);
        assert_eq!(fake.lists_freed.load(Ordering::SeqCst), 1);
        assert_eq!(fake.blocks_dropped.load(Ordering::SeqCst), 0);
        drop(state);
        assert_eq!(fake.blocks_dropped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn fixed_size_records_are_read_within_their_payload() {
        // Under Miri, reading a node as a whole `DnsRecord` overruns these.
        let a = SizedRecord::new(
            ffi::DNS_TYPE_A,
            ffi::DNS_A_DATA {
                ip_address: u32::from(Ipv4Addr::new(192, 0, 2, 1)).to_be(),
            },
        );
        assert!(std::mem::size_of_val(&a) < std::mem::size_of::<ffi::DnsRecord>());
        let mut addrs = Vec::new();
        // SAFETY: the walk contract: `a` is a live, aligned test local whose
        // type covers its header plus `data_length` bytes, with a null `next`,
        // and nothing writes it during the call.
        unsafe { parse_a_records((&raw const a).cast(), &mut |ip| addrs.push(ip)) }.unwrap();
        assert_eq!(addrs, [Ipv4Addr::new(192, 0, 2, 1)]);

        let target = "alias.example.\0".encode_utf16().collect::<Vec<_>>();
        let cname = SizedRecord::new(
            ffi::DNS_TYPE_CNAME,
            ffi::DNS_PTR_DATAW {
                name_host: target.as_ptr(),
            },
        );
        assert!(std::mem::size_of_val(&cname) < std::mem::size_of::<ffi::DnsRecord>());
        let mut names = Vec::new();
        // SAFETY: as above, and `pNameHost` points to the NUL-terminated
        // `target`, which outlives the call.
        unsafe { parse_cname_records((&raw const cname).cast(), &mut |name| names.push(name)) }
            .unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].as_wire(), b"\x05alias\x07example\0");
    }

    #[test]
    fn records_shorter_than_their_type_are_rejected() {
        let a = SizedRecord::new(ffi::DNS_TYPE_A, [0x7f_u8; 2]);
        let aaaa = SizedRecord::new(ffi::DNS_TYPE_AAAA, [0x7f_u8; 15]);
        let cname = SizedRecord::new(ffi::DNS_TYPE_CNAME, [0x7f_u8; 4]);
        // SAFETY: the walk contract: each node is a live, aligned test local
        // whose type covers its header plus `data_length` bytes, with a null
        // `next`, and nothing writes it during the call.
        unsafe { parse_a_records((&raw const a).cast(), &mut |_| panic!("short A")) }
            .expect_err("an A payload shorter than an address is invalid");
        // SAFETY: as above.
        unsafe { parse_aaaa_records((&raw const aaaa).cast(), &mut |_| panic!("short AAAA")) }
            .expect_err("an AAAA payload shorter than an address is invalid");
        // SAFETY: as above.
        unsafe { parse_cname_records((&raw const cname).cast(), &mut |_| panic!("short CNAME")) }
            .expect_err("a CNAME payload shorter than a pointer is invalid");
    }

    #[test]
    fn parse_records_handles_empty_list() {
        // SAFETY: the walk contract allows a null (empty) list.
        unsafe { parse_a_records(ptr::null(), &mut |_| panic!("no records expected")) }.unwrap();
    }

    #[tokio::test]
    async fn lookup_ipv4_localhost_resolves() {
        let resolver = WindowsDnsResolver::new();
        let addrs: Vec<_> = resolver
            .lookup_ipv4(Domain::tld_localhost())
            .collect()
            .await;
        assert!(
            addrs
                .iter()
                .any(|result| matches!(result, Ok(addr) if addr.is_loopback())),
            "expected a loopback answer, got: {addrs:?}",
        );
    }

    #[tokio::test]
    async fn lookup_ipv4_nonexistent_domain_yields_no_addresses() {
        let resolver = WindowsDnsResolver::new();
        let addrs: Vec<_> = resolver
            .lookup_ipv4(Domain::from_static("does-not-exist.invalid"))
            .collect()
            .await;
        assert!(
            !addrs.iter().any(|result| result.is_ok()),
            "unexpected answer for reserved .invalid name: {addrs:?}",
        );
    }

    /// A name no earlier run asked, so the DNS Client cache cannot answer it.
    fn uncached(label: &str) -> Domain {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("{label}-{nonce:x}.example.com")
            .try_into()
            .expect("domain")
    }

    /// A lookup that answers `127.0.0.1` once `gate` opens.
    fn gated_lookup(
        gate: &Arc<Notify>,
    ) -> impl FnOnce(Domain, Instant, Duration) -> BoxStream<'static, Result<Ipv4Addr, BoxError>>
    + Send
    + 'static {
        let gate = gate.clone();
        move |_domain, _deadline, _timeout| {
            stream::once(async move {
                gate.notified().await;
                Ok(Ipv4Addr::LOCALHOST)
            })
            .boxed()
        }
    }

    #[tokio::test]
    async fn rooted_and_relative_names_share_one_query() {
        let resolver = WindowsDnsResolver::new();
        let gate = Arc::new(Notify::new());
        // the root dot is dropped before DnsQueryEx: both ask the same thing
        let relative = resolver
            .coalesced(
                Domain::from_static("intranet"),
                ffi::DNS_TYPE_A,
                gated_lookup(&gate),
            )
            .collect::<Vec<_>>();
        let rooted = resolver
            .coalesced(
                Domain::from_static("intranet."),
                ffi::DNS_TYPE_A,
                gated_lookup(&gate),
            )
            .collect::<Vec<_>>();
        let both_running = async {
            let running = resolver.in_flight.running();
            gate.notify_waiters();
            running
        };
        let (relative, rooted, running) = tokio::join!(relative, rooted, both_running);

        assert_eq!(running, 1);
        assert_matches!(relative.as_slice(), [Ok(_)], "{relative:?}");
        assert_matches!(rooted.as_slice(), [Ok(_)], "{rooted:?}");
    }

    #[test]
    fn only_resolvers_with_the_same_timeout_share_lookups() {
        let resolver = WindowsDnsResolver::new();
        assert!(resolver.clone().in_flight.shares_with(&resolver.in_flight));
        let hasty = resolver.clone().with_timeout(Duration::from_millis(100));
        assert!(!hasty.in_flight.shares_with(&resolver.in_flight));
    }

    #[test]
    fn abandoned_lookups_are_cancelled() {
        // each holds a DNS Client service request nobody waits on anymore
        let resolver = WindowsDnsResolver::new();
        assert_eq!(resolver.in_flight.abandoned(), Abandoned::Cancel);
        let resolver = resolver.with_timeout(Duration::from_secs(1));
        assert_eq!(resolver.in_flight.abandoned(), Abandoned::Cancel);
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_is_not_held_back_by_default() {
        let resolver = WindowsDnsResolver::new();
        assert_eq!(resolver.max_concurrency(), None);
        assert_eq!(resolver.burst_limit(), None);
        let gate = Arc::new(Notify::new());
        let started = Arc::new(AtomicUsize::new(0));
        let lookups = (0..1024).map(|i| {
            let (gate, started) = (gate.clone(), started.clone());
            let domain = Domain::try_from(format!("n{i}.burst.test")).expect("domain");
            resolver
                .coalesced(domain, ffi::DNS_TYPE_A, move |domain, deadline, timeout| {
                    started.fetch_add(1, Ordering::Relaxed);
                    gated_lookup(&gate)(domain, deadline, timeout)
                })
                .collect::<Vec<_>>()
        });
        let all_started = async {
            for _ in 0..16 {
                tokio::task::yield_now().await;
            }
            let all_started = started.load(Ordering::Relaxed);
            gate.notify_waiters();
            all_started
        };
        let (answers, all_started) = tokio::join!(join_all(lookups), all_started);

        assert_eq!(all_started, 1024);
        assert!(
            answers
                .iter()
                .all(|items| matches!(items.as_slice(), [Ok(_)]))
        );

        let bounded = resolver.with_burst_limit(128);
        assert_eq!(bounded.burst_limit(), Some(128));
        assert_eq!(bounded.without_burst_limit().burst_limit(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn answers_free_their_burst_place() {
        let resolver = WindowsDnsResolver::new()
            .with_burst_limit(1)
            .with_burst_window(Duration::from_mins(1));
        let started = Instant::now();
        // records, an error answer, then records again: none waits for the window
        for (i, answer) in [
            Ok(Ipv4Addr::LOCALHOST),
            Err("SERVFAIL"),
            Ok(Ipv4Addr::LOCALHOST),
        ]
        .into_iter()
        .enumerate()
        {
            let domain = Domain::try_from(format!("n{i}.burst.test")).expect("domain");
            let items: Vec<_> = resolver
                .coalesced(
                    domain,
                    ffi::DNS_TYPE_A,
                    move |_domain, _deadline, _timeout| {
                        stream::once(std::future::ready(
                            answer.map_err(BoxError::from_static_str),
                        ))
                    },
                )
                .collect()
                .await;
            assert!(
                !items
                    .iter()
                    .any(|item| item.as_ref().is_err_and(|err| err.is::<DnsTimeoutError>())),
                "{items:?}"
            );
        }
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test]
    async fn lookup_waiting_for_a_busy_slot_times_out() {
        let resolver = WindowsDnsResolver::new()
            .with_max_concurrency(1)
            .with_timeout(Duration::from_millis(100));
        let _busy = resolver
            .limit
            .acquire(deadline_after(Duration::from_secs(5)))
            .await
            .expect("the only slot");
        let gate = Arc::new(Notify::new());

        let items: Vec<_> = resolver
            .coalesced(
                Domain::from_static("intranet"),
                ffi::DNS_TYPE_A,
                gated_lookup(&gate),
            )
            .collect()
            .await;
        assert_matches!(
            items.as_slice(),
            [Err(err)] if err.downcast_ref::<DnsTimeoutError>().is_some(),
            "{items:?}",
        );
    }

    #[tokio::test]
    async fn leading_dot_name_is_refused_before_sharing() {
        let resolver = WindowsDnsResolver::new();
        let gate = Arc::new(Notify::new());
        let bare = resolver
            .coalesced(
                Domain::from_static("intranet"),
                ffi::DNS_TYPE_A,
                gated_lookup(&gate),
            )
            .collect::<Vec<_>>();
        let dotted = resolver
            .coalesced(
                Domain::from_static(".intranet"),
                ffi::DNS_TYPE_A,
                gated_lookup(&gate),
            )
            .collect::<Vec<_>>();
        let open = async {
            let running = resolver.in_flight.running();
            gate.notify_waiters();
            running
        };
        let (bare, dotted, running) = tokio::join!(bare, dotted, open);

        assert_eq!(running, 1);
        assert_matches!(bare.as_slice(), [Ok(_)], "{bare:?}");
        assert_matches!(
            dotted.as_slice(),
            [Err(err)] if err.to_string().contains("starts with a dot"),
            "{dotted:?}",
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abandoned_shared_query_is_cancelled() {
        let fake = Arc::new(FakeDnsBackend::new());
        let backend = fake.clone();
        let stream = coalesced_stream(
            InFlight::new(Abandoned::Cancel),
            (Domain::example(), ffi::DNS_TYPE_A),
            Duration::from_secs(30),
            move || {
                query_record_stream_with_backend(
                    Domain::example(),
                    deadline_after(Duration::from_secs(30)),
                    Duration::from_secs(30),
                    ffi::DNS_TYPE_A,
                    parse_a_records,
                    DnsBackend::Fake(backend),
                )
            },
        );
        let caller = tokio::spawn(async move { pin!(stream).next().await });

        tokio::time::timeout(Duration::from_secs(5), fake.started.notified())
            .await
            .expect("fake DNS query did not start");
        caller.abort();
        _ = caller.await;

        // the fake's cancel returns once the callback finished, or gave up on it
        tokio::time::timeout(Duration::from_secs(5), async {
            while fake.callback_threads.lock().is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the abandoned shared query was not cancelled");
        assert!(fake.cancel_called.load(Ordering::SeqCst));
        assert!(
            fake.callback_completed_during_cancel.load(Ordering::SeqCst),
            "completion callback was blocked during cancellation",
        );
        fake.join_callback_threads();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_pending_query_does_not_block_completion_callback() {
        let fake = Arc::new(FakeDnsBackend::new());
        let stream = query_record_stream_with_backend(
            Domain::example(),
            deadline_after(Duration::from_secs(30)),
            Duration::from_secs(30),
            ffi::DNS_TYPE_A,
            parse_a_records,
            DnsBackend::Fake(fake.clone()),
        );

        let query_task = tokio::spawn(async move {
            let mut stream = pin!(stream);
            stream.next().await
        });

        tokio::time::timeout(Duration::from_secs(5), fake.started.notified())
            .await
            .expect("fake DNS query did not start");

        query_task.abort();
        let task_result = tokio::time::timeout(Duration::from_secs(5), query_task)
            .await
            .expect("stream cancellation remained blocked");
        assert!(
            task_result.as_ref().is_err_and(|err| err.is_cancelled()),
            "query task was not cancelled: {task_result:?}",
        );

        let cancel_called = fake.cancel_called.load(Ordering::SeqCst);
        let callback_completed_during_cancel =
            fake.callback_completed_during_cancel.load(Ordering::SeqCst);
        fake.join_callback_threads();

        assert!(
            cancel_called,
            "dropping the stream did not cancel its pending query",
        );
        assert!(
            callback_completed_during_cancel,
            "completion callback was blocked during cancellation",
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn timed_out_query_parks_until_cancel_callback_fires() {
        let fake = Arc::new(FakeDnsBackend::with_mode(FakeMode::DeferCancel));
        // a lookup that queued for its slot: little time left of a 5s budget
        let stream = query_record_stream_with_backend(
            Domain::example(),
            deadline_after(Duration::from_millis(10)),
            Duration::from_secs(5),
            ffi::DNS_TYPE_A,
            parse_a_records,
            DnsBackend::Fake(fake.clone()),
        );

        let consumer = tokio::spawn(async move {
            let mut stream = pin!(stream);
            let mut items = Vec::new();
            while let Some(item) = stream.next().await {
                items.push(item);
            }
            items
        });

        tokio::time::timeout(Duration::from_secs(5), fake.cancel_requested.notified())
            .await
            .expect("query did not time out into a cancel request");

        // a busy-waiting stream racks up thousands of loop iterations in this window
        tokio::time::sleep(Duration::from_millis(100)).await;
        fake.fire_pending_callback(FakeAnswer::Cancelled);

        let items = tokio::time::timeout(Duration::from_secs(5), consumer)
            .await
            .expect("stream did not finish after the cancel callback")
            .expect("consumer task panicked");
        assert_matches!(
            items.as_slice(),
            [Err(err)] if err
                .downcast_ref::<DnsTimeoutError>()
                .is_some_and(|err| err.timeout() == Duration::from_secs(5)),
            "expected a single timeout error reporting the whole budget, got: {items:?}",
        );

        let iterations = fake.wait_loop_iterations.load(Ordering::SeqCst);
        assert!(
            iterations < 50,
            "wait loop burned {iterations} iterations while parked on a cancelled query",
        );
    }

    #[test]
    fn sibling_stream_drop_cancels_in_flight_query_without_hanging() {
        // dropping a stream with a still-pending query must not deadlock with the completion callback
        let (done, finished) = std::sync::mpsc::channel();
        // its own thread and runtime: a deadlock blocks them, not this watchdog
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async {
                let resolver = WindowsDnsResolver::new().with_timeout(Duration::from_secs(2));
                for i in 0..64 {
                    // uncached names keep both queries async, also on a re-run
                    let domain = uncached(&format!("cancel-race-{i}"));
                    let mut lookup_v4 = pin!(resolver.lookup_ipv4(domain.clone()));
                    let mut lookup_v6 = pin!(resolver.lookup_ipv6(domain));
                    tokio::select! {
                        _ = lookup_v4.next() => {}
                        _ = lookup_v6.next() => {}
                    }
                    _ = done.send(());
                }
            });
        });

        for _ in 0..64 {
            // one iteration takes at most the 2s lookup timeout and its cancel
            finished
                .recv_timeout(Duration::from_secs(15))
                .expect("in-flight query cancellation deadlocked");
        }
    }

    #[tokio::test]
    async fn short_timeout_lookup_completes() {
        let resolver = WindowsDnsResolver::new().with_timeout(Duration::from_millis(1));
        let completed = tokio::time::timeout(Duration::from_secs(30), async {
            let mut stream = pin!(resolver.lookup_ipv4(uncached("short-timeout")));
            while stream.next().await.is_some() {}
        })
        .await;
        assert!(completed.is_ok(), "timed-out lookup hung");
    }

    fn unicast(ip: &str, skip_as_source: bool, dad_state: ffi::NL_DAD_STATE) -> UnicastAddress {
        UnicastAddress {
            ip: ip.parse().expect("ip"),
            skip_as_source,
            dad_state,
        }
    }

    /// Two usable IPv4 addresses, one usable IPv6 address, and one row for
    /// each filter.
    fn fake_host() -> LocalHost {
        let preferred = ffi::IpDadStatePreferred;
        LocalHost::Fake(Arc::new(FakeLocalHost {
            names: [
                "DESKTOP-RAMA".into(),
                "desktop-rama.corp.example".into(),
                "DESKTOP-RAMA".into(),
            ]
            .into(),
            addresses: vec![
                unicast("192.0.2.10", false, preferred),
                unicast("2001:db8::10", false, preferred),
                unicast("192.0.2.11", true, preferred),
                unicast("2001:db8::11", true, preferred),
                unicast("192.0.2.12", false, IpDadStateTentative),
                unicast("2001:db8::12", false, IpDadStateDeprecated),
                unicast("127.0.0.1", false, preferred),
                unicast("::1", false, preferred),
                unicast("fe80::1", false, preferred),
                unicast("192.0.2.20", false, preferred),
            ],
        }))
    }

    async fn own_name_lookup<T: HostAddress>(
        name: &str,
        local_host: Option<LocalHost>,
        fake: &Arc<FakeDnsBackend>,
    ) -> Vec<Result<T, BoxError>> {
        WindowsDnsResolver::new()
            .address_lookup_on(
                Domain::try_from(name.to_owned()).expect("domain"),
                local_host,
                DnsBackend::Fake(fake.clone()),
            )
            .collect()
            .await
    }

    fn addrs<T>(items: Vec<Result<T, BoxError>>) -> Vec<T> {
        items
            .into_iter()
            .collect::<Result<_, _>>()
            .expect("no error items")
    }

    #[tokio::test]
    async fn own_name_is_answered_without_querying_dns() {
        let fake = Arc::new(FakeDnsBackend::with_mode(FakeMode::AnswerSync));
        for name in [
            "DESKTOP-RAMA",
            "desktop-rama",
            "Desktop-Rama.",
            "desktop-rama.corp.example",
            "DESKTOP-RAMA.CORP.EXAMPLE.",
        ] {
            let v4 = addrs(own_name_lookup::<Ipv4Addr>(name, Some(fake_host()), &fake).await);
            assert_eq!(
                v4,
                [Ipv4Addr::new(192, 0, 2, 10), Ipv4Addr::new(192, 0, 2, 20)],
                "{name}"
            );
            let v6 = addrs(own_name_lookup::<Ipv6Addr>(name, Some(fake_host()), &fake).await);
            assert_eq!(v6, ["2001:db8::10".parse::<Ipv6Addr>().unwrap()], "{name}");
        }
        assert_eq!(fake.queries.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn own_name_without_addresses_of_the_family_is_empty() {
        let fake = Arc::new(FakeDnsBackend::with_mode(FakeMode::AnswerSync));
        let host = LocalHost::Fake(Arc::new(FakeLocalHost {
            names: ["desktop-rama".into()].into(),
            addresses: vec![unicast("192.0.2.10", false, ffi::IpDadStatePreferred)],
        }));
        assert!(
            own_name_lookup::<Ipv6Addr>("desktop-rama", Some(host), &fake)
                .await
                .is_empty()
        );
        assert_eq!(fake.queries.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn own_name_answer_takes_no_query_slot() {
        let resolver = WindowsDnsResolver::new().with_max_concurrency(1);
        let gate = Arc::new(Notify::new());
        let mut held =
            pin!(resolver.coalesced(uncached("held"), ffi::DNS_TYPE_A, gated_lookup(&gate)));
        let mut cx = Context::from_waker(Waker::noop());
        // the held lookup takes the only slot and waits on its gate
        assert!(held.as_mut().poll_next(&mut cx).is_pending());

        let fake = Arc::new(FakeDnsBackend::with_mode(FakeMode::AnswerSync));
        let lookup = |name| {
            resolver.address_lookup_on::<Ipv4Addr>(
                Domain::from_static(name),
                Some(fake_host()),
                DnsBackend::Fake(fake.clone()),
            )
        };
        let mut queued = pin!(lookup("desktop-rama2"));
        assert!(queued.as_mut().poll_next(&mut cx).is_pending());
        let v4 = collect_without_waiting(lookup("desktop-rama"));
        assert_eq!(
            addrs(v4),
            [Ipv4Addr::new(192, 0, 2, 10), Ipv4Addr::new(192, 0, 2, 20)]
        );
        assert_eq!(fake.queries.load(Ordering::SeqCst), 0);

        gate.notify_waiters();
        assert_matches!(held.next().await, Some(Ok(_)));
        assert_eq!(held.next().await.map(|_| ()), None);
        assert_answer(&queued.collect::<Vec<_>>().await);
    }

    #[tokio::test]
    async fn other_names_are_sent_to_dns() {
        let fake = Arc::new(FakeDnsBackend::with_mode(FakeMode::AnswerSync));
        let names = [
            "desktop-rama2",
            "desktop",
            "desktop-rama.corp",
            "rama.corp.example",
        ];
        for name in names {
            assert_answer(&own_name_lookup::<Ipv4Addr>(name, Some(fake_host()), &fake).await);
        }
        assert_eq!(fake.queries.load(Ordering::SeqCst), names.len());
        assert!(fake.live_lists.lock().is_empty());
    }

    #[tokio::test]
    async fn dns_only_sends_the_own_name_to_dns() {
        let fake = Arc::new(FakeDnsBackend::with_mode(FakeMode::NameErrorSync));
        assert!(
            own_name_lookup::<Ipv4Addr>("DESKTOP-RAMA", None, &fake)
                .await
                .is_empty()
        );
        assert!(
            own_name_lookup::<Ipv6Addr>("DESKTOP-RAMA", None, &fake)
                .await
                .is_empty()
        );
        assert_eq!(fake.queries.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn local_hostname_setting_defaults_on_and_splits_sharing() {
        let resolver = WindowsDnsResolver::new();
        assert!(resolver.local_hostname());
        let dns_only = resolver.clone().with_local_hostname(false);
        assert!(!dns_only.local_hostname());
        assert!(!dns_only.in_flight.shares_with(&resolver.in_flight));
    }

    #[test]
    fn computer_name_match_ignores_case_and_one_root_dot() {
        let names: [Box<str>; 2] = ["".into(), "Desktop-Rama".into()];
        assert!(is_computer_name("desktop-rama", &names));
        assert!(is_computer_name("DESKTOP-RAMA.", &names));
        assert!(!is_computer_name("desktop-rama..", &names));
        assert!(!is_computer_name(".", &names));
        assert!(!is_computer_name("", &names));
        assert!(!is_computer_name("desktop-ram", &names));
    }

    /// A unicast address table as `GetUnicastIpAddressTable` lays it out.
    #[repr(C)]
    struct TestUnicastTable<const N: usize> {
        num_entries: u32,
        table: [ffi::MIB_UNICASTIPADDRESS_ROW; N],
    }

    fn table_row(
        ip: &str,
        skip_as_source: bool,
        dad_state: ffi::NL_DAD_STATE,
    ) -> ffi::MIB_UNICASTIPADDRESS_ROW {
        let mut row = ffi::MIB_UNICASTIPADDRESS_ROW::default();
        match ip.parse().expect("ip") {
            IpAddr::V4(ip) => {
                row.Address.Ipv4 = SOCKADDR_IN {
                    sin_family: ffi::AF_INET,
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(ip.octets()),
                        },
                    },
                    ..Default::default()
                }
            }
            IpAddr::V6(ip) => {
                row.Address.Ipv6 = SOCKADDR_IN6 {
                    sin6_family: ffi::AF_INET6,
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 { Byte: ip.octets() },
                    },
                    ..Default::default()
                }
            }
        }
        row.SkipAsSource = skip_as_source;
        row.DadState = dad_state;
        row
    }

    #[test]
    fn unicast_table_rows_are_read_in_order_and_filtered() {
        let preferred = ffi::IpDadStatePreferred;
        let table = TestUnicastTable::<9> {
            num_entries: 9,
            table: [
                table_row("192.0.2.10", false, preferred),
                // an unknown family is skipped
                ffi::MIB_UNICASTIPADDRESS_ROW::default(),
                table_row("2001:db8::10", false, preferred),
                table_row("192.0.2.11", true, preferred),
                table_row("192.0.2.12", false, IpDadStateTentative),
                table_row("127.0.0.1", false, preferred),
                table_row("fe80::1", false, preferred),
                table_row("::1", false, preferred),
                table_row("2001:db8::12", false, IpDadStateDeprecated),
            ],
        };
        assert_eq!(
            std::mem::offset_of!(TestUnicastTable<9>, table),
            std::mem::offset_of!(ffi::MIB_UNICASTIPADDRESS_TABLE, Table),
        );

        // SAFETY: the `table_rows` contract: `table` is a live, aligned local
        // laid out as the SDK table (offset checked above) with `num_entries`
        // initialized rows, and nothing writes it during the call.
        let rows = unsafe { local_host::table_rows((&raw const table).cast()) };
        let ips: Vec<String> = rows.iter().map(|row| row.ip.to_string()).collect();
        assert_eq!(
            ips,
            [
                "192.0.2.10",
                "2001:db8::10",
                "192.0.2.11",
                "192.0.2.12",
                "127.0.0.1",
                "fe80::1",
                "::1",
                "2001:db8::12",
            ]
        );
        assert!(rows[2].skip_as_source && !rows[0].skip_as_source);
        assert_eq!(rows[3].dad_state, IpDadStateTentative);

        let answered: Vec<IpAddr> = rows
            .iter()
            .filter(|row| row.answers_own_name())
            .map(|row| row.ip)
            .collect();
        assert_eq!(
            answered,
            [
                IpAddr::from(Ipv4Addr::new(192, 0, 2, 10)),
                "2001:db8::10".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "reads the computer name and addresses from the OS")]
    async fn own_host_name_resolves_like_getaddrinfo() {
        let name = local_host::computer_name(ffi::ComputerNameDnsHostname).expect("host name");
        // getaddrinfo answers no-longer-preferred rows too; this resolver does not
        let not_preferred: BTreeSet<IpAddr> = local_host::unicast_addresses()
            .expect("unicast table")
            .into_iter()
            .filter(|row| row.dad_state != ffi::IpDadStatePreferred)
            .map(|row| row.ip)
            .collect();
        let expected: BTreeSet<IpAddr> = (name.as_ref(), 0)
            .to_socket_addrs()
            .expect("getaddrinfo")
            .map(|addr| addr.ip())
            .filter(|ip| {
                !ip.is_loopback()
                    && !matches!(ip, IpAddr::V6(ip) if ip.is_unicast_link_local())
                    && !not_preferred.contains(ip)
            })
            .collect();
        assert!(
            !expected.is_empty(),
            "getaddrinfo has no address for {name}"
        );

        let resolver = WindowsDnsResolver::new();
        for name in [name.to_ascii_uppercase(), name.to_ascii_lowercase()] {
            let domain = Domain::try_from(name.clone()).expect("domain");
            let v4: Vec<_> = resolver.lookup_ipv4(domain.clone()).collect().await;
            let v6: Vec<_> = resolver.lookup_ipv6(domain).collect().await;
            let resolved: BTreeSet<IpAddr> = v4
                .into_iter()
                .map(|item| item.map(IpAddr::from))
                .chain(v6.into_iter().map(|item| item.map(IpAddr::from)))
                .collect::<Result<_, _>>()
                .expect("own-name lookup");
            assert_eq!(resolved, expected, "{name}");
        }
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore = "queries the DNS Client service")]
    async fn unknown_single_label_name_is_empty_before_the_timeout() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let domain = Domain::try_from(format!("rama-{nonce:x}")).expect("domain");
        let started = std::time::Instant::now();
        let addrs: Vec<_> = WindowsDnsResolver::new()
            .lookup_ipv4(domain)
            .collect()
            .await;
        let elapsed = started.elapsed();
        // DnsQueryEx waits about 1.3s for LLMNR and mDNS before its NXDOMAIN
        assert!(elapsed < DEFAULT_TIMEOUT, "took {elapsed:?}");
        assert!(addrs.is_empty(), "{addrs:?}");
    }

    #[test]
    #[ignore = "micro-benchmark: cargo test -p rama-dns --lib computer_name_check_cost -- --ignored --nocapture"]
    fn computer_name_check_cost() {
        const ITERATIONS: u32 = 10_000;
        let mut matched = 0_usize;
        let started = std::time::Instant::now();
        for _ in 0..ITERATIONS {
            let names = std::hint::black_box(local_host::computer_names());
            matched += usize::from(is_computer_name("rama-not-this-host", &names));
        }
        let uncached = started.elapsed() / ITERATIONS;
        let host = LocalHost::System;
        let started = std::time::Instant::now();
        for _ in 0..ITERATIONS {
            let names = std::hint::black_box(host.computer_names());
            matched += usize::from(is_computer_name("rama-not-this-host", &names));
        }
        let cached = started.elapsed() / ITERATIONS;
        eprintln!(
            "own-name check over {ITERATIONS} runs: {} ns/op reading 3 names (6 GetComputerNameExW calls), {} ns/op cached",
            uncached.as_nanos(),
            cached.as_nanos(),
        );
        assert_eq!(matched, 0);
    }
}
