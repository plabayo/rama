//! Windows-native DNS resolver backed by `DnsQueryEx` from `Dnsapi.dll`.

use std::collections::VecDeque;
use std::ffi::c_void;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rama_core::bytes::Bytes;
use rama_core::error::BoxError;
use rama_core::futures::{Stream, async_stream::stream_fn};
use rama_core::telemetry::tracing;
use rama_net::address::Domain;
use rama_utils::macros::generate_set_and_with;
use rama_utils::str::arcstr::ArcStr;

use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio::time::Instant;
use windows_sys::Win32::Foundation::ERROR_CANCELLED;
use windows_sys::core::PCWSTR;

use super::resolver::{DnsAddressResolver, DnsResolver, DnsTxtResolver};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Windows-native [`DnsResolver`] implementation using `DnsQueryEx`.
pub struct WindowsDnsResolver {
    timeout: Duration,
}

impl Default for WindowsDnsResolver {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
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
        pub fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }
    }
}

impl DnsAddressResolver for WindowsDnsResolver {
    type Error = BoxError;

    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        query_record_stream(domain, self.timeout, ffi::DNS_TYPE_A, parse_a_records)
    }

    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        query_record_stream(domain, self.timeout, ffi::DNS_TYPE_AAAA, parse_aaaa_records)
    }
}

impl DnsTxtResolver for WindowsDnsResolver {
    type Error = BoxError;

    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_ {
        query_record_stream(domain, self.timeout, ffi::DNS_TYPE_TEXT, parse_txt_records)
    }
}

impl DnsResolver for WindowsDnsResolver {}

fn query_record_stream<T, P>(
    domain: Domain,
    timeout: Duration,
    rrtype: u16,
    parser: P,
) -> impl Stream<Item = Result<T, BoxError>> + Send
where
    T: fmt::Debug + Send + 'static,
    P: Fn(*mut ffi::DnsRecord, &mut dyn FnMut(T)) -> Result<(), BoxError> + Send + Sync + 'static,
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

        if let Err(err) = start_query(&state, name, rrtype) {
            yielder.yield_item(Err(err)).await;
            return;
        }

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
                state.timed_out.store(true, Ordering::SeqCst);
                request_cancel(&state);
            }

            match tokio::time::timeout_at(deadline, state.notify.notified()).await {
                Ok(()) => {}
                Err(err) => {
                    tracing::trace!("windows query record stream: timeout reached: {err}");
                    state.timed_out.store(true, Ordering::SeqCst);
                    request_cancel(&state);
                }
            }
        }

        for item in drain_queue(&state) {
            yielder.yield_item(item).await;
        }
    })
}

fn start_query<T, P>(
    state: &Arc<QueryState<T, P>>,
    name: Vec<u16>,
    rrtype: u16,
) -> Result<(), BoxError>
where
    T: fmt::Debug + Send + 'static,
    P: Fn(*mut ffi::DnsRecord, &mut dyn FnMut(T)) -> Result<(), BoxError> + Send + Sync + 'static,
{
    let context = Arc::into_raw(state.clone()) as *mut c_void;
    let mut inflight = Box::new(InFlightQuery::new(name, rrtype, context));
    inflight.request.query_completion_callback = Some(query_completion_callback::<T, P>);

    // SAFETY:
    // - `inflight` lives in stable boxed storage until completion.
    // - request/result/cancel pointers remain valid while the query is in flight.
    // - callback ABI/signature match the Windows API contract.
    let status = unsafe {
        ffi::DnsQueryEx(
            &inflight.request,
            &mut inflight.result,
            &mut inflight.cancel,
        )
    };

    if status == ffi::DNS_REQUEST_PENDING {
        *state.inflight.lock() = Some(inflight);
        return Ok(());
    }

    // The callback will not run for the synchronous path, so reclaim the extra Arc.
    // SAFETY: `context` came from `Arc::into_raw(state.clone())` immediately above.
    unsafe {
        drop(Arc::from_raw(context.cast::<QueryState<T, P>>()));
    }

    handle_query_result(state, &mut inflight.result, status);
    Ok(())
}

fn request_cancel<T, P>(state: &Arc<QueryState<T, P>>) {
    if state.cancel_requested.swap(true, Ordering::SeqCst) {
        return;
    }

    if let Some(query) = state.inflight.lock().as_mut() {
        // SAFETY: the query owns a live cancel handle initialized by `DnsQueryEx`.
        unsafe {
            ffi::DnsCancelQuery(&mut query.cancel);
        }
    }
}

fn drain_queue<T, P>(state: &QueryState<T, P>) -> Vec<Result<T, BoxError>> {
    state.queue.lock().drain(..).collect()
}

fn handle_query_result<T, P>(
    state: &Arc<QueryState<T, P>>,
    result: &mut ffi::DNS_QUERY_RESULT,
    call_status: u32,
) where
    T: fmt::Debug + Send + 'static,
    P: Fn(*mut ffi::DnsRecord, &mut dyn FnMut(T)) -> Result<(), BoxError> + Send + Sync + 'static,
{
    let query_status = if result.query_status == 0 {
        call_status
    } else {
        result.query_status
    };

    if state.suppress_results.load(Ordering::SeqCst) {
        cleanup_result(result);
        mark_done(state);
        return;
    }

    if state.timed_out.load(Ordering::SeqCst) && query_status == ERROR_CANCELLED {
        state
            .queue
            .lock()
            .push_back(Err(WindowsDnsResolverError::timeout(state.timeout).into()));
        cleanup_result(result);
        mark_done(state);
        return;
    }

    if matches!(
        query_status,
        ffi::ERROR_SUCCESS | ffi::DNS_INFO_NO_RECORDS | ffi::DNS_ERROR_RCODE_NAME_ERROR
    ) {
        if query_status == ffi::ERROR_SUCCESS && !result.query_records.is_null() {
            let mut emit_record = |record| {
                tracing::debug!("dns::windows: answer: {record:?}");
                state.queue.lock().push_back(Ok(record));
            };

            if let Err(err) = (state.parser)(result.query_records, &mut emit_record) {
                state.queue.lock().push_back(Err(err));
            }
        }

        cleanup_result(result);
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
    cleanup_result(result);
    mark_done(state);
}

fn cleanup_result(result: &mut ffi::DNS_QUERY_RESULT) {
    if !result.query_records.is_null() {
        // SAFETY: the returned record list is owned by the query result until freed.
        unsafe {
            ffi::DnsRecordListFree(result.query_records.cast(), ffi::DNS_FREE_RECORD_LIST);
        }
        result.query_records = ptr::null_mut();
    }
}

fn mark_done<T, P>(state: &Arc<QueryState<T, P>>) {
    state.done.store(true, Ordering::SeqCst);
    let _ = state.inflight.lock().take();
    state.notify.notify_waiters();
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

fn parse_a_records(
    records: *mut ffi::DnsRecord,
    emit: &mut dyn FnMut(Ipv4Addr),
) -> Result<(), BoxError> {
    walk_records(records, ffi::DNS_TYPE_A, |record| {
        // SAFETY: `record` is a live DNS_RECORD of type A while walking the list.
        let addr = unsafe { u32::from_be(record.data.a.ip_address) };
        emit(Ipv4Addr::from(addr));
        Ok(())
    })
}

fn parse_aaaa_records(
    records: *mut ffi::DnsRecord,
    emit: &mut dyn FnMut(Ipv6Addr),
) -> Result<(), BoxError> {
    walk_records(records, ffi::DNS_TYPE_AAAA, |record| {
        // SAFETY: `record` is a live DNS_RECORD of type AAAA while walking the list.
        let octets = unsafe { record.data.aaaa.ip6_address.ip6_byte };
        emit(Ipv6Addr::from(octets));
        Ok(())
    })
}

fn parse_txt_records(
    records: *mut ffi::DnsRecord,
    emit: &mut dyn FnMut(Bytes),
) -> Result<(), BoxError> {
    walk_records(records, ffi::DNS_TYPE_TEXT, |record| {
        // SAFETY: `record` is a live DNS_RECORD of type TXT while walking the list.
        let txt = unsafe { &record.data.txt };
        for idx in 0..txt.string_count as usize {
            let ptr = unsafe { *txt.strings.as_ptr().add(idx) };
            if ptr.is_null() {
                continue;
            }
            let value = wide_ptr_to_string(ptr);
            emit(Bytes::from(value));
        }
        Ok(())
    })
}

fn walk_records<F>(
    mut record: *mut ffi::DnsRecord,
    rrtype: u16,
    mut visit: F,
) -> Result<(), BoxError>
where
    F: FnMut(&ffi::DnsRecord) -> Result<(), BoxError>,
{
    while !record.is_null() {
        // SAFETY: `record` is a valid node in the linked list while iterating.
        let current = unsafe { &*record };
        if current.record_type == rrtype {
            visit(current)?;
        }
        record = current.next;
    }
    Ok(())
}

fn wide_ptr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }

    let mut len = 0;
    // SAFETY: callers only pass pointers originating from the Windows DNS API
    // record list for the lifetime of the parsing call.
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
}

struct QueryState<T, P> {
    queue: Mutex<VecDeque<Result<T, BoxError>>>,
    done: AtomicBool,
    timeout: Duration,
    timed_out: AtomicBool,
    suppress_results: AtomicBool,
    cancel_requested: AtomicBool,
    notify: Notify,
    inflight: Mutex<Option<Box<InFlightQuery>>>,
    parser: P,
}

struct QueryCancelGuard<T, P> {
    state: Arc<QueryState<T, P>>,
}

impl<T, P> Drop for QueryCancelGuard<T, P> {
    fn drop(&mut self) {
        if self.state.done.load(Ordering::SeqCst) {
            return;
        }

        request_cancel(&self.state);
        self.state.suppress_results.store(true, Ordering::SeqCst);
    }
}

struct InFlightQuery {
    request: ffi::DNS_QUERY_REQUEST,
    result: ffi::DNS_QUERY_RESULT,
    cancel: ffi::DNS_QUERY_CANCEL,
    name: Vec<u16>,
}

impl InFlightQuery {
    fn new(name: Vec<u16>, rrtype: u16, context: *mut c_void) -> Self {
        let request = ffi::DNS_QUERY_REQUEST {
            version: ffi::DNS_QUERY_REQUEST_VERSION1,
            query_name: ptr::null(),
            query_type: rrtype,
            query_options: ffi::DNS_QUERY_STANDARD,
            dns_server_list: ptr::null_mut(),
            interface_index: 0,
            query_completion_callback: None,
            query_context: context,
        };

        let result = ffi::DNS_QUERY_RESULT {
            version: ffi::DNS_QUERY_RESULTS_VERSION1,
            query_status: 0,
            query_options: 0,
            query_records: ptr::null_mut(),
            reserved: ptr::null_mut(),
        };

        let cancel = ffi::DNS_QUERY_CANCEL { reserved: [0; 32] };

        let mut inflight = Self {
            request,
            result,
            cancel,
            name,
        };
        inflight.request.query_name = inflight.name.as_ptr();
        inflight
    }
}

// SAFETY: the in-flight query is only accessed under a mutex and by the owning
// Windows callback/query lifecycle.
unsafe impl Send for InFlightQuery {}

impl Drop for InFlightQuery {
    fn drop(&mut self) {
        cleanup_result(&mut self.result);
    }
}

unsafe extern "system" fn query_completion_callback<T, P>(
    query_context: *mut c_void,
    query_result: *mut ffi::DNS_QUERY_RESULT,
) where
    T: fmt::Debug + Send + 'static,
    P: Fn(*mut ffi::DnsRecord, &mut dyn FnMut(T)) -> Result<(), BoxError> + Send + Sync + 'static,
{
    if query_context.is_null() {
        return;
    }

    // SAFETY: the context is created with `Arc::into_raw(state.clone())` when the
    // query starts and must be reconstructed exactly once in the callback path.
    let state = unsafe { Arc::from_raw(query_context.cast::<QueryState<T, P>>()) };

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

    // SAFETY: the callback contract guarantees the pointer is valid for the duration
    // of the callback.
    let result = unsafe { &mut *query_result };
    handle_query_result(&state, result, result.query_status);

    if let Some(mut inflight) = state.inflight.lock().take() {
        cleanup_result(&mut inflight.result);
    }
}

#[derive(Debug)]
struct WindowsDnsResolverError(ArcStr);

impl WindowsDnsResolverError {
    fn message(message: impl Into<ArcStr>) -> Self {
        Self(message.into())
    }

    fn timeout(timeout: Duration) -> Self {
        Self::message(format!("windows dns query timed out after {timeout:?}"))
    }

    fn dns_status(operation: &str, status: u32) -> Self {
        Self::message(format!("{operation} failed with DNS status {status}"))
    }
}

impl fmt::Display for WindowsDnsResolverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WindowsDnsResolverError {}

mod ffi {
    use super::*;

    // Official docs index for DNS structures and functions:
    // <https://learn.microsoft.com/en-us/windows/win32/dns/dns-structures>
    // <https://learn.microsoft.com/en-us/windows/win32/api/windns/>

    pub(super) const ERROR_SUCCESS: u32 = 0;
    pub(super) const DNS_REQUEST_PENDING: u32 = 9506;
    pub(super) const DNS_INFO_NO_RECORDS: u32 = 9501;
    pub(super) const DNS_ERROR_RCODE_NAME_ERROR: u32 = 9003;

    pub(super) const DNS_TYPE_A: u16 = 1;
    pub(super) const DNS_TYPE_TEXT: u16 = 16;
    pub(super) const DNS_TYPE_AAAA: u16 = 28;

    pub(super) const DNS_QUERY_STANDARD: u64 = 0;
    pub(super) const DNS_QUERY_REQUEST_VERSION1: u32 = 1;
    pub(super) const DNS_QUERY_RESULTS_VERSION1: u32 = 1;

    pub(super) const DNS_FREE_RECORD_LIST: DnsFreeType = 1;

    pub(super) type DnsFreeType = u32;
    pub(super) type PdnsQueryCompletionRoutine =
        Option<unsafe extern "system" fn(*mut c_void, *mut DNS_QUERY_RESULT)>;

    /// DNS_QUERY_REQUEST:
    /// Official docs:
    /// <https://learn.microsoft.com/en-us/windows/win32/api/windns/ns-windns-dns_query_request>
    /// Rust projection reference:
    /// <https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/NetworkManagement/Dns/struct.DNS_QUERY_REQUEST.html>
    #[repr(C)]
    pub(super) struct DNS_QUERY_REQUEST {
        /// The structure version must be one of the following:
        /// - [`DNS_QUERY_REQUEST_VERSION1`]
        pub(super) version: u32,
        /// A pointer to a string that represents the DNS name to query.
        ///
        /// ## Note
        ///
        /// If QueryName is NULL, the query is for the local machine name.
        pub(super) query_name: PCWSTR,
        /// A value that represents the Resource Record (RR) DNS Record Type
        /// that is queried. QueryType determines the format of data pointed to by
        /// pQueryRecords returned in the [`DNS_QUERY_RESULT`] structure.
        ///
        /// For example, if the value of wType is [`DNS_TYPE_A`],
        /// the format of data pointed to by pQueryRecords is [`DNS_A_DATA`].
        pub(super) query_type: u16,
        /// A value that contains a bitmap of DNS Query Options to use in the DNS query.
        /// Options can be combined and all options override [`DNS_QUERY_STANDARD`].
        ///
        /// See for more info:
        /// <https://learn.microsoft.com/en-us/windows/desktop/DNS/dns-constants>
        pub(super) query_options: u64,
        /// A pointer to a DNS_ADDR_ARRAY structure that
        /// contains a list of DNS servers to use in the query.
        ///
        /// See for more info:
        /// <https://learn.microsoft.com/en-us/windows/win32/api/windnsdef/ns-windnsdef-dns_addr_array>
        pub(super) dns_server_list: *mut c_void,
        /// A value that contains the interface index over which the query is sent.
        /// If InterfaceIndex is 0, all interfaces will be considered.
        pub(super) interface_index: u32,
        /// A pointer to a DNS_QUERY_COMPLETION_ROUTINE callback that is used to
        /// return the results of an asynchronous query from a call to [`DnsQueryEx`].
        ///
        /// ## Note
        ///
        /// If NULL, [`DnsQueryEx`] is called synchronously.
        pub(super) query_completion_callback: PdnsQueryCompletionRoutine,
        /// A pointer to a user context.
        pub(super) query_context: *mut c_void,
    }

    /// DNS_QUERY_RESULT:
    /// Official docs:
    /// <https://learn.microsoft.com/en-us/windows/win32/api/windns/ns-windns-dns_query_result>
    #[repr(C)]
    pub(super) struct DNS_QUERY_RESULT {
        /// The structure version must be one of the following:
        /// - [`DNS_QUERY_REQUEST_VERSION1`]
        pub(super) version: u32,
        /// The return status of the call to [`DnsQueryEx`].
        ///
        /// If the query was completed asynchronously and this structure was
        /// returned directly from DnsQueryEx, QueryStatus contains [`DNS_REQUEST_PENDING`].
        ///
        /// If the query was completed synchronously or if this structure was
        /// returned by the DNS_QUERY_COMPLETION_ROUTINE DNS callback,
        /// QueryStatus contains ERROR_SUCCESS if successful or the appropriate
        /// DNS-specific error code as defined in Winerror.h.
        ///
        /// See for more information:
        /// <https://learn.microsoft.com/en-us/windows/desktop/api/windns/nc-windns-dns_query_completion_routine>
        pub(super) query_status: u32,
        /// A value that contains a bitmap of DNS Query Options that were used in the DNS query.
        /// Options can be combined and all options override DNS_QUERY_STANDARD
        ///
        /// See for more information:
        /// <https://learn.microsoft.com/en-us/windows/desktop/DNS/dns-constants>
        pub(super) query_options: u64,
        /// pointer to a DNS_RECORD structure.
        ///
        /// If the query was completed asynchronously and this structure was
        /// returned directly from [`DnsQueryEx`], pQueryRecords is NULL.
        ///
        /// If the query was completed synchronously or if this structure was returned
        /// by the DNS_QUERY_COMPLETION_ROUTINE DNS callback, pQueryRecords contains
        /// a list of Resource Records (RR) that comprise the response.
        ///
        /// See for more information:
        /// <https://learn.microsoft.com/en-us/windows/desktop/api/windns/nc-windns-dns_query_completion_routine>
        ///
        /// ## Note
        ///
        /// Applications must free returned RR sets with the [`DnsRecordListFree`] function.
        pub(super) query_records: *mut DnsRecord,
        /// ¯\_(ツ)_/¯
        pub(super) reserved: *mut c_void,
    }

    /// DNS_QUERY_CANCEL:
    /// Official docs:
    /// <https://learn.microsoft.com/en-us/windows/win32/api/windns/ns-windns-dns_query_cancel>
    #[repr(C)]
    pub(super) struct DNS_QUERY_CANCEL {
        /// ¯\_(ツ)_/¯
        pub(super) reserved: [usize; 32],
    }

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
        /// The DNS RR data type is determined by wType.
        pub(super) data: DnsRecordData,
    }

    /// DNS_RECORDW::Data union subset used by this backend.
    #[repr(C)]
    pub(super) union DnsRecordData {
        pub(super) a: DNS_A_DATA,
        pub(super) aaaa: DNS_AAAA_DATA,
        pub(super) txt: DNS_TXT_DATAW,
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

    #[link(name = "Dnsapi")]
    unsafe extern "system" {
        /// DnsQueryEx:
        /// Official docs:
        /// <https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsqueryex>
        /// Rust projection reference:
        /// <https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/NetworkManagement/Dns/fn.DnsQueryEx.html>
        pub(super) fn DnsQueryEx(
            // A pointer to a DNS_QUERY_REQUEST or DNS_QUERY_REQUEST3 structure
            // that contains the query request information.
            //
            // ## Note
            //
            // By omitting the DNS_QUERY_COMPLETION_ROUTINE callback from
            // the pQueryCompleteCallback member of this structure,
            // DnsQueryEx is called synchronously.
            query_request: *const DNS_QUERY_REQUEST,
            // A pointer to a DNS_QUERY_RESULT structure that contains
            // the results of the query. On input,
            // the version member of pQueryResults must be [`DNS_QUERY_RESULTS_VERSION1`]
            // and all other members should be NULL. On output, the remaining members
            // will be filled as part of the query complete
            query_result: *mut DNS_QUERY_RESULT,
            // A pointer to a DNS_QUERY_CANCEL structure tha
            // can be used to cancel a pending asynchronous query.
            //
            // ## Note
            //
            // An application should not free this structure until
            // the DNS_QUERY_COMPLETION_ROUTINE callback is invoked.
            cancel_handle: *mut DNS_QUERY_CANCEL,
        ) -> u32;

        /// DnsCancelQuery:
        /// Official docs:
        /// <https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnscancelquery>
        pub(super) fn DnsCancelQuery(cancel_handle: *mut DNS_QUERY_CANCEL);

        /// DnsRecordListFree:
        /// Official docs:
        /// <https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsrecordlistfree>
        pub(super) fn DnsRecordListFree(record_list: *mut c_void, free_type: DnsFreeType);
    }
}
