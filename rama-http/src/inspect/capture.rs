use crate::{
    Body, BodyCaptureEvent, BodyCaptureSink, CaptureBody, CaptureOutcome, HeaderMap, Request,
    Response, StreamingBody,
    fingerprint::{AkamaiH2, Ja4H},
};
use crate::{Method, StatusCode, Version};
use parking_lot::{Mutex as SyncMutex, RwLock};
use rama_core::{
    Layer, Service,
    bytes::Bytes,
    error::{BoxError, ErrorContext as _},
    extensions::{Extension, Extensions},
    futures::{Stream, async_stream::stream_fn},
};
use rama_inspect::storage::{AppendRecord, Collection, CreateCollection, RecordId, Storage};
use rama_net::{Protocol, stream::SocketInfo};

use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering},
    },
};
use tokio::{
    io::AsyncReadExt as _,
    sync::{Mutex, watch},
};

#[cfg(test)]
use crate::body::util::BodyExt as _;

use super::control::{Control, ControlConnection};
use rama_inspect::InspectionState;

const MAX_CACHED_SEARCHES: usize = 16;

mod connection;
mod extension;
mod model;
mod observation;
mod query;
mod reading;
mod recording;
mod search;
pub use extension::{CapturedRecord, ExchangeCapture};
pub use observation::{CaptureMetadata, CaptureObserver, CaptureProtocol};

use model::contains_folded;
pub use model::{
    CaptureDetails, CaptureFilter, CaptureSnapshot, CapturedBody, ConnectionId, ConnectionSummary,
    ExchangeId, ExchangeSummary, IngressProtocol, ReplayRequest, StoredRecord,
};
#[cfg(test)]
use model::{matches_connection_id, matches_protocol, matches_status};

struct CapturedConnection {
    summary_template: ConnectionSummary,
    metadata: rama_inspect::Observations,
    akamai_h2: OnceLock<AkamaiH2>,
    display_id: OnceLock<u64>,
    ingress_protocol: RwLock<Protocol>,
    confirmed: AtomicBool,
    transport_finished: AtomicBool,
    active: AtomicBool,
    ended_at: OnceLock<jiff::Timestamp>,
    request_count: AtomicUsize,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

#[derive(Default)]
struct ConnectionExchangeState {
    active: bool,
    completed_at: Option<jiff::Timestamp>,
}

fn reconcile_connection_summary(
    summary: &mut ConnectionSummary,
    exchange_state: Option<&ConnectionExchangeState>,
) {
    let Some(exchange_state) = exchange_state else {
        return;
    };
    if exchange_state.active {
        summary.active = true;
        summary.ended_at = None;
    } else if !summary.active
        && let Some(completed_at) = &exchange_state.completed_at
    {
        summary.ended_at = Some(match summary.ended_at.take() {
            Some(ended_at) => std::cmp::max(ended_at, *completed_at),
            None => *completed_at,
        });
    }
}

impl CapturedConnection {
    fn snapshot(&self) -> ConnectionSummary {
        let mut summary = self.summary_template.clone();
        summary.display_id = self.display_id.get().copied().unwrap_or_default();
        summary
            .ingress_protocol
            .clone_from(&self.ingress_protocol.read());
        summary.active = self.active.load(Ordering::Relaxed);
        summary.ended_at.clone_from(&self.ended_at.get().cloned());
        summary.request_count = self.request_count.load(Ordering::Relaxed);
        summary.bytes_in = self.bytes_in.load(Ordering::Relaxed);
        summary.bytes_out = self.bytes_out.load(Ordering::Relaxed);
        summary.metadata = self.metadata.clone();
        summary.akamai_h2 = self.akamai_h2.get().cloned();
        summary
    }
}

struct CapturedExchange {
    decision: RwLock<Option<String>>,
    decision_count: AtomicUsize,
    summary_template: ExchangeSummary,
    connection: Option<Arc<CapturedConnection>>,
    status: AtomicU16,
    active: AtomicBool,
    upgraded: bool,
    upgrade_lifecycle_started: AtomicBool,
    response_started_at: OnceLock<jiff::Timestamp>,
    completed_at: OnceLock<jiff::Timestamp>,
    metadata: CaptureMetadata,
    request_bytes: AtomicU64,
    response_bytes: AtomicU64,
    request_truncated: AtomicBool,
    response_truncated: AtomicBool,
    extensions: Extensions,
    extension_records: RwLock<BTreeMap<std::any::TypeId, extension::RecordIndex>>,
    collection: Collection,
    append_lock: Mutex<()>,
    records: RwLock<Vec<RecordLocation>>,
    metadata_records: RwLock<Vec<RecordLocation>>,
    request_body_records: RwLock<Vec<RecordId>>,
    response_body_records: RwLock<Vec<RecordId>>,
    request_stored: AtomicU64,
    response_stored: AtomicU64,
    budget: Arc<CaptureBudget>,
    stored_bytes: AtomicU64,
    search_revision: AtomicU64,
}

impl Drop for CapturedExchange {
    fn drop(&mut self) {
        self.budget
            .release(self.stored_bytes.load(Ordering::Acquire));
    }
}

impl CapturedExchange {
    fn snapshot(&self) -> ExchangeSummary {
        let mut summary = self.summary_template.clone();
        summary.decision = self.decision.read().clone();
        if let Some(connection) = &self.connection {
            summary.connection_display_id =
                connection.display_id.get().copied().unwrap_or_default();
        }
        let status = self.status.load(Ordering::Relaxed);
        summary.status = StatusCode::from_u16(status).ok();
        summary.active = self.active.load(Ordering::Relaxed);
        summary
            .response_started_at
            .clone_from(&self.response_started_at.get().cloned());
        summary
            .completed_at
            .clone_from(&self.completed_at.get().cloned());

        summary.request_bytes = self.request_bytes.load(Ordering::Relaxed);
        summary.response_bytes = self.response_bytes.load(Ordering::Relaxed);
        summary.request_truncated = self.request_truncated.load(Ordering::Relaxed);
        summary.response_truncated = self.response_truncated.load(Ordering::Relaxed);
        summary
    }
}

fn saturating_add(counter: &AtomicU64, value: u64) {
    _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(value))
    });
}

fn reserve_capture_bytes(counter: &AtomicU64, limit: u64, amount: u64) -> bool {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let Some(next) = current.checked_add(amount).filter(|next| *next <= limit) else {
            return false;
        };
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

fn mark_capture_gap_entry(entry: &CapturedExchange, direction: BodyDirection) {
    match direction {
        BodyDirection::Request => entry.request_truncated.store(true, Ordering::Release),
        BodyDirection::Response => entry.response_truncated.store(true, Ordering::Release),
    }
}

fn successful_upgrade_response(entry: &CapturedExchange, status: u16) -> bool {
    if !entry.upgraded {
        return false;
    }
    match entry.summary_template.http_version {
        Version::HTTP_2 => (200..300).contains(&status),
        _ => status == 101,
    }
}

struct CaptureRegistry<T> {
    entries: BTreeMap<u64, Arc<T>>,
    order: VecDeque<u64>,
}

impl<T> Default for CaptureRegistry<T> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            order: VecDeque::new(),
        }
    }
}

struct CaptureStoreInner {
    control: Control,
    inspection: InspectionState,
    storage: Storage,
    next_connection_id: AtomicU64,
    next_display_connection_id: AtomicU64,
    next_exchange_id: AtomicU64,
    generation: AtomicU64,
    connections: RwLock<CaptureRegistry<CapturedConnection>>,
    exchanges: RwLock<CaptureRegistry<CapturedExchange>>,
    pending_exchanges: AtomicUsize,
    max_connections: usize,
    max_exchanges: usize,
    max_decisions: usize,
    body_limit: u64,
    budget: Arc<CaptureBudget>,
    changes: watch::Sender<u64>,
    search_caches: SyncMutex<SearchCaches>,
    observer: Arc<dyn CaptureObserver>,
    #[cfg(test)]
    append_test_hook: Mutex<Option<Arc<AppendTestHook>>>,
    #[cfg(test)]
    record_reads: AtomicUsize,
}

struct SearchCaches {
    entries: VecDeque<SearchCache>,
    max_results_per_query: usize,
}

struct SearchCache {
    needle: String,
    matches: BTreeMap<u64, (u64, bool)>,
}

impl SearchCaches {
    fn new(max_results_per_query: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            max_results_per_query,
        }
    }

    fn get(&self, needle: &str, exchange_id: u64, revision: u64) -> Option<bool> {
        self.entries
            .iter()
            .find(|cache| cache.needle == needle)
            .and_then(|cache| cache.matches.get(&exchange_id))
            .and_then(|(cached_revision, matched)| {
                (*cached_revision == revision).then_some(*matched)
            })
    }

    fn insert(&mut self, needle: &str, exchange_id: u64, revision: u64, matched: bool) {
        let index = self.entries.iter().position(|cache| cache.needle == needle);
        let new_cache = || SearchCache {
            needle: needle.to_owned(),
            matches: BTreeMap::new(),
        };
        let mut cache = match index {
            Some(index) => self.entries.remove(index).unwrap_or_else(new_cache),
            None => SearchCache {
                needle: needle.to_owned(),
                matches: BTreeMap::new(),
            },
        };
        cache.matches.insert(exchange_id, (revision, matched));
        while cache.matches.len() > self.max_results_per_query {
            cache.matches.pop_first();
        }
        self.entries.push_back(cache);
        if self.entries.len() > MAX_CACHED_SEARCHES {
            self.entries.pop_front();
        }
    }
}

struct CaptureBudget {
    /// Zero means unlimited. Production still uses a finite default; the
    /// escape hatch is useful for deliberate offline captures.
    limit: u64,
    used: AtomicU64,
}

impl CaptureBudget {
    fn try_reserve(self: &Arc<Self>, amount: u64) -> Option<CaptureBudgetReservation> {
        let mut used = self.used.load(Ordering::Acquire);
        loop {
            let next = used.checked_add(amount)?;
            if self.limit != 0 && next > self.limit {
                return None;
            }
            match self
                .used
                .compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    return Some(CaptureBudgetReservation {
                        budget: self.clone(),
                        amount,
                        committed: false,
                    });
                }
                Err(observed) => used = observed,
            }
        }
    }

    fn release(&self, amount: u64) {
        let previous = self.used.fetch_sub(amount, Ordering::AcqRel);
        debug_assert!(previous >= amount, "capture storage budget underflow");
    }
}

struct CaptureBudgetReservation {
    budget: Arc<CaptureBudget>,
    amount: u64,
    committed: bool,
}

impl CaptureBudgetReservation {
    fn commit(&mut self, entry: &CapturedExchange) {
        entry.stored_bytes.fetch_add(self.amount, Ordering::Release);
        self.committed = true;
    }
}

impl Drop for CaptureBudgetReservation {
    fn drop(&mut self) {
        if !self.committed {
            self.budget.release(self.amount);
        }
    }
}

#[derive(Clone)]
pub struct CaptureStore(Arc<CaptureStoreInner>);

#[derive(Debug, Clone, Copy)]
enum ConnectionWindow {
    Offset(usize),
    Before(Option<u64>),
}

pub struct CaptureConnectionGuard {
    store: CaptureStore,
    id: u64,
}

impl Drop for CaptureConnectionGuard {
    fn drop(&mut self) {
        self.store.finish_connection(self.id);
    }
}

#[derive(Extension)]
#[extension(tags(http))]
pub struct CaptureUpgradeGuard {
    store: CaptureStore,
    id: u64,
}

impl fmt::Debug for CaptureUpgradeGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaptureUpgradeGuard")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

pub struct CaptureHttpExchangeGuard {
    store: CaptureStore,
    id: u64,
    armed: bool,
}

impl CaptureHttpExchangeGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CaptureHttpExchangeGuard {
    fn drop(&mut self) {
        if self.armed {
            self.store.finish_http_exchange(self.id);
        }
    }
}

struct CaptureExchangeAdmission<'a> {
    pending: &'a AtomicUsize,
}

impl Drop for CaptureExchangeAdmission<'_> {
    fn drop(&mut self) {
        self.pending.fetch_sub(1, Ordering::Release);
    }
}

struct CaptureAppendGuard {
    entry: Arc<CapturedExchange>,
    direction: BodyDirection,
    committed: bool,
}

impl CaptureAppendGuard {
    fn new(entry: Arc<CapturedExchange>, direction: BodyDirection) -> Self {
        Self {
            entry,
            direction,
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for CaptureAppendGuard {
    fn drop(&mut self) {
        if !self.committed {
            mark_capture_gap_entry(&self.entry, self.direction);
        }
    }
}

#[cfg(test)]
#[derive(Default)]
struct AppendTestHook {
    reached: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}

impl Drop for CaptureUpgradeGuard {
    fn drop(&mut self) {
        self.store.finish_upgrade(self.id);
    }
}

/// A stable selection that retains its storage and can be read one exchange
/// at a time, without materializing every selected body in memory.
pub struct CaptureSelection {
    store: CaptureStore,
    entries: VecDeque<Arc<CapturedExchange>>,
}

impl CaptureSelection {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn next_capture(&mut self) -> Option<ExchangeCapture> {
        self.entries.pop_front().map(|entry| ExchangeCapture {
            store: self.store.clone(),
            entry,
        })
    }
    pub async fn next_details(&mut self) -> Result<Option<CaptureDetails>, BoxError> {
        let Some(entry) = self.entries.pop_front() else {
            return Ok(None);
        };
        self.store.details_for_entry(entry).await.map(Some)
    }
}

impl fmt::Debug for CaptureStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaptureStore")
            .field("inspection", &self.0.inspection)
            .field("max_connections", &self.0.max_connections)
            .field("max_exchanges", &self.0.max_exchanges)
            .field("body_limit", &self.0.body_limit)
            .field("total_limit", &self.0.budget.limit)
            .field("total_stored", &self.0.budget.used.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// Capture admission and optional metadata enrichment. Limits count logical
/// serialized record bytes; a storage backend can independently limit physical bytes.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub max_connections: usize,
    pub max_exchanges: usize,
    pub body_limit: u64,
    pub total_limit: u64,
    pub observer: Arc<dyn CaptureObserver>,
}
impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            max_exchanges: 4096,
            body_limit: rama_utils::octets::mib_u64(1),
            total_limit: rama_utils::octets::mib_u64(256),
            observer: Arc::new(()),
        }
    }
}

impl CaptureStore {
    /// Assemble an inspector with caller-selected storage and a shared pause boundary.
    pub fn with_storage(
        storage: Storage,
        config: CaptureConfig,
        inspection: InspectionState,
    ) -> Self {
        let CaptureConfig {
            max_connections,
            max_exchanges,
            body_limit,
            total_limit,
            observer,
        } = config;
        let (changes, _) = watch::channel(0);
        Self(Arc::new(CaptureStoreInner {
            control: Control::new(inspection.clone()),
            inspection,
            storage,
            next_connection_id: AtomicU64::new(1),
            next_display_connection_id: AtomicU64::new(1),
            next_exchange_id: AtomicU64::new(1),
            generation: AtomicU64::new(0),
            connections: RwLock::new(CaptureRegistry::default()),
            exchanges: RwLock::new(CaptureRegistry::default()),
            pending_exchanges: AtomicUsize::new(0),
            max_connections: max_connections.max(1),
            max_exchanges: max_exchanges.max(1),
            max_decisions: 4096,
            body_limit,
            budget: Arc::new(CaptureBudget {
                limit: total_limit,
                used: AtomicU64::new(0),
            }),
            changes,
            search_caches: SyncMutex::new(SearchCaches::new(max_exchanges.max(1))),
            observer,
            #[cfg(test)]
            append_test_hook: Mutex::new(None),
            #[cfg(test)]
            record_reads: AtomicUsize::new(0),
        }))
    }

    pub fn control(&self) -> Control {
        self.0.control.clone()
    }

    pub fn new_control_connection(&self) -> ControlConnection {
        ControlConnection::new(self.0.next_connection_id.fetch_add(1, Ordering::Relaxed))
    }

    pub fn begin_observed_connection(
        &self,
        id: u64,
        socket: Option<SocketInfo>,
        ingress: Protocol,
    ) -> Option<u64> {
        let _permit = self.0.inspection.try_capture()?;
        self.begin_connection_labeled_inner(socket, ingress, None, true, Some(id))
    }

    pub fn inspection_state(&self) -> InspectionState {
        self.0.inspection.clone()
    }

    /// Subscribe directly to initial and updated capture content. Body bytes remain
    /// independently streamable through `body_stream`, so lists stay lightweight.
    pub fn subscribe(
        &self,
        query: CaptureQuery,
    ) -> impl Stream<Item = CaptureSnapshot> + Send + 'static {
        use rama_core::futures::StreamExt;
        rama_inspect::subscription::subscribe(self.subscribe_changes(), self.clone(), query).map(
            |result| match result {
                Ok(value) => value,
                Err(never) => match never {},
            },
        )
    }
    pub fn subscribe_changes(&self) -> watch::Receiver<u64> {
        self.0.changes.subscribe()
    }

    fn changed(&self) {
        self.0
            .changes
            .send_modify(|version| *version = version.wrapping_add(1));
    }

    pub fn connection_display_id(&self, id: u64) -> Option<u64> {
        self.0
            .connections
            .read()
            .entries
            .get(&id)?
            .display_id
            .get()
            .copied()
    }

    pub fn connection_summary(&self, id: u64) -> Option<ConnectionSummary> {
        let mut summary = self
            .0
            .connections
            .read()
            .entries
            .get(&id)
            .filter(|connection| connection.confirmed.load(Ordering::Relaxed))
            .map(|connection| connection.snapshot())?;
        let states = self.connection_exchange_states();
        reconcile_connection_summary(&mut summary, states.get(&id));
        Some(summary)
    }

    fn connection_exchange_states(&self) -> BTreeMap<u64, ConnectionExchangeState> {
        let exchanges = self.0.exchanges.read();
        let mut states = BTreeMap::<u64, ConnectionExchangeState>::new();
        for exchange in exchanges.entries.values() {
            let state = states
                .entry(exchange.summary_template.connection_id)
                .or_default();
            state.active |= exchange.active.load(Ordering::Relaxed);
            if let Some(completed_at) = exchange.completed_at.get() {
                state.completed_at = Some(match state.completed_at.take() {
                    Some(latest) => std::cmp::max(latest, *completed_at),
                    None => *completed_at,
                });
            }
        }
        states
    }

    pub fn selected_exchange_ids(
        &self,
        request_ids: &BTreeSet<u64>,
        connection_ids: &BTreeSet<u64>,
    ) -> BTreeSet<u64> {
        self.0
            .exchanges
            .read()
            .entries
            .values()
            .filter_map(|entry| {
                let summary = &entry.summary_template;
                (request_ids.contains(&summary.id)
                    || connection_ids.contains(&summary.connection_id))
                .then_some(summary.id)
            })
            .collect()
    }

    pub fn selected_exchanges(
        &self,
        request_ids: &BTreeSet<u64>,
        connection_ids: &BTreeSet<u64>,
    ) -> CaptureSelection {
        let entries = self
            .0
            .exchanges
            .read()
            .entries
            .values()
            .filter(|entry| {
                let summary = &entry.summary_template;
                request_ids.contains(&summary.id) || connection_ids.contains(&summary.connection_id)
            })
            .cloned()
            .collect();
        CaptureSelection {
            store: self.clone(),
            entries,
        }
    }
}

#[derive(Clone, Copy)]
struct RecordLocation {
    id: RecordId,
    body: Option<CapturedBody>,
}

async fn read_record_at(
    collection: &Collection,
    location: RecordLocation,
) -> Result<StoredRecord, BoxError> {
    let mut reader = collection.read(location.id).await?;
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .await
        .context("read capture record")?;
    match location.body {
        Some(CapturedBody::Request) => Ok(StoredRecord::RequestBody { data: bytes.into() }),
        Some(CapturedBody::Response) => Ok(StoredRecord::ResponseBody { data: bytes.into() }),
        None => serde_json::from_slice(&bytes).context("decode capture record"),
    }
}

fn is_upgrade_request(parts: &crate::request::Parts) -> bool {
    match parts.version {
        Version::HTTP_10 | Version::HTTP_11 => parts.headers.contains_key(crate::header::UPGRADE),
        Version::HTTP_2 => {
            parts.method == Method::CONNECT
                && parts
                    .extensions
                    .contains::<crate::proto::h2::ext::Protocol>()
        }
        _ => false,
    }
}

fn records_match_search(records: &[StoredRecord], needle: &str) -> bool {
    records.iter().any(|record| match record {
        StoredRecord::RequestBody { data } | StoredRecord::ResponseBody { data } => {
            search::matches_display(&rama_utils::fmt::utf8_or_hex(data), needle)
        }
        StoredRecord::RequestHead {
            method,
            url,
            version,
            headers,
        } => {
            search::matches_display(&format_args!("{method} {url} {version}"), needle)
                || headers.iter().any(|(name, value)| {
                    search::matches_display(
                        &format_args!("{name}: {}", rama_utils::fmt::utf8_or_hex(value.as_bytes())),
                        needle,
                    )
                })
        }
        StoredRecord::ResponseHead {
            status,
            version,
            headers,
        } => {
            search::matches_display(&format_args!("{status} {version}"), needle)
                || headers.iter().any(|(name, value)| {
                    search::matches_display(
                        &format_args!("{name}: {}", rama_utils::fmt::utf8_or_hex(value.as_bytes())),
                        needle,
                    )
                })
        }
        StoredRecord::RequestTrailers { headers } | StoredRecord::ResponseTrailers { headers } => {
            headers.iter().any(|(name, value)| {
                search::matches_display(
                    &format_args!("{name}: {}", rama_utils::fmt::utf8_or_hex(value.as_bytes())),
                    needle,
                )
            })
        }
        StoredRecord::Interception {
            outcome,
            original_payload,
            ..
        } => {
            contains_folded(outcome, needle)
                || original_payload
                    .as_ref()
                    .is_some_and(|value| search::matches_display(value, needle))
        }
        _ => false,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyDirection {
    Request,
    Response,
}

mod service;

pub use service::{CaptureHttpLayer, MarkProtocolLayer, ObserveConnectionLayer};

#[cfg(test)]
#[path = "capture/tests/mod.rs"]
mod tests;

/// A bounded view suitable for an API, native GUI, or TUI. A cursor pages older connections.
#[derive(Debug, Clone)]
pub struct CaptureQuery {
    pub filter: CaptureFilter,
    pub selected_connections: BTreeSet<u64>,
    pub before_connection_id: Option<u64>,
    pub connection_limit: usize,
    pub exchange_limit: usize,
}
impl Default for CaptureQuery {
    fn default() -> Self {
        Self {
            filter: CaptureFilter::default(),
            selected_connections: BTreeSet::new(),
            before_connection_id: None,
            connection_limit: 100,
            exchange_limit: 1000,
        }
    }
}
impl Service<CaptureQuery> for CaptureStore {
    type Output = CaptureSnapshot;
    type Error = std::convert::Infallible;
    async fn serve(&self, query: CaptureQuery) -> Result<Self::Output, Self::Error> {
        Ok(self
            .snapshot_limited_before_connection(
                &query.filter,
                &query.selected_connections,
                query.before_connection_id,
                query.connection_limit,
                query.exchange_limit,
            )
            .await)
    }
}
