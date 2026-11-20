use arc_swap::ArcSwapOption;
use parking_lot::Mutex;
use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    futures::{
        Stream,
        stream::{BoxStream, Select, select},
    },
    telemetry::tracing::warn,
};
use rama_crypto::{
    native_certs::{NativeCertsChanges, load_reloadable_native_certs},
    pki_types::CertificateDer,
};
use std::{
    error::Error,
    fmt,
    hash::{Hash, Hasher},
    pin::Pin,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// Turn a stream or a tuple of streams into native TLS trust refresh events.
/// Each item requests a refresh. Tuples combine two to four streams.
pub trait IntoNativeTrustReloadTrigger<Kind> {
    /// The stream produced by this source.
    type Stream: Stream<Item = ()> + Send + 'static;

    /// Combine these sources into one stream of refresh requests.
    fn into_reload_stream(self) -> Self::Stream;
}

impl<S> IntoNativeTrustReloadTrigger<()> for S
where
    S: Stream<Item = ()> + Send + 'static,
{
    type Stream = S;

    fn into_reload_stream(self) -> Self::Stream {
        self
    }
}

impl<A, B, KA, KB> IntoNativeTrustReloadTrigger<(KA, KB)> for (A, B)
where
    A: IntoNativeTrustReloadTrigger<KA>,
    B: IntoNativeTrustReloadTrigger<KB>,
{
    type Stream = Select<A::Stream, B::Stream>;

    fn into_reload_stream(self) -> Self::Stream {
        select(self.0.into_reload_stream(), self.1.into_reload_stream())
    }
}

impl<A, B, C, KA, KB, KC> IntoNativeTrustReloadTrigger<(KA, KB, KC)> for (A, B, C)
where
    A: IntoNativeTrustReloadTrigger<KA>,
    B: IntoNativeTrustReloadTrigger<KB>,
    C: IntoNativeTrustReloadTrigger<KC>,
{
    type Stream = Select<A::Stream, Select<B::Stream, C::Stream>>;

    fn into_reload_stream(self) -> Self::Stream {
        (self.0, (self.1, self.2)).into_reload_stream()
    }
}

impl<A, B, C, D, KA, KB, KC, KD> IntoNativeTrustReloadTrigger<(KA, KB, KC, KD)> for (A, B, C, D)
where
    A: IntoNativeTrustReloadTrigger<KA>,
    B: IntoNativeTrustReloadTrigger<KB>,
    C: IntoNativeTrustReloadTrigger<KC>,
    D: IntoNativeTrustReloadTrigger<KD>,
{
    type Stream = Select<Select<A::Stream, B::Stream>, Select<C::Stream, D::Stream>>;

    fn into_reload_stream(self) -> Self::Stream {
        ((self.0, self.1), (self.2, self.3)).into_reload_stream()
    }
}

/// Requests a refresh after the operating system's native trust store changes.
///
/// On macOS and Windows this uses system change notifications. File-backed
/// stores, including SSL_CERT_FILE, SSL_CERT_DIR and the corresponding
/// SSL_CERT_EXTRA_* settings, are checked using file metadata.
pub struct NativeTrustStoreChanges {
    interval: Duration,
    worker: Option<NativeChangesWorker>,
}

impl NativeTrustStoreChanges {
    /// Set the file metadata polling interval, with a minimum of 10 ms.
    ///
    /// The first poll starts a monitor thread. Once its initial probe completes
    /// it asks the next handshake to recheck trust. Dropping the stream stops
    /// its monitor.
    pub const fn new(interval: Duration) -> Self {
        Self {
            interval,
            worker: None,
        }
    }
}

impl Default for NativeTrustStoreChanges {
    fn default() -> Self {
        Self::new(Duration::from_secs(60))
    }
}

impl Stream for NativeTrustStoreChanges {
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<()>> {
        let interval = self.interval;
        let worker = self
            .worker
            .get_or_insert_with(|| NativeChangesWorker::new(interval));
        Pin::new(&mut worker.events).poll_next(cx)
    }
}

struct NativeChangesWorker {
    events: ChannelReloadTrigger,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl NativeChangesWorker {
    fn new(interval: Duration) -> Self {
        // Bound very short intervals even if the caller supplies zero.
        let interval = interval.max(Duration::from_millis(10));
        let (send, events) = ChannelReloadTrigger::new();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let thread = thread::Builder::new()
            .name("rama-native-trust-probe".into())
            .spawn(move || {
                let mut changes = NativeCertsChanges::new(interval);
                let mut first = true;
                // On these platforms the OS records change events between file checks.
                #[cfg(any(target_os = "macos", windows))]
                let sleep = interval.min(Duration::from_millis(250));
                #[cfg(not(any(target_os = "macos", windows)))]
                let sleep = interval;
                while !worker_stop.load(Ordering::Acquire) {
                    let changed = changes.changed();
                    // A file may change while the baseline and first snapshot are
                    // being read in parallel. Request one read after registration.
                    if (changed || first) && send.request_reload().is_err() {
                        break;
                    }
                    first = false;
                    thread::park_timeout(sleep);
                }
            })
            .inspect_err(|error| warn!(%error, "could not start native trust store monitor"))
            .ok();
        Self {
            events,
            stop,
            thread,
        }
    }
}

impl Drop for NativeChangesWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = &self.thread {
            thread.thread().unpark();
        }
    }
}

/// Receive manually requested native trust reloads.
pub struct ChannelReloadTrigger(flume::r#async::RecvStream<'static, ()>);

/// A cloneable sender for the channel reload trigger.
#[derive(Debug, Clone)]
pub struct ChannelReloadSender(flume::Sender<()>);

impl ChannelReloadTrigger {
    /// Create a sender and the trigger it feeds.
    #[must_use]
    pub fn new() -> (ChannelReloadSender, Self) {
        let (send, recv) = flume::bounded(1);
        (ChannelReloadSender(send), Self(recv.into_stream()))
    }
}

impl ChannelReloadSender {
    /// Queue a reload for the next handshake. Pending requests coalesce.
    pub fn request_reload(&self) -> Result<(), ChannelReloadClosed> {
        match self.0.try_send(()) {
            Ok(()) | Err(flume::TrySendError::Full(())) => Ok(()),
            Err(flume::TrySendError::Disconnected(())) => Err(ChannelReloadClosed),
        }
    }
}

/// The policy listening for manual native trust reloads has been dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelReloadClosed;

impl fmt::Display for ChannelReloadClosed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("native trust reload channel is closed")
    }
}

impl Error for ChannelReloadClosed {}

impl Stream for ChannelReloadTrigger {
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<()>> {
        Pin::new(&mut self.0).poll_next(cx)
    }
}

/// Request a native trust refresh when the process receives a Unix signal.
#[cfg(unix)]
pub struct UnixSignalTrigger(tokio::signal::unix::Signal);

#[cfg(unix)]
impl UnixSignalTrigger {
    /// Register for SIGHUP on the current Tokio runtime. As with other Tokio
    /// signal listeners, registering replaces the process's default behavior
    /// for this signal, even after the listener is dropped.
    ///
    /// ```
    /// # #[cfg(unix)]
    /// # async fn configure() -> std::io::Result<()> {
    /// use rama_tls::client::{TlsServerTrust, UnixSignalTrigger};
    ///
    /// let trust = TlsServerTrust::native_roots()
    ///     .with_reload_trigger(UnixSignalTrigger::sighup()?);
    /// # drop(trust);
    /// # Ok(())
    /// # }
    /// ```
    pub fn sighup() -> std::io::Result<Self> {
        Self::new(tokio::signal::unix::SignalKind::hangup())
    }

    /// Register for the specified Unix signal on the current Tokio runtime.
    ///
    /// The runtime must have I/O enabled.
    pub fn new(kind: tokio::signal::unix::SignalKind) -> std::io::Result<Self> {
        tokio::runtime::Handle::try_current().map_err(std::io::Error::other)?;
        tokio::signal::unix::signal(kind).map(Self)
    }
}

#[cfg(unix)]
impl Stream for UnixSignalTrigger {
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<()>> {
        self.0.poll_recv(cx)
    }
}

/// Immutable native trust anchors selected for a particular handshake.
#[derive(Clone)]
pub(super) struct NativeTrustSnapshot {
    generation: u64,
    anchors: Arc<[CertificateDer<'static>]>,
}

impl NativeTrustSnapshot {
    pub(super) fn anchors(&self) -> &[CertificateDer<'static>] {
        &self.anchors
    }
}

impl fmt::Debug for NativeTrustSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeTrustSnapshot")
            .field("generation", &self.generation)
            .field("anchor_count", &self.anchors.len())
            .finish()
    }
}

impl PartialEq for NativeTrustSnapshot {
    fn eq(&self, other: &Self) -> bool {
        self.generation == other.generation
    }
}

impl Eq for NativeTrustSnapshot {}

impl Hash for NativeTrustSnapshot {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.generation.hash(state);
    }
}

#[derive(Clone)]
pub(super) struct NativeTrustReload(Arc<ReloadController>);

struct ReloadController {
    identity: u64,
    wake: Arc<TriggerWake>,
    has_trigger: bool,
    failed: AtomicBool,
    current: ArcSwapOption<CheckedSnapshot>,
    reload: Mutex<ReloadState>,
}

struct TriggerWake(AtomicBool);

impl Wake for TriggerWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::Release);
    }
}

struct CheckedSnapshot {
    snapshot: NativeTrustSnapshot,
    checked_at: Instant,
}

impl CheckedSnapshot {
    fn is_fresh(&self, max_age: Option<Duration>) -> bool {
        max_age.is_none_or(|age| self.checked_at.elapsed() < age)
    }
}

struct ReloadState {
    trigger: Option<BoxStream<'static, ()>>,
    pending: bool,
    allow_bundled_fallback: bool,
    failure: Option<(Instant, Arc<dyn Error + Send + Sync>)>,
    flight: Option<Arc<RefreshFlight>>,
}

type LoadNativeTrust = Result<(Vec<CertificateDer<'static>>, bool), BoxError>;
type RefreshResult = Result<NativeTrustSnapshot, Arc<dyn Error + Send + Sync>>;

struct RefreshFlight {
    finished: flume::Receiver<()>,
    result: OnceLock<RefreshResult>,
}

impl RefreshFlight {
    fn result(
        &self,
        current: Option<&CheckedSnapshot>,
        max_age: Option<Duration>,
    ) -> Option<Result<NativeTrustSnapshot, BoxError>> {
        Some(match self.result.get()? {
            // This read completed after the caller reserved or joined the flight.
            Ok(snapshot) => Ok(snapshot.clone()),
            Err(error) => cached_after_failure(current, max_age, error),
        })
    }
}

fn cached_after_failure(
    current: Option<&CheckedSnapshot>,
    max_age: Option<Duration>,
    error: &Arc<dyn Error + Send + Sync>,
) -> Result<NativeTrustSnapshot, BoxError> {
    match current {
        Some(current) if current.is_fresh(max_age) => Ok(current.snapshot.clone()),
        _ => Err(Box::new(NativeTrustRefreshError(error.clone()))),
    }
}

enum PinAction {
    Ready(Result<NativeTrustSnapshot, BoxError>),
    Wait(Arc<RefreshFlight>, Option<Arc<CheckedSnapshot>>),
    Refresh(RefreshJob),
}

struct RefreshJob {
    reload: NativeTrustReload,
    flight: Arc<RefreshFlight>,
    // Dropping the only sender wakes every waiter, even if this job is cancelled.
    _finished: flume::Sender<()>,
    current: Option<Arc<CheckedSnapshot>>,
    allow_bundled_fallback: bool,
}

impl RefreshJob {
    fn run(
        self,
        max_age: Option<Duration>,
        load: impl FnOnce(bool) -> LoadNativeTrust,
    ) -> Result<NativeTrustSnapshot, BoxError> {
        let loaded = load(self.allow_bundled_fallback)
            .inspect_err(|error| warn!(%error, "could not refresh native TLS trust anchors"))
            .map(|(anchors, used_bundled_fallback)| {
                let snapshot = match &self.current {
                    Some(current) if current.snapshot.anchors() == anchors => {
                        current.snapshot.clone()
                    }
                    _ => {
                        static GENERATION: AtomicU64 = AtomicU64::new(1);
                        NativeTrustSnapshot {
                            generation: GENERATION.fetch_add(1, Ordering::Relaxed),
                            anchors: anchors.into(),
                        }
                    }
                };
                (snapshot, used_bundled_fallback)
            });

        let mut state = self.reload.0.reload.lock();
        let result = match loaded {
            Ok((snapshot, used_bundled_fallback)) => {
                self.reload.0.current.store(Some(Arc::new(CheckedSnapshot {
                    snapshot: snapshot.clone(),
                    checked_at: Instant::now(),
                })));
                state.allow_bundled_fallback = used_bundled_fallback;
                state.failure = None;
                self.reload.0.failed.store(false, Ordering::Relaxed);
                Ok(snapshot)
            }
            Err(error) => {
                let error: Arc<dyn Error + Send + Sync> = Arc::from(error);
                state.failure = Some((Instant::now(), error.clone()));
                self.reload.0.failed.store(true, Ordering::Relaxed);
                Err(error)
            }
        };
        let pinned = match &result {
            Ok(snapshot) => Ok(snapshot.clone()),
            Err(error) => cached_after_failure(self.current.as_deref(), max_age, error),
        };
        let published = self.flight.result.set(result);
        debug_assert!(published.is_ok());
        state.flight = None;
        pinned
    }
}

impl Drop for RefreshJob {
    fn drop(&mut self) {
        if self.flight.result.get().is_none() {
            let mut state = self.reload.0.reload.lock();
            state.flight = None;
            state.pending = true;
            self.reload.0.wake.0.store(true, Ordering::Release);
        }
    }
}

impl NativeTrustReload {
    pub(super) fn new(trigger: Option<BoxStream<'static, ()>>) -> Self {
        static IDENTITY: AtomicU64 = AtomicU64::new(1);
        Self(Arc::new(ReloadController {
            identity: IDENTITY.fetch_add(1, Ordering::Relaxed),
            wake: Arc::new(TriggerWake(AtomicBool::new(trigger.is_some()))),
            has_trigger: trigger.is_some(),
            failed: AtomicBool::new(false),
            current: ArcSwapOption::empty(),
            reload: Mutex::new(ReloadState {
                trigger,
                pending: false,
                allow_bundled_fallback: true,
                failure: None,
                flight: None,
            }),
        }))
    }

    pub(super) fn has_trigger(&self) -> bool {
        self.0.has_trigger
    }

    pub(super) fn pin(&self, max_age: Option<Duration>) -> Result<NativeTrustSnapshot, BoxError> {
        self.pin_with(max_age, load_reloadable_native_certs)
    }

    fn pin_with(
        &self,
        max_age: Option<Duration>,
        load: impl FnOnce(bool) -> LoadNativeTrust,
    ) -> Result<NativeTrustSnapshot, BoxError> {
        loop {
            match self.prepare_pin(max_age) {
                PinAction::Ready(result) => return result,
                PinAction::Wait(flight, current) => {
                    let _closed = flight.finished.recv();
                    if let Some(result) = flight.result(current.as_deref(), max_age) {
                        return result;
                    }
                }
                PinAction::Refresh(job) => return job.run(max_age, load),
            }
        }
    }

    pub(super) async fn pin_async(
        &self,
        max_age: Option<Duration>,
    ) -> Result<NativeTrustSnapshot, BoxError> {
        self.pin_async_with(max_age, load_reloadable_native_certs)
            .await
    }

    async fn pin_async_with(
        &self,
        max_age: Option<Duration>,
        load: impl FnOnce(bool) -> LoadNativeTrust + Send + 'static,
    ) -> Result<NativeTrustSnapshot, BoxError> {
        loop {
            match self.prepare_pin(max_age) {
                PinAction::Ready(result) => return result,
                PinAction::Wait(flight, current) => {
                    let _closed = flight.finished.recv_async().await;
                    if let Some(result) = flight.result(current.as_deref(), max_age) {
                        return result;
                    }
                }
                PinAction::Refresh(job) => {
                    return tokio::task::spawn_blocking(move || job.run(max_age, load)).await?;
                }
            }
        }
    }

    fn prepare_pin(&self, max_age: Option<Duration>) -> PinAction {
        if !self.0.wake.0.load(Ordering::Acquire)
            && !self.0.failed.load(Ordering::Relaxed)
            && let Some(current) = self.0.current.load().as_ref()
            && current.is_fresh(max_age)
        {
            return PinAction::Ready(Ok(current.snapshot.clone()));
        }

        let mut state = self.0.reload.lock();
        let current = self.0.current.load_full();
        if let Some(flight) = &state.flight {
            // Established roots remain usable during a concurrent refresh
            // unless this handshake requires a newer snapshot.
            return match &current {
                Some(current) if current.is_fresh(max_age) => {
                    PinAction::Ready(Ok(current.snapshot.clone()))
                }
                _ => PinAction::Wait(flight.clone(), current),
            };
        }

        if self.0.wake.0.swap(false, Ordering::AcqRel) {
            state.poll_trigger(&self.0.wake);
        }
        let needs_refresh = current
            .as_ref()
            .is_none_or(|snapshot| !snapshot.is_fresh(max_age));

        // Retry a failed read even if the change notification was consumed.
        // A fresh notification can bypass the backoff.
        const RETRY_DELAY: Duration = Duration::from_secs(1);
        let can_retry = state
            .failure
            .as_ref()
            .is_none_or(|(failed_at, _)| failed_at.elapsed() >= RETRY_DELAY);
        if state.pending || (can_retry && (needs_refresh || state.failure.is_some())) {
            let (finished_sender, finished) = flume::bounded(0);
            let flight = Arc::new(RefreshFlight {
                finished,
                result: OnceLock::new(),
            });
            state.pending = false;
            state.flight = Some(flight.clone());
            return PinAction::Refresh(RefreshJob {
                reload: self.clone(),
                flight,
                _finished: finished_sender,
                current,
                allow_bundled_fallback: state.allow_bundled_fallback,
            });
        }

        PinAction::Ready(if let Some((_, error)) = &state.failure {
            cached_after_failure(current.as_deref(), max_age, error)
        } else {
            current
                .map(|checked| checked.snapshot.clone())
                .ok_or_else(|| {
                    BoxError::from_static_str("native TLS trust anchors were not initialized")
                })
        })
    }
}

impl ReloadState {
    fn poll_trigger(&mut self, wake: &Arc<TriggerWake>) {
        let Some(trigger) = &mut self.trigger else {
            return;
        };
        let waker = Waker::from(wake.clone());
        let mut cx = Context::from_waker(&waker);
        // Coalesce events already in a tuple or source queue. A continuously
        // ready input must never keep a handshake in this loop.
        for _ in 0..32 {
            match trigger.as_mut().poll_next(&mut cx) {
                Poll::Ready(Some(())) => self.pending = true,
                Poll::Pending => return,
                Poll::Ready(None) => {
                    self.trigger = None;
                    return;
                }
            }
        }
        wake.0.store(true, Ordering::Release);
    }
}

impl fmt::Debug for NativeTrustReload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeTrustReload").finish_non_exhaustive()
    }
}

impl PartialEq for NativeTrustReload {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for NativeTrustReload {}

impl Hash for NativeTrustReload {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.identity.hash(state);
    }
}

/// The native trust store could not be read before a handshake that required
/// fresh trust anchors.
#[derive(Debug)]
pub struct NativeTrustRefreshError(Arc<dyn Error + Send + Sync>);

impl fmt::Display for NativeTrustRefreshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "could not refresh native TLS trust anchors: {}", self.0)
    }
}

impl Error for NativeTrustRefreshError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_crypto::native_certs::bundled_root_certs;

    #[test]
    fn manual_requests_coalesce_and_report_closure() {
        let (first, trigger) = ChannelReloadTrigger::new();
        let second = first.clone();
        let mut trigger = (trigger, ChannelReloadTrigger::new().1).into_reload_stream();
        let cx = &mut Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut trigger).poll_next(cx).is_pending());
        first.request_reload().unwrap();
        second.request_reload().unwrap();
        assert_eq!(Pin::new(&mut trigger).poll_next(cx), Poll::Ready(Some(())));
        assert!(Pin::new(&mut trigger).poll_next(cx).is_pending());
        drop(trigger);
        assert_eq!(second.request_reload(), Err(ChannelReloadClosed));
    }

    #[tokio::test]
    async fn grouped_triggers_accept_pinned_streams_without_boxing() {
        use rama_core::futures::{
            StreamExt as _,
            stream::{Once, once},
        };

        // The single-stream adapter preserves the concrete, !Unpin stream.
        let first: Once<_> = once(async {}).into_reload_stream();
        let events = (first, once(async {}), once(async {}), once(async {})).into_reload_stream();
        assert_eq!(events.count().await, 4);
    }

    #[test]
    fn a_user_stream_is_polled_only_after_its_waker_fires() {
        use rama_core::futures::{channel::mpsc, stream::poll_fn};
        use std::sync::atomic::AtomicUsize;

        let (mut send, mut events) = mpsc::channel(1);
        let polls = AtomicUsize::new(0);
        let polls = Arc::new(polls);
        let stream = poll_fn({
            let polls = polls.clone();
            move |cx| {
                polls.fetch_add(1, Ordering::Relaxed);
                Pin::new(&mut events).poll_next(cx)
            }
        });
        let reload = NativeTrustReload::new(Some(Box::pin(stream)));
        let anchors = bundled_root_certs();
        let original = reload
            .pin_with(None, |_| Ok((anchors[..1].to_vec(), false)))
            .unwrap();
        for _ in 0..32 {
            let PinAction::Ready(Ok(quiet)) = reload.prepare_pin(None) else {
                panic!("unexpected native trust refresh");
            };
            assert_eq!(original, quiet);
        }
        assert_eq!(polls.load(Ordering::Relaxed), 1);

        send.try_send(()).unwrap();
        let PinAction::Refresh(job) = reload.prepare_pin(None) else {
            panic!("expected native trust refresh");
        };
        let updated = job
            .run(None, |_| Ok((anchors[1..2].to_vec(), false)))
            .unwrap();
        assert_ne!(original, updated);
        assert_eq!(updated.anchors(), &anchors[1..2]);
    }

    #[test]
    fn refresh_retries_without_another_request_and_preserves_equal_generations() {
        let (sender, trigger) = ChannelReloadTrigger::new();
        let reload = NativeTrustReload::new(Some(Box::pin(trigger)));
        let anchors = bundled_root_certs()[..1].to_vec();
        let load = |_| Ok((anchors.clone(), false));
        let original = reload.pin_with(None, load).unwrap();

        sender.request_reload().unwrap();
        let failed = reload
            .pin_with(None, |_| {
                Err(std::io::Error::from(std::io::ErrorKind::InvalidData).into())
            })
            .unwrap();
        assert_eq!(original, failed);

        let stale = reload
            .pin_with(Some(Duration::ZERO), |_| panic!("failure backoff active"))
            .unwrap_err();
        assert!(stale.is::<NativeTrustRefreshError>());

        reload.0.reload.lock().failure.as_mut().unwrap().0 -= Duration::from_secs(2);
        let retried = reload.pin_with(None, load).unwrap();
        assert_eq!(original, retried);
    }

    #[test]
    fn async_refresh_waiters_share_one_blocking_worker_after_leader_cancellation() {
        use rama_core::futures::future::join_all;
        use std::pin::pin;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .max_blocking_threads(2)
            .build()
            .unwrap();
        runtime.block_on(async {
            let reload = NativeTrustReload::new(None);
            let max_age = Some(Duration::ZERO);
            let (entered, started) = flume::bounded(1);
            let (resume, paused) = flume::bounded(1);

            {
                let mut leader = pin!(reload.pin_async_with(max_age, move |_| {
                    entered.send(()).unwrap();
                    paused.recv().unwrap();
                    Ok((bundled_root_certs()[..1].to_vec(), false))
                }));
                let cx = &mut Context::from_waker(Waker::noop());
                assert!(leader.as_mut().poll(cx).is_pending());
            }
            started.recv_async().await.unwrap();

            let mut waiters = pin!(join_all((0..16).map(|_| {
                reload.pin_async_with(max_age, |_| panic!("waiter started another refresh"))
            })));
            let cx = &mut Context::from_waker(Waker::noop());
            assert!(waiters.as_mut().poll(cx).is_pending());

            tokio::time::timeout(Duration::from_secs(5), tokio::task::spawn_blocking(|| {}))
                .await
                .expect("other blocking work must run while the native trust store is blocked")
                .unwrap();

            resume.send(()).unwrap();
            let snapshots = waiters.await;
            for snapshot in snapshots {
                assert_eq!(snapshot.unwrap().anchors(), &bundled_root_certs()[..1]);
            }

            let next = reload
                .pin_async_with(max_age, |_| {
                    Ok((bundled_root_certs()[1..2].to_vec(), false))
                })
                .await
                .unwrap();
            assert_eq!(next.anchors(), &bundled_root_certs()[1..2]);
        });
    }

    #[test]
    fn concurrent_handshakes_keep_a_fresh_pinned_snapshot_until_publication() {
        let (sender, trigger) = ChannelReloadTrigger::new();
        let reload = NativeTrustReload::new(Some(Box::pin(trigger)));
        let anchors = bundled_root_certs();
        let initial = reload
            .pin_with(None, |_| Ok((anchors[..1].to_vec(), false)))
            .unwrap();

        sender.request_reload().unwrap();
        std::thread::scope(|scope| {
            let (entered, waiting) = std::sync::mpsc::sync_channel(0);
            let (resume, paused) = std::sync::mpsc::sync_channel(0);
            let reload = &reload;
            let refreshing = scope.spawn(move || {
                reload
                    .pin_with(None, |_| {
                        entered.send(()).unwrap();
                        paused.recv().unwrap();
                        Ok((anchors[1..2].to_vec(), false))
                    })
                    .unwrap()
            });
            waiting.recv().unwrap();
            let concurrent = reload.prepare_pin(None);
            let strict = reload.prepare_pin(Some(Duration::ZERO));
            resume.send(()).unwrap();

            let updated = refreshing.join().unwrap();
            let PinAction::Ready(Ok(concurrent)) = concurrent else {
                panic!("expected concurrent handshake to keep using fresh trust anchors");
            };
            assert!(matches!(strict, PinAction::Wait(..)));
            assert_eq!(initial, concurrent);
            assert_eq!(concurrent.anchors(), &anchors[..1]);
            assert_ne!(initial, updated);
            assert_eq!(updated.anchors(), &anchors[1..2]);
            let PinAction::Ready(Ok(next)) = reload.prepare_pin(None) else {
                panic!("expected newly published trust anchors");
            };
            assert_eq!(updated, next);
        });
    }
}
