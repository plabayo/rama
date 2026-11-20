use arc_swap::ArcSwapOption;
use parking_lot::Mutex;
use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    futures::stream::BoxStream,
    telemetry::tracing::warn,
};
use rama_crypto::{native_certs::load_reloadable_native_certs, pki_types::CertificateDer};
use std::{
    convert::Infallible,
    error::Error,
    fmt,
    hash::{Hash, Hasher},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    time::{Duration, Instant},
};

/// Immutable native trust anchors selected for a particular handshake.
#[derive(Clone)]
pub(in crate::client) struct NativeTrustSnapshot {
    generation: u64,
    anchors: Arc<[CertificateDer<'static>]>,
}

impl NativeTrustSnapshot {
    fn new(anchors: Vec<CertificateDer<'static>>) -> Self {
        static GENERATION: AtomicU64 = AtomicU64::new(1);
        Self {
            generation: GENERATION.fetch_add(1, Ordering::Relaxed),
            anchors: anchors.into(),
        }
    }

    pub(in crate::client) fn anchors(&self) -> &[CertificateDer<'static>] {
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
pub(in crate::client) struct NativeTrustReload(Arc<ReloadController>);

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
    completion: flume::Receiver<Infallible>,
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
    // The channel carries no messages. Dropping this sender wakes every
    // waiter after the job publishes its result or is cancelled.
    _completion: flume::Sender<Infallible>,
    current: Option<Arc<CheckedSnapshot>>,
    allow_bundled_fallback: bool,
}

impl RefreshJob {
    fn run(
        self,
        max_age: Option<Duration>,
        load: impl FnOnce(bool) -> LoadNativeTrust,
    ) -> Result<NativeTrustSnapshot, BoxError> {
        // Read the store and compare anchors before taking the controller lock.
        let loaded = load(self.allow_bundled_fallback)
            .inspect_err(|error| warn!(%error, "could not refresh native TLS trust anchors"))
            .map(|(anchors, used_bundled_fallback)| {
                let snapshot = match &self.current {
                    Some(current) if current.snapshot.anchors() == anchors => {
                        current.snapshot.clone()
                    }
                    _ => NativeTrustSnapshot::new(anchors),
                };
                (snapshot, used_bundled_fallback)
            });
        self.publish(loaded, max_age)
    }

    fn publish(
        &self,
        loaded: Result<(NativeTrustSnapshot, bool), BoxError>,
        max_age: Option<Duration>,
    ) -> Result<NativeTrustSnapshot, BoxError> {
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
    pub(in crate::client) fn new(trigger: Option<BoxStream<'static, ()>>) -> Self {
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

    pub(in crate::client) fn has_trigger(&self) -> bool {
        self.0.has_trigger
    }

    pub(in crate::client) fn pin(
        &self,
        max_age: Option<Duration>,
    ) -> Result<NativeTrustSnapshot, BoxError> {
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
                    let _closed = flight.completion.recv();
                    if let Some(result) = flight.result(current.as_deref(), max_age) {
                        return result;
                    }
                }
                PinAction::Refresh(job) => return job.run(max_age, load),
            }
        }
    }

    pub(in crate::client) async fn pin_async(
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
                    let _closed = flight.completion.recv_async().await;
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
        // An unchanged, fresh snapshot can be pinned without locking or polling.
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
        if state.should_refresh(current.as_deref(), max_age) {
            let (completion_sender, completion) = flume::bounded(0);
            let flight = Arc::new(RefreshFlight {
                completion,
                result: OnceLock::new(),
            });
            state.pending = false;
            state.flight = Some(flight.clone());
            return PinAction::Refresh(RefreshJob {
                reload: self.clone(),
                flight,
                _completion: completion_sender,
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
    fn should_refresh(&self, current: Option<&CheckedSnapshot>, max_age: Option<Duration>) -> bool {
        // A fresh notification bypasses backoff. Otherwise retry a failed read
        // after a delay even if its change notification was consumed.
        const RETRY_DELAY: Duration = Duration::from_secs(1);
        self.pending
            || match self.failure {
                Some((failed_at, _)) => failed_at.elapsed() >= RETRY_DELAY,
                None => current.is_none_or(|snapshot| !snapshot.is_fresh(max_age)),
            }
    }

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
mod tests;
