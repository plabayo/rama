//! Where a PAC script comes from.
//!
//! A provider is a [`Service<Uri>`] returning a [`PacScript`]. The
//! resolver asks it on every lookup, so how often the script is really
//! fetched is the provider's decision: [`FetchPacScript`] always fetches,
//! [`PacScriptCache`] keeps an answer for a while, and
//! [`StaticPacScript`] never leaves the process.

use std::fmt;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use ahash::HashMap;
use rama_core::error::{BoxError, BoxErrorExt as _, ErrorExt, extra::OpaqueError};
use rama_core::telemetry::tracing;
use rama_core::{Layer, Service};
use rama_net::uri::Uri;
use rama_utils::macros::generate_set_and_with;
use rama_utils::str::arcstr::ArcStr;
use tokio::sync::Mutex;

/// The source of a PAC script.
///
/// Cheap to clone and compared by content, which is what lets a resolver
/// tell a re-fetch of the same script from a real change. Build one from
/// an [`ArcStr`] — including an `arcstr!` const — to avoid allocating a
/// script that ships with the binary.
#[derive(Clone, PartialEq, Eq)]
pub struct PacScript(ArcStr);

impl PacScript {
    /// The script source.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for PacScript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacScript")
            .field("len", &self.0.len())
            .finish()
    }
}

impl From<String> for PacScript {
    fn from(source: String) -> Self {
        Self(ArcStr::from(source))
    }
}

impl From<&str> for PacScript {
    fn from(source: &str) -> Self {
        Self(ArcStr::from(source))
    }
}

impl From<ArcStr> for PacScript {
    fn from(source: ArcStr) -> Self {
        Self(source)
    }
}

/// Serves one script, ignoring the uri: for scripts that ship with the
/// configuration rather than being fetched.
#[derive(Debug, Clone)]
pub struct StaticPacScript(PacScript);

impl StaticPacScript {
    /// Always serve this script.
    pub fn new(script: impl Into<PacScript>) -> Self {
        Self(script.into())
    }
}

impl Service<Uri> for StaticPacScript {
    type Output = PacScript;
    type Error = OpaqueError;

    async fn serve(&self, _uri: Uri) -> Result<Self::Output, Self::Error> {
        Ok(self.0.clone())
    }
}

/// Keeps a fetched script for [`ttl`][PacScriptCacheLayer::with_ttl],
/// so an always-fetching provider does not hit the network per request.
///
/// At most one refresh per script URI runs at a time, however many callers
/// arrive. A slow obsolete URI therefore cannot block a newly configured URI.
/// A caller with a usable script gets it right away; callers for the same URI
/// share the outcome of the attempt already in flight.
#[derive(Debug, Clone)]
pub struct PacScriptCacheLayer {
    ttl: Duration,
    serve_stale: bool,
}

impl Default for PacScriptCacheLayer {
    fn default() -> Self {
        Self {
            ttl: Self::DEFAULT_TTL,
            serve_stale: true,
        }
    }
}

impl PacScriptCacheLayer {
    /// How long a fetched script is reused by default.
    ///
    /// Browsers hold a pac file for hours; a script uri change bypasses
    /// the ttl anyway, so a long default costs little.
    pub const DEFAULT_TTL: Duration = Duration::from_hours(12);

    /// How long a failed refresh is remembered before the origin is tried
    /// again.
    ///
    /// Within the window a stale script is served straight away — and the
    /// refresh error returned right away when
    /// [`serve_stale`][Self::with_serve_stale] is off — so an unreachable
    /// origin costs one attempt per window instead of one per caller.
    pub const REFRESH_BACKOFF: Duration = Duration::from_secs(30);

    /// Create a new [`PacScriptCacheLayer`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    generate_set_and_with! {
        /// Reuse a fetched script for this long
        /// (defaults to [`Self::DEFAULT_TTL`]).
        pub fn ttl(mut self, ttl: Duration) -> Self {
            self.ttl = ttl;
            self
        }
    }

    generate_set_and_with! {
        /// Keep serving an expired script when the refresh fails
        /// (defaults to `true`: a stale policy beats no policy).
        ///
        /// Either way a failed refresh opens a [`Self::REFRESH_BACKOFF`]
        /// window in which the origin is left alone.
        pub fn serve_stale(mut self, serve_stale: bool) -> Self {
            self.serve_stale = serve_stale;
            self
        }
    }
}

impl<S> Layer<S> for PacScriptCacheLayer {
    type Service = PacScriptCache<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PacScriptCache {
            inner,
            ttl: self.ttl,
            serve_stale: self.serve_stale,
            state: Mutex::new(CacheState::default()),
            fetching: Mutex::new(HashMap::default()),
        }
    }
}

/// See [`PacScriptCacheLayer`].
#[derive(Debug)]
pub struct PacScriptCache<S> {
    inner: S,
    ttl: Duration,
    serve_stale: bool,
    state: Mutex<CacheState>,
    /// Per-URI weak locks deduplicate a fetch without serializing unrelated
    /// PAC locations. Dead locks are discarded whenever another is selected.
    fetching: Mutex<HashMap<Uri, Weak<Mutex<()>>>>,
}

#[derive(Debug, Default)]
struct CacheState {
    entries: HashMap<Uri, UriCacheState>,
}

#[derive(Debug, Clone)]
struct CachedScript {
    script: PacScript,
    fetched_at: Instant,
}

#[derive(Debug)]
struct UriCacheState {
    entry: Option<CachedScript>,
    /// Start of the failed-refresh backoff window.
    failure_at: Option<Instant>,
    last_used: Instant,
}

/// What the cached state alone allows, without an outbound fetch.
enum Cached {
    /// serve this script as is
    Hit(PacScript),
    /// nothing servable, and the last attempt for this uri is still
    /// within its backoff window
    Backoff,
    /// refresh needed; carries the stale script to fall back on
    Refresh(Option<PacScript>),
}

impl<S> PacScriptCache<S> {
    const MAX_CACHED_URIS: usize = 16;

    async fn cached(&self, uri: &Uri) -> Cached {
        let mut state = self.state.lock().await;
        let Some(state) = state.entries.get_mut(uri) else {
            return Cached::Refresh(None);
        };
        state.last_used = Instant::now();
        let entry = state.entry.as_ref();
        if let Some(entry) = entry
            && entry.fetched_at.elapsed() < self.ttl
        {
            return Cached::Hit(entry.script.clone());
        }
        let stale = entry
            .filter(|_| self.serve_stale)
            .map(|entry| entry.script.clone());
        // only a *failed* attempt backs off: an in-flight one is deduplicated
        // by the fetch lock, and counting it here would let one abandoned
        // caller deny every later one for a whole window
        let backing_off = state
            .failure_at
            .is_some_and(|at| at.elapsed() < PacScriptCacheLayer::REFRESH_BACKOFF);
        if !backing_off {
            state.failure_at = None;
            return Cached::Refresh(stale);
        }
        match stale {
            Some(script) => Cached::Hit(script),
            None => Cached::Backoff,
        }
    }

    async fn fetch_lock(&self, uri: &Uri) -> Arc<Mutex<()>> {
        let mut fetching = self.fetching.lock().await;
        fetching.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = fetching.get(uri).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(Mutex::new(()));
        fetching.insert(uri.clone(), Arc::downgrade(&lock));
        lock
    }

    fn state_for_uri<'a>(state: &'a mut CacheState, uri: &Uri) -> &'a mut UriCacheState {
        if !state.entries.contains_key(uri)
            && state.entries.len() >= Self::MAX_CACHED_URIS
            && let Some(oldest) = state
                .entries
                .iter()
                .min_by_key(|(_, state)| state.last_used)
                .map(|(uri, _)| uri.clone())
        {
            state.entries.remove(&oldest);
        }
        state
            .entries
            .entry(uri.clone())
            .or_insert_with(|| UriCacheState {
                entry: None,
                failure_at: None,
                last_used: Instant::now(),
            })
    }
}

impl<S> Service<Uri> for PacScriptCache<S>
where
    S: Service<Uri, Output = PacScript, Error: Into<BoxError>>,
{
    type Output = PacScript;
    type Error = OpaqueError;

    async fn serve(&self, uri: Uri) -> Result<Self::Output, Self::Error> {
        let stale = match self.cached(&uri).await {
            Cached::Hit(script) => return Ok(script),
            Cached::Backoff => None,
            Cached::Refresh(stale) => stale,
        };

        // The fetch never happens under the state lock. Only callers for this
        // URI serialize; a caller with a usable script never queues for it.
        let fetching = self.fetch_lock(&uri).await;
        let _fetching = if let Ok(guard) = fetching.try_lock() {
            guard
        } else {
            if let Some(script) = stale {
                tracing::trace!("pac script refresh in flight, serving stale script");
                return Ok(script);
            }
            fetching.lock().await
        };

        // the attempt we waited for may have installed a script, or failed
        match self.cached(&uri).await {
            Cached::Hit(script) => return Ok(script),
            Cached::Backoff => {
                return Err(BoxError::from_static_str("pac script refresh backing off")
                    .context("refresh pac script")
                    .into_opaque_error());
            }
            Cached::Refresh(_) => (),
        }

        match self.inner.serve(uri.clone()).await {
            Ok(script) => {
                let mut state = self.state.lock().await;
                let state = Self::state_for_uri(&mut state, &uri);
                state.entry = Some(CachedScript {
                    script: script.clone(),
                    fetched_at: Instant::now(),
                });
                state.failure_at = None;
                state.last_used = Instant::now();
                Ok(script)
            }
            Err(err) => {
                let err: BoxError = err.into();
                let newest = {
                    let mut state = self.state.lock().await;
                    let state = Self::state_for_uri(&mut state, &uri);
                    // Fetches for one URI share a lock, so this failed attempt
                    // is necessarily the latest attempt for this entry.
                    state.failure_at = Some(Instant::now());
                    state.last_used = Instant::now();
                    state.entry.as_ref().map(|entry| entry.script.clone())
                };
                match newest {
                    Some(script) if self.serve_stale => {
                        tracing::warn!("pac script refresh failed, serving stale script: {err}");
                        Ok(script)
                    }
                    _ => Err(err.context("refresh pac script").into_opaque_error()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use rama_core::futures::future::join_all;

    const SCRIPT_V1: &str = "function FindProxyForURL(url, host) { return \"DIRECT\"; }";
    const TEST_WATCHDOG: Duration = Duration::from_mins(1);

    fn script_uri() -> Uri {
        Uri::from_static("http://pac.example/proxy.pac")
    }

    /// Provider whose calls are counted, can be switched to fail, and can be
    /// held open so an attempt is observably in flight.
    #[derive(Debug)]
    struct TestProvider {
        calls: AtomicUsize,
        fail: AtomicBool,
        hold: AtomicBool,
        held: AtomicUsize,
        entered: tokio::sync::Notify,
        released: tokio::sync::Notify,
        script: PacScript,
    }

    impl TestProvider {
        fn new(script: &'static str) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                fail: AtomicBool::new(false),
                hold: AtomicBool::new(false),
                held: AtomicUsize::new(0),
                entered: tokio::sync::Notify::new(),
                released: tokio::sync::Notify::new(),
                script: PacScript::from(script),
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn fail(&self, fail: bool) {
            self.fail.store(fail, Ordering::SeqCst);
        }

        fn hold(&self, hold: bool) {
            self.hold.store(hold, Ordering::SeqCst);
        }

        async fn wait_until_held(&self) {
            tokio::time::timeout(TEST_WATCHDOG, async {
                loop {
                    let entered = self.entered.notified();
                    if self.held.load(Ordering::SeqCst) > 0 {
                        return;
                    }
                    entered.await;
                }
            })
            .await
            .expect("held provider call did not start");
        }

        fn release(&self) {
            self.hold(false);
            self.released.notify_waiters();
        }
    }

    impl Service<Uri> for TestProvider {
        type Output = PacScript;
        type Error = OpaqueError;

        async fn serve(&self, _uri: Uri) -> Result<Self::Output, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.hold.load(Ordering::SeqCst) {
                let released = self.released.notified();
                self.held.fetch_add(1, Ordering::SeqCst);
                self.entered.notify_waiters();
                released.await;
                self.held.fetch_sub(1, Ordering::SeqCst);
            }
            if self.fail.load(Ordering::SeqCst) {
                return Err(OpaqueError::from_static_str("origin down"));
            }
            Ok(self.script.clone())
        }
    }

    #[tokio::test]
    async fn fresh_script_is_served_without_a_refetch() {
        let provider = TestProvider::new(SCRIPT_V1);
        let cache = PacScriptCacheLayer::new().layer(provider.clone());
        let uri = script_uri();

        assert_eq!(
            cache.serve(uri.clone()).await.unwrap(),
            PacScript::from(SCRIPT_V1)
        );
        assert_eq!(
            cache.serve(uri.clone()).await.unwrap(),
            PacScript::from(SCRIPT_V1)
        );
        assert_eq!(provider.calls(), 1);

        cache
            .serve(Uri::from_static("http://pac.example/other.pac"))
            .await
            .unwrap();
        assert_eq!(provider.calls(), 2);
    }

    #[tokio::test]
    async fn cold_concurrent_callers_share_one_fetch() {
        let provider = TestProvider::new(SCRIPT_V1);
        provider.hold(true);
        let cache = PacScriptCacheLayer::new().layer(provider.clone());
        let uri = script_uri();

        let requests = join_all((0..50).map(|_| cache.serve(uri.clone())));
        let release = async {
            provider.wait_until_held().await;
            provider.release();
        };
        let (results, ()) = tokio::join!(requests, release);

        assert_eq!(provider.calls(), 1);
        for result in results {
            assert_eq!(result.unwrap(), PacScript::from(SCRIPT_V1));
        }
    }

    #[tokio::test]
    async fn concurrent_failed_refreshes_fetch_once_serving_stale() {
        let provider = TestProvider::new(SCRIPT_V1);
        let cache = PacScriptCacheLayer::new()
            .with_ttl(Duration::ZERO)
            .with_serve_stale(true)
            .layer(provider.clone());
        let uri = script_uri();

        cache.serve(uri.clone()).await.unwrap();
        assert_eq!(provider.calls(), 1);

        provider.fail(true);
        provider.hold(true);

        let requests = join_all((0..50).map(|_| cache.serve(uri.clone())));
        let release = async {
            provider.wait_until_held().await;
            provider.release();
        };
        let (results, ()) = tokio::join!(requests, release);

        // one outbound attempt for all 50 callers, everyone gets the script
        assert_eq!(provider.calls(), 2);
        for result in results {
            assert_eq!(result.unwrap(), PacScript::from(SCRIPT_V1));
        }
    }

    #[tokio::test]
    async fn concurrent_failed_refreshes_fetch_once_without_serve_stale() {
        let provider = TestProvider::new(SCRIPT_V1);
        let cache = PacScriptCacheLayer::new()
            .with_ttl(Duration::ZERO)
            .with_serve_stale(false)
            .layer(provider.clone());
        let uri = script_uri();

        cache.serve(uri.clone()).await.unwrap();
        assert_eq!(provider.calls(), 1);

        provider.fail(true);
        provider.hold(true);

        let requests = join_all((0..50).map(|_| cache.serve(uri.clone())));
        let release = async {
            provider.wait_until_held().await;
            provider.release();
        };
        let (results, ()) = tokio::join!(requests, release);

        assert_eq!(provider.calls(), 2);
        for result in results {
            result.unwrap_err();
        }
    }

    #[tokio::test]
    async fn a_failed_refresh_backs_off_before_retrying() {
        let provider = TestProvider::new(SCRIPT_V1);
        let cache = PacScriptCacheLayer::new()
            .with_ttl(Duration::ZERO)
            .layer(provider.clone());
        let uri = script_uri();

        cache.serve(uri.clone()).await.unwrap();
        provider.fail(true);
        assert_eq!(
            cache.serve(uri.clone()).await.unwrap(),
            PacScript::from(SCRIPT_V1)
        );
        assert_eq!(provider.calls(), 2);

        for _ in 0..5 {
            assert_eq!(
                cache.serve(uri.clone()).await.unwrap(),
                PacScript::from(SCRIPT_V1)
            );
        }
        assert_eq!(provider.calls(), 2);
    }

    #[tokio::test]
    async fn a_backoff_never_holds_off_another_script_uri() {
        let provider = TestProvider::new(SCRIPT_V1);
        let cache = PacScriptCacheLayer::new()
            .with_ttl(Duration::ZERO)
            .with_serve_stale(false)
            .layer(provider.clone());
        let uri = script_uri();

        cache.serve(uri.clone()).await.unwrap();
        provider.fail(true);
        cache.serve(uri.clone()).await.unwrap_err();
        assert_eq!(provider.calls(), 2);

        // a different uri is a different policy: it must be fetched on its
        // own merits rather than inherit another uri's backoff window
        provider.fail(false);
        assert_eq!(
            cache
                .serve(Uri::from_static("http://pac.example/other.pac"))
                .await
                .unwrap(),
            PacScript::from(SCRIPT_V1)
        );
        assert_eq!(provider.calls(), 3);
    }

    #[tokio::test]
    async fn a_cancelled_attempt_does_not_deny_later_callers() {
        let provider = TestProvider::new(SCRIPT_V1);
        let cache = PacScriptCacheLayer::new()
            .with_ttl(Duration::ZERO)
            .layer(provider.clone());
        let uri = script_uri();

        cache.serve(uri.clone()).await.unwrap();
        provider.hold(true);

        // the caller goes away while its attempt is in flight
        let mut attempt = Box::pin(cache.serve(uri.clone()));
        tokio::select! {
            result = &mut attempt => panic!("attempt completed unexpectedly: {result:?}"),
            () = provider.wait_until_held() => (),
        }
        drop(attempt);
        assert_eq!(provider.calls(), 2);

        // an abandoned attempt is not a failure, so the next caller is served
        // rather than held off for a whole backoff window
        provider.release();
        assert_eq!(
            cache.serve(uri.clone()).await.unwrap(),
            PacScript::from(SCRIPT_V1)
        );
        assert_eq!(provider.calls(), 3);
    }

    #[tokio::test]
    async fn a_cancelled_first_attempt_does_not_deny_a_cold_cache() {
        let provider = TestProvider::new(SCRIPT_V1);
        provider.hold(true);
        let cache = PacScriptCacheLayer::new().layer(provider.clone());
        let uri = script_uri();

        // nothing cached yet: an abandoned first attempt must not turn into an
        // outage for everyone who arrives after it
        let mut attempt = Box::pin(cache.serve(uri.clone()));
        tokio::select! {
            result = &mut attempt => panic!("attempt completed unexpectedly: {result:?}"),
            () = provider.wait_until_held() => (),
        }
        drop(attempt);

        provider.release();
        assert_eq!(
            cache.serve(uri.clone()).await.unwrap(),
            PacScript::from(SCRIPT_V1)
        );
    }

    #[test]
    fn uri_state_eviction_is_bounded_and_never_evicts_an_existing_key() {
        let mut state = CacheState::default();
        let mut uris = Vec::with_capacity(PacScriptCache::<TestProvider>::MAX_CACHED_URIS);
        for index in 0..PacScriptCache::<TestProvider>::MAX_CACHED_URIS {
            let uri: Uri = format!("http://pac.example/{index}.pac").parse().unwrap();
            uris.push(uri.clone());
            PacScriptCache::<TestProvider>::state_for_uri(&mut state, &uri);
        }
        assert_eq!(
            state.entries.len(),
            PacScriptCache::<TestProvider>::MAX_CACHED_URIS
        );

        let existing = uris[0].clone();
        PacScriptCache::<TestProvider>::state_for_uri(&mut state, &existing);
        assert_eq!(
            state.entries.len(),
            PacScriptCache::<TestProvider>::MAX_CACHED_URIS
        );
        assert!(uris.iter().all(|uri| state.entries.contains_key(uri)));

        let replacement: Uri = "http://pac.example/replacement.pac".parse().unwrap();
        PacScriptCache::<TestProvider>::state_for_uri(&mut state, &replacement);
        assert_eq!(
            state.entries.len(),
            PacScriptCache::<TestProvider>::MAX_CACHED_URIS
        );
        assert!(state.entries.contains_key(&replacement));
        assert_eq!(
            uris.iter()
                .filter(|uri| state.entries.contains_key(*uri))
                .count(),
            PacScriptCache::<TestProvider>::MAX_CACHED_URIS - 1
        );
    }
}
