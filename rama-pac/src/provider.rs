//! Where a PAC script comes from.
//!
//! A provider is a [`Service<Uri>`] returning a [`PacScript`]. The
//! resolver asks it on every lookup, so how often the script is really
//! fetched is the provider's decision: [`FetchPacScript`] always fetches,
//! [`PacScriptCache`] keeps an answer for a while, and
//! [`StaticPacScript`] never leaves the process.

use std::fmt;
use std::time::{Duration, Instant};

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
/// At most one refresh runs at a time, however many callers arrive: a
/// caller with a usable script gets it right away, the rest share the
/// outcome of the attempt already in flight.
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
            fetching: Mutex::new(()),
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
    /// held for the whole fetch, so an unreachable origin costs one
    /// outbound attempt at a time rather than one per caller
    fetching: Mutex<()>,
}

#[derive(Debug, Default)]
struct CacheState {
    /// newest successfully fetched script
    entry: Option<CachedScript>,
    /// last refresh that failed, cleared by a success
    failure: Option<Failure>,
}

#[derive(Debug, Clone)]
struct CachedScript {
    uri: Uri,
    script: PacScript,
    fetched_at: Instant,
}

#[derive(Debug)]
struct Failure {
    uri: Uri,
    /// start of the backoff window
    at: Instant,
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
    async fn cached(&self, uri: &Uri) -> Cached {
        let state = self.state.lock().await;
        // a different uri is a different policy, never a cache hit
        let entry = state.entry.as_ref().filter(|entry| entry.uri == *uri);
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
        let backing_off = state.failure.as_ref().is_some_and(|failure| {
            failure.uri == *uri && failure.at.elapsed() < PacScriptCacheLayer::REFRESH_BACKOFF
        });
        if !backing_off {
            return Cached::Refresh(stale);
        }
        match stale {
            Some(script) => Cached::Hit(script),
            None => Cached::Backoff,
        }
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

        // the fetch never happens under the state lock, and only one runs
        // at a time; a caller with a usable script never queues for it
        let _fetching = if let Ok(guard) = self.fetching.try_lock() {
            guard
        } else {
            if let Some(script) = stale {
                tracing::trace!("pac script refresh in flight, serving stale script");
                return Ok(script);
            }
            self.fetching.lock().await
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

        let started_at = Instant::now();
        match self.inner.serve(uri.clone()).await {
            Ok(script) => {
                let mut state = self.state.lock().await;
                state.entry = Some(CachedScript {
                    uri,
                    script: script.clone(),
                    fetched_at: Instant::now(),
                });
                state.failure = None;
                Ok(script)
            }
            Err(err) => {
                let err: BoxError = err.into();
                let newest = {
                    let mut state = self.state.lock().await;
                    let superseded = state
                        .entry
                        .as_ref()
                        .is_some_and(|entry| entry.uri == uri && entry.fetched_at > started_at);
                    if superseded {
                        // a script newer than this attempt must not pay for its failure
                        state.failure = None;
                    } else {
                        state.failure = Some(Failure {
                            uri: uri.clone(),
                            at: Instant::now(),
                        });
                    }
                    state
                        .entry
                        .as_ref()
                        .filter(|entry| entry.uri == uri)
                        .map(|entry| entry.script.clone())
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
    const SCRIPT_V2: &str = "function FindProxyForURL(url, host) { return \"PROXY a:8080\"; }";

    fn script_uri() -> Uri {
        Uri::from_static("http://pac.example/proxy.pac")
    }

    /// How long a held call stays in flight: long enough for every caller to
    /// arrive, short enough to keep the tests quick. A fixed delay rather
    /// than a handshake, so a broken single-flight fails an assertion instead
    /// of deadlocking the test.
    const HOLD: Duration = Duration::from_millis(150);

    /// Provider whose calls are counted, can be switched to fail, and can be
    /// held open so an attempt is observably in flight.
    #[derive(Debug)]
    struct TestProvider {
        calls: AtomicUsize,
        fail: AtomicBool,
        hold: AtomicBool,
        script: PacScript,
    }

    impl TestProvider {
        fn new(script: &'static str) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                fail: AtomicBool::new(false),
                hold: AtomicBool::new(false),
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
    }

    impl Service<Uri> for TestProvider {
        type Output = PacScript;
        type Error = OpaqueError;

        async fn serve(&self, _uri: Uri) -> Result<Self::Output, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.hold.load(Ordering::SeqCst) {
                tokio::time::sleep(HOLD).await;
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

        let results = join_all((0..50).map(|_| cache.serve(uri.clone()))).await;

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

        let results = join_all((0..50).map(|_| cache.serve(uri.clone()))).await;

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

        let results = join_all((0..50).map(|_| cache.serve(uri.clone()))).await;

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
        tokio::select! {
            _ = cache.serve(uri.clone()) => panic!("attempt should still be in flight"),
            () = tokio::time::sleep(HOLD / 5) => (),
        }
        assert_eq!(provider.calls(), 2);

        // an abandoned attempt is not a failure, so the next caller is served
        // rather than held off for a whole backoff window
        provider.hold(false);
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
        tokio::select! {
            _ = cache.serve(uri.clone()) => panic!("attempt should still be in flight"),
            () = tokio::time::sleep(HOLD / 5) => (),
        }

        provider.hold(false);
        assert_eq!(
            cache.serve(uri.clone()).await.unwrap(),
            PacScript::from(SCRIPT_V1)
        );
    }

    #[tokio::test]
    async fn a_failed_attempt_does_not_penalise_a_newer_script() {
        let provider = TestProvider::new(SCRIPT_V1);
        let cache = PacScriptCacheLayer::new()
            .with_ttl(Duration::ZERO)
            .layer(provider.clone());
        let uri = script_uri();

        cache.serve(uri.clone()).await.unwrap();
        provider.fail(true);
        provider.hold(true);

        let refresh = cache.serve(uri.clone());
        let winner = async {
            // a newer script lands while the failing attempt is in flight
            tokio::time::sleep(HOLD / 3).await;
            let mut state = cache.state.lock().await;
            state.entry = Some(CachedScript {
                uri: uri.clone(),
                script: PacScript::from(SCRIPT_V2),
                fetched_at: Instant::now(),
            });
            state.failure = None;
        };
        let (served, ()) = tokio::join!(refresh, winner);

        assert_eq!(served.unwrap(), PacScript::from(SCRIPT_V2));
        // the newer script keeps its refresh eligibility
        assert!(cache.state.lock().await.failure.is_none());
    }
}
