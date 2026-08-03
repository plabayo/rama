//! Where a PAC script comes from.
//!
//! A provider is a [`Service<Uri>`] returning a [`PacScript`]. The
//! resolver asks it on every lookup, so how often the script is really
//! fetched is the provider's decision: [`FetchPacScript`] always fetches,
//! [`PacScriptCache`] keeps an answer for a while, and
//! [`StaticPacScript`] never leaves the process.

use std::fmt;
use std::time::{Duration, Instant};

use rama_core::error::{BoxError, ErrorExt, extra::OpaqueError};
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
            cached: Mutex::new(None),
        }
    }
}

/// See [`PacScriptCacheLayer`].
#[derive(Debug)]
pub struct PacScriptCache<S> {
    inner: S,
    ttl: Duration,
    serve_stale: bool,
    cached: Mutex<Option<CachedScript>>,
}

#[derive(Debug, Clone)]
struct CachedScript {
    uri: Uri,
    script: PacScript,
    fetched_at: Instant,
}

impl<S> Service<Uri> for PacScriptCache<S>
where
    S: Service<Uri, Output = PacScript, Error: Into<BoxError>>,
{
    type Output = PacScript;
    type Error = OpaqueError;

    async fn serve(&self, uri: Uri) -> Result<Self::Output, Self::Error> {
        let mut cached = self.cached.lock().await;

        // a different uri is a different policy, never a cache hit
        if let Some(entry) = cached.as_ref()
            && entry.uri == uri
            && entry.fetched_at.elapsed() < self.ttl
        {
            return Ok(entry.script.clone());
        }

        match self.inner.serve(uri.clone()).await {
            Ok(script) => {
                *cached = Some(CachedScript {
                    uri,
                    script: script.clone(),
                    fetched_at: Instant::now(),
                });
                Ok(script)
            }
            Err(err) => {
                let err: BoxError = err.into();
                match cached.as_ref() {
                    Some(entry) if self.serve_stale && entry.uri == uri => {
                        tracing::warn!("pac script refresh failed, serving stale script: {err}");
                        Ok(entry.script.clone())
                    }
                    _ => Err(err.context("refresh pac script").into_opaque_error()),
                }
            }
        }
    }
}
