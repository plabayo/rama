//! Where a PAC script comes from.
//!
//! A provider is a [`Service<Uri>`] returning a [`PacScript`]. The
//! resolver asks it on every lookup, so how often the script is really
//! fetched is the provider's decision: [`FetchPacScript`] always fetches,
//! [`PacScriptCache`] keeps an answer for a while, and
//! [`StaticPacScript`] never leaves the process.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rama_core::error::{BoxError, BoxErrorExt, ErrorContext, ErrorExt, extra::OpaqueError};
use rama_core::telemetry::tracing;
use rama_core::{Layer, Service, service::BoxService};
use rama_http::service::client::HttpClientExt as _;
use rama_http::{BodyExtractExt as _, Request, Response, body::CollectOptions};
use rama_net::uri::Uri;
use rama_utils::macros::generate_set_and_with;
use tokio::sync::Mutex;

/// The source of a PAC script.
///
/// Cheap to clone and compared by content, which is what lets a resolver
/// tell a re-fetch of the same script from a real change.
#[derive(Clone, PartialEq, Eq)]
pub struct PacScript(Arc<str>);

impl PacScript {
    /// The script source.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
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
        Self(source.into())
    }
}

impl From<&str> for PacScript {
    fn from(source: &str) -> Self {
        Self(source.into())
    }
}

/// Always fetches the script, through the given http client.
///
/// The client decides which schemes work: layer it with
/// [`FileUriLayer`][rama_http::layer::file_uri::FileUriLayer] and
/// [`DataUriLayer`][rama_http::layer::data_uri::DataUriLayer] to also
/// accept `file://` and `data:` script uris.
pub struct FetchPacScript {
    client: BoxService<Request, Response, OpaqueError>,
    max_size: usize,
    timeout: Duration,
}

impl fmt::Debug for FetchPacScript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchPacScript")
            .field("max_size", &self.max_size)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl FetchPacScript {
    /// Largest script accepted by default; browsers cap PAC files
    /// around this size.
    pub const DEFAULT_MAX_SIZE: usize = 1024 * 1024;

    /// Default budget for one fetch: connect, headers and body.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

    /// Fetch PAC scripts with the given http client.
    pub fn new<S>(client: S) -> Self
    where
        S: Service<Request, Output = Response, Error: std::error::Error + Send + Sync + 'static>,
    {
        Self {
            client: rama_core::layer::MapErr::into_opaque_error(client).boxed(),
            max_size: Self::DEFAULT_MAX_SIZE,
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    generate_set_and_with! {
        /// Reject scripts larger than this
        /// (defaults to [`Self::DEFAULT_MAX_SIZE`]).
        pub fn max_size(mut self, max_size: usize) -> Self {
            self.max_size = max_size;
            self
        }
    }

    generate_set_and_with! {
        /// Budget for one fetch — connect, headers and body
        /// (defaults to [`Self::DEFAULT_TIMEOUT`]).
        pub fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }
    }
}

impl Service<Uri> for FetchPacScript {
    type Output = PacScript;
    type Error = OpaqueError;

    async fn serve(&self, uri: Uri) -> Result<Self::Output, Self::Error> {
        // `Debug` redacts the userinfo password, `Display` does not
        let fetch = async {
            let response = self
                .client
                .get(uri.clone())
                .send()
                .await
                .with_context(|| format!("fetch pac script from {uri:?}"))?;

            let status = response.status();
            if !status.is_success() {
                return Err(BoxError::from_static_str("pac script fetch failed")
                    .context_field("status", status));
            }

            response
                .try_into_string_with(CollectOptions::new().with_max_size(self.max_size))
                .await
                .context("collect pac script body")
        };

        // the timeout covers connect, headers and body alike
        let source = tokio::time::timeout(self.timeout, fetch)
            .await
            .map_err(|_elapsed| BoxError::from_static_str("pac script fetch timed out"))
            .and_then(|result| result)
            .into_opaque_error()?;

        Ok(PacScript::from(source))
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
    pub const DEFAULT_TTL: Duration = Duration::from_mins(5);

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
