use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use rama_core::Layer;

use super::origin::{Origins, parse_trusted_origin};
use super::service::Csrf;
use super::{BypassFn, ConfigError, DebugFn, DefaultResponseForProtectionError};
use crate::Method;
use rama_net::uri::Uri;

/// Layer that applies the [`Csrf`] middleware.
///
/// See the [module docs](crate::layer::csrf) for an example.
#[derive(Clone)]
#[must_use]
pub struct CsrfLayer<T = DefaultResponseForProtectionError> {
    insecure_bypass: Option<Arc<BypassFn>>,
    rejection_response: T,
    trusted_origins: Origins,
}

impl Default for CsrfLayer {
    fn default() -> Self {
        Self {
            insecure_bypass: None,
            rejection_response: DefaultResponseForProtectionError,
            trusted_origins: Origins::default(),
        }
    }
}

impl<T> Debug for CsrfLayer<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CsrfLayer")
            .field(
                "insecure_bypass",
                &self.insecure_bypass.as_ref().map(|_| DebugFn),
            )
            .field("trusted_origins", &self.trusted_origins)
            .field("rejection_response", &DebugFn)
            .finish()
    }
}

impl CsrfLayer {
    /// Creates a new `CsrfLayer` with no trusted origins, no bypass, and the default rejection
    /// response.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<T> CsrfLayer<T> {
    /// Adds a trusted origin that allows all requests whose `Origin` matches the given value.
    ///
    /// The value is compared **structurally** (via [`rama_net::uri::Uri`]) against the request's
    /// `Origin`: the host is matched case-insensitively and a default port compares equal whether
    /// written explicitly or omitted. The input must be a bare origin of the form
    /// `scheme://host[:port]` with an `http`/`https` scheme and no userinfo, path, query, or
    /// fragment; anything else is rejected with a [`ConfigError`].
    pub fn add_trusted_origin<S: AsRef<str>>(mut self, origin: S) -> Result<Self, ConfigError> {
        let origin = parse_trusted_origin(origin.as_ref())?;
        self.trusted_origins.insert(origin);
        Ok(self)
    }

    /// Adds a bypass predicate that returns `true` for requests which should skip CSRF protection.
    ///
    /// This is an escape hatch for endpoints that legitimately need to accept cross-origin POSTs
    /// (e.g. webhook receivers). Bypassed endpoints must have their own protection (signed
    /// payloads, authentication tokens, etc.) — otherwise they are CSRF-vulnerable.
    pub fn with_insecure_bypass<F>(mut self, predicate: F) -> Self
    where
        F: Fn(&Method, &Uri) -> bool + Send + Sync + 'static,
    {
        self.insecure_bypass = Some(Arc::new(predicate));
        self
    }

    /// Replaces the response builder used when a request is rejected.
    ///
    /// Accepts any type that implements
    /// [`ResponseForProtectionError`](super::ResponseForProtectionError), including a
    /// `Fn(ProtectionError) -> Response<B> + Clone + Send + Sync + 'static` closure. The default
    /// builder returns a `403 Forbidden` with an empty body. Regardless of the builder,
    /// [`Csrf`](super::Csrf) attaches the [`ProtectionError`](super::ProtectionError) to the
    /// response's extensions, so a custom builder need not re-attach it.
    pub fn with_rejection_response<R>(self, rejection_response: R) -> CsrfLayer<R>
    where
        R: Clone,
    {
        CsrfLayer {
            insecure_bypass: self.insecure_bypass,
            trusted_origins: self.trusted_origins,
            rejection_response,
        }
    }
}

impl<S, T> Layer<S> for CsrfLayer<T>
where
    T: Clone,
{
    type Service = Csrf<S, T>;

    fn layer(&self, inner: S) -> Self::Service {
        Csrf::new(
            inner,
            self.insecure_bypass.clone(),
            self.rejection_response.clone(),
            self.trusted_origins.clone(),
        )
    }

    fn into_layer(self, inner: S) -> Self::Service {
        Csrf::new(
            inner,
            self.insecure_bypass,
            self.rejection_response,
            self.trusted_origins,
        )
    }
}
