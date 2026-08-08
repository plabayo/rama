//! Route requests through the proxies a PAC script selects.

use std::num::NonZeroUsize;
use std::sync::Arc;

use rama_core::error::{BoxError, BoxErrorExt, ErrorContext};
use rama_core::extensions::ExtensionsRef;
use rama_core::telemetry::tracing;
use rama_core::{Layer, Service};
use rama_http::Request;
use rama_net::client::{ProxyRoute, ProxyRoutes};
use rama_net::uri::Uri;
use rama_net::{AuthorityInputExt, Protocol, ProtocolInputExt};
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};

use crate::PacResolver;

/// Default maximum number of routes one script verdict may publish.
pub const DEFAULT_PAC_MAX_ROUTES: NonZeroUsize = NonZeroUsize::new(8).unwrap();

/// What to route through when the script cannot be consulted.
#[derive(Debug, Clone, Default)]
pub enum PacFailurePolicy {
    /// Fail the request. The default: silently sending traffic
    /// unproxied is the kind of surprise a proxy must not spring.
    #[default]
    Fail,
    /// Connect without a proxy, as browsers do.
    Direct,
    /// Route through these instead.
    Routes(ProxyRoutes),
}

/// Inserts the [`ProxyRoutes`] a PAC script selects for each request, for
/// a [`ProxyRoutesConnector`][rama_net::client::ProxyRoutesConnector]
/// further down the stack to connect through.
///
/// A request that already carries a [`ProxyRoute`] or [`ProxyRoutes`] is
/// left alone and the script is not consulted at all, unless
/// [`overwrite`][Self::with_overwrite] says otherwise.
///
/// A verdict publishes at most [`DEFAULT_PAC_MAX_ROUTES`] routes, so a
/// script cannot decide that one request is worth an unbounded number of
/// connect attempts — see [`max_routes`][Self::with_max_routes].
pub struct PacProxyRoutesLayer {
    resolver: Arc<PacResolver>,
    failure: PacFailurePolicy,
    overwrite: bool,
    max_routes: Option<NonZeroUsize>,
}

impl std::fmt::Debug for PacProxyRoutesLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacProxyRoutesLayer")
            .field("failure", &self.failure)
            .field("overwrite", &self.overwrite)
            .field("max_routes", &self.max_routes)
            .finish_non_exhaustive()
    }
}

impl Clone for PacProxyRoutesLayer {
    fn clone(&self) -> Self {
        Self {
            resolver: self.resolver.clone(),
            failure: self.failure.clone(),
            overwrite: self.overwrite,
            max_routes: self.max_routes,
        }
    }
}

impl PacProxyRoutesLayer {
    /// Route through what the given resolver's script selects.
    #[must_use]
    pub fn new(resolver: Arc<PacResolver>) -> Self {
        Self {
            resolver,
            failure: PacFailurePolicy::default(),
            overwrite: false,
            max_routes: Some(DEFAULT_PAC_MAX_ROUTES),
        }
    }

    generate_set_and_with! {
        /// What to route through when the script cannot be consulted
        /// (defaults to [`PacFailurePolicy::Fail`]).
        pub fn failure_policy(mut self, failure: PacFailurePolicy) -> Self {
            self.failure = failure;
            self
        }
    }

    generate_set_and_with! {
        /// Consult the script even when the request already carries a
        /// route, and let its verdict win (defaults to `false`).
        pub fn overwrite(mut self, overwrite: bool) -> Self {
            self.overwrite = overwrite;
            self
        }
    }

    generate_set_and_with! {
        /// How many routes a verdict may publish; the rest are dropped
        /// (defaults to [`DEFAULT_PAC_MAX_ROUTES`]).
        ///
        /// Every published route is a connect attempt the connector may
        /// make for a single request. Use
        /// [`without_max_routes`][Self::without_max_routes] to trust the
        /// script with an unbounded list.
        pub fn max_routes(mut self, max_routes: Option<NonZeroUsize>) -> Self {
            self.max_routes = max_routes;
            self
        }
    }
}

impl<S> Layer<S> for PacProxyRoutesLayer {
    type Service = PacProxyRoutesService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PacProxyRoutesService {
            inner,
            layer: self.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        PacProxyRoutesService { inner, layer: self }
    }
}

/// See [`PacProxyRoutesLayer`].
#[derive(Debug, Clone)]
pub struct PacProxyRoutesService<S> {
    inner: S,
    layer: PacProxyRoutesLayer,
}

impl<S> PacProxyRoutesService<S> {
    define_inner_service_accessors!();
}

impl<S, Body> Service<Request<Body>> for PacProxyRoutesService<S>
where
    S: Service<Request<Body>, Error: Into<BoxError>>,
    Body: Send + 'static,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, req: Request<Body>) -> Result<Self::Output, Self::Error> {
        if !self.layer.overwrite && is_already_routed(&req) {
            return self.inner.serve(req).await.map_err(Into::into);
        }

        // the uri is resolved before the await: the script call must not
        // borrow the request
        let resolved = match pac_uri(&req) {
            Ok(uri) => self.layer.resolver.find_proxy(&uri).await,
            Err(err) => Err(err),
        };

        let routes = match resolved {
            Ok(mut directives) => {
                if let Some(max_routes) = self.layer.max_routes {
                    let dropped = directives.truncate(max_routes.get());
                    if dropped > 0 {
                        tracing::debug!(
                            pac.dropped_routes = dropped,
                            pac.max_routes = max_routes.get(),
                            "pac verdict published more routes than allowed",
                        );
                    }
                }
                tracing::trace!(pac.directives = %directives, "pac routed request");
                directives
                    .into_proxy_routes()
                    .with_overwrite(self.layer.overwrite)
            }
            Err(err) => match &self.layer.failure {
                PacFailurePolicy::Fail => {
                    return Err(err).context("evaluate pac script for request");
                }
                PacFailurePolicy::Direct => {
                    tracing::debug!("pac evaluation failed, going direct: {err}");
                    ProxyRoutes::new([ProxyRoute::Direct]).with_overwrite(self.layer.overwrite)
                }
                PacFailurePolicy::Routes(routes) => {
                    tracing::debug!("pac evaluation failed, using the fallback routes: {err}");
                    routes.clone().with_overwrite(self.layer.overwrite)
                }
            },
        };

        req.extensions().insert(routes);
        self.inner.serve(req).await.map_err(Into::into)
    }
}

/// The uri to consult the script for: the request uri when it carries the
/// target, else the authority the connector below will dial — SNI,
/// `Forwarded` or the `Host` header — grafted onto the request's path.
fn pac_uri<Body>(req: &Request<Body>) -> Result<Uri, BoxError> {
    let uri = req.uri();
    if uri.host().is_some() {
        return Ok(uri.clone());
    }

    let authority = req
        .authority()
        .ok_or_else(|| BoxError::from_static_str("request has no resolvable authority"))?;
    let protocol = req.protocol().cloned().unwrap_or(Protocol::HTTP);
    // browsers never show a default port to the script, and an explicit one
    // would defeat a `shExpMatch(url, "https://*.corp/*")` rule
    let authority = authority.without_default_port_for(Some(&protocol));

    if uri.is_asterisk() {
        // asterisk-form has no path or query to keep
        let mut synthetic = Uri::from_authority(protocol, authority);
        synthetic.ensure_path_or_root();
        return Ok(synthetic);
    }

    Ok(uri
        .clone()
        .with_authority(authority.into())
        .with_scheme(protocol))
}

fn is_already_routed<Body>(req: &Request<Body>) -> bool {
    req.extensions().contains::<ProxyRoute>() || req.extensions().contains::<ProxyRoutes>()
}
