//! Route requests through the proxies a PAC script selects.

use std::sync::Arc;

use rama_core::error::{BoxError, ErrorContext};
use rama_core::extensions::ExtensionsRef;
use rama_core::telemetry::tracing;
use rama_core::{Layer, Service};
use rama_http::Request;
use rama_net::client::{ProxyRoute, ProxyRoutes};
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};

use crate::PacResolver;

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
pub struct PacProxyRoutesLayer {
    resolver: Arc<PacResolver>,
    failure: PacFailurePolicy,
    overwrite: bool,
}

impl std::fmt::Debug for PacProxyRoutesLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacProxyRoutesLayer")
            .field("failure", &self.failure)
            .field("overwrite", &self.overwrite)
            .finish_non_exhaustive()
    }
}

impl Clone for PacProxyRoutesLayer {
    fn clone(&self) -> Self {
        Self {
            resolver: self.resolver.clone(),
            failure: self.failure.clone(),
            overwrite: self.overwrite,
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

        let routes = match self.layer.resolver.find_proxy(req.uri()).await {
            Ok(directives) => {
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

fn is_already_routed<Body>(req: &Request<Body>) -> bool {
    req.extensions().contains::<ProxyRoute>() || req.extensions().contains::<ProxyRoutes>()
}
