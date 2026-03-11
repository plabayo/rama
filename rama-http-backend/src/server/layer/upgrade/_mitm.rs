use std::convert::Infallible;

use rama_core::{
    Layer, Service,
    extensions::{ExtensionsMut, ExtensionsRef},
    io::BridgeIo,
    rt::Executor,
    telemetry::tracing::{self, Instrument},
};
use rama_http::{
    Body, Request, Response, io::upgrade::Upgraded, opentelemetry::version_as_protocol_version,
};
use rama_http_types::proxy::is_req_http_proxy_connect;

#[derive(Debug, Clone)]
/// Layer used to create the middleware [`HttpMitmUpgradeRelay`] service.
pub struct HttpMitmUpgradeRelayLayer<U, F> {
    exec: Executor,
    upgrade_svc: U,
    fallback_svc: F,
}

impl<U> HttpProxyConnectMitmRelayLayer<U> {
    #[inline(always)]
    #[must_use]
    /// Create a new [`HttpProxyConnectMitmRelayLayer`] used to produce
    /// the middleware [`HttpProxyConnectMitmRelay`] service.
    pub const fn new(exec: Executor, upgrade_svc: U) -> Self {
        Self { exec, upgrade_svc }
    }
}

impl<U: Clone, S> Layer<S> for HttpProxyConnectMitmRelayLayer<U> {
    type Service = HttpProxyConnectMitmRelay<U, S>;

    #[inline(always)]
    fn layer(&self, inner_svc: S) -> Self::Service {
        Self::Service {
            exec: self.exec.clone(),
            upgrade_svc: self.upgrade_svc.clone(),
            inner_svc,
        }
    }

    #[inline(always)]
    fn into_layer(self, inner_svc: S) -> Self::Service {
        Self::Service {
            exec: self.exec,
            upgrade_svc: self.upgrade_svc,
            inner_svc,
        }
    }
}

#[derive(Debug, Clone)]
/// Http middleware that can be used by MITM proxies,
/// such as transparent (L4) proxies to relay a HTTP upgrade-request
/// as-is and pipe the upgraded upgrade request on both ends
/// via the upgrade (bridgeIo) svc.
pub struct HttpProxyConnectMitmRelay<U, S> {
    exec: Executor,
    upgrade_svc: U,
    inner_svc: S,
}

impl<U, S> HttpProxyConnectMitmRelay<U, S> {
    #[inline(always)]
    #[must_use]
    /// Create a new [`HttpProxyConnectMitmRelayLayer`] used to produce
    /// the middleware [`HttpProxyConnectMitmRelay`] service.
    pub const fn new(exec: Executor, upgrade_svc: U, inner_svc: S) -> Self {
        Self {
            exec,
            upgrade_svc,
            inner_svc,
        }
    }
}

impl<U, S, ReqBody, ResBody> Service<Request<ReqBody>> for HttpProxyConnectMitmRelay<U, S>
where
    U: Service<BridgeIo<Upgraded, Upgraded>, Output = (), Error = Infallible> + Clone,
    S: Service<Request<ReqBody>, Output = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        if is_req_http_proxy_connect(&req) {
            tracing::debug!("HttpProxyConnectMitmRelay: HTTP Proxy Connect detected");

            let on_upgrade_ingress = rama_http::io::upgrade::handle_upgrade(&req);
            let req_extensions = req.extensions().clone();

            let relay_upgrade_span = tracing::trace_root_span!(
                "upgrade::mitm_relay::serve",
                otel.kind = "server",
                http.request.method = %req.method().as_str(),
                url.full = %req.uri(),
                url.path = %req.uri().path(),
                url.query = req.uri().query().unwrap_or_default(),
                url.scheme = %req.uri().scheme().map(|s| s.as_str()).unwrap_or_default(),
                network.protocol.name = "http",
                network.protocol.version = version_as_protocol_version(req.version()),
            );

            let res = self.inner_svc.serve(req).await?;
            if !res.status().is_success() {
                tracing::trace!(
                    "HttpProxyConnectMitmRelay: HTTP Proxy Connect: aborted: egress server failed response w/ status code: {}",
                    res.status()
                );
                return Ok(res);
            }

            let on_upgrade_egress = rama_http::io::upgrade::handle_upgrade(&res);
            let res_extensions = res.extensions().clone();

            tracing::trace!("HttpProxyConnectMitmRelay: spawn HTTP Proxy Connect relay svc");

            let upgrade_relay_svc = self.upgrade_svc.clone();
            self.exec.spawn_task(async move {
                tracing::debug!(
                    "HttpProxyConnectMitmRelay: HTTP Proxy Connect relay svc: spawned task active"
                );

                let (mut ingress_stream, mut egress_stream) = match tokio::try_join!(on_upgrade_ingress, on_upgrade_egress) {
                    Ok(streams) => streams,
                    Err(err) => {
                        tracing::debug!("HttpProxyConnectMitmRelay: relay task: one or both sides filed to upgrade: {err}");
                        return;
                    }
                };

                ingress_stream.extensions_mut().extend(req_extensions);
                egress_stream.extensions_mut().extend(res_extensions);

                tracing::trace!(
                    "HttpProxyConnectMitmRelay: HTTP Proxy Connect relay svc: bidirectional upgrade complete: continue serving via upgrade relay svc"
                );
                upgrade_relay_svc.serve(BridgeIo(ingress_stream, egress_stream)).await;
            }.instrument(relay_upgrade_span));

            Ok(res)
        } else {
            self.inner_svc.serve(req).await
        }
    }
}
