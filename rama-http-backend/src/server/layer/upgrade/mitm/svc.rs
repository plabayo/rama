use std::{convert::Infallible, fmt};

use rama_core::{
    Service, bytes,
    error::BoxError,
    extensions::{ExtensionsMut, ExtensionsRef as _},
    io::BridgeIo,
    matcher::service::{ServiceMatch, ServiceMatcher},
    rt::Executor,
    telemetry::tracing::{self, Instrument as _},
};
use rama_http::{
    Body, Request, Response, StreamingBody, io::upgrade::Upgraded,
    opentelemetry::version_as_protocol_version, service::web::response::IntoResponse,
};

#[derive(Debug, Clone)]
/// Http middleware that can be used by MITM proxies,
/// such as transparent (L4) proxies to relay a HTTP upgrade-request
/// as-is and pipe the upgraded upgrade request on both ends
/// via the upgrade (bridgeIo) svc.
pub struct HttpUpgradeMitmRelay<M, S> {
    exec: Executor,
    nested_matcher_svc: M,
    inner_svc: S,
}

impl<M, S> HttpUpgradeMitmRelay<M, S> {
    #[inline(always)]
    #[must_use]
    /// Create a new [`HttpUpgradeMitmRelay`].
    pub const fn new(exec: Executor, nested_matcher_svc: M, inner_svc: S) -> Self {
        Self {
            exec,
            nested_matcher_svc,
            inner_svc,
        }
    }
}

impl<M, S, ReqBody, ResBody> Service<Request<ReqBody>> for HttpUpgradeMitmRelay<M, S>
where
    M: ServiceMatcher<
            Request<ReqBody>,
            Error: IntoResponse,
            Service: ServiceMatcher<
                Response<ResBody>,
                Error: IntoResponse,
                Service: Service<BridgeIo<Upgraded, Upgraded>, Output = (), Error = Infallible>,
            >,
        >,
    S: Service<Request<ReqBody>, Output = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: StreamingBody<Data = bytes::Bytes, Error: Into<BoxError> + fmt::Display>
        + Send
        + Sync
        + 'static,
{
    type Output = Response;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let ServiceMatch {
            input: req,
            service: maybe_res_svc_matcher,
        } = match self.nested_matcher_svc.match_service(req).await {
            Ok(sm) => sm,
            Err(err) => return Ok(err.into_response()),
        };

        if let Some(res_svc_matcher) = maybe_res_svc_matcher {
            tracing::debug!(
                "HttpUpgradeMitmRelay: upgrade MITM relay req match made... opening request upgrade handle option"
            );

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

            let ServiceMatch {
                input: res,
                service: maybe_relay_svc,
            } = match res_svc_matcher.match_service(res).await {
                Ok(sm) => sm,
                Err(err) => return Ok(err.into_response()),
            };

            if let Some(relay_svc) = maybe_relay_svc {
                let on_upgrade_egress = rama_http::io::upgrade::handle_upgrade(&res);
                let res_extensions = res.extensions().clone();

                tracing::trace!("HttpUpgradeMitmRelay: spawn relay svc on its own task");

                self.exec.spawn_task(async move {
                    tracing::debug!(
                        "HttpUpgradeMitmRelay: spawned task active"
                    );

                    let (mut ingress_stream, mut egress_stream) = match tokio::try_join!(on_upgrade_ingress, on_upgrade_egress) {
                        Ok(streams) => streams,
                        Err(err) => {
                            tracing::debug!("HttpUpgradeMitmRelay: relay task: one or both sides filed to upgrade: {err}");
                            return;
                        }
                    };

                    ingress_stream.extensions_mut().extend(req_extensions);
                    egress_stream.extensions_mut().extend(res_extensions);

                    tracing::trace!(
                        "HttpUpgradeMitmRelay: relay task: bidirectional upgrade complete: continue serving via upgrade relay svc"
                    );
                    relay_svc.serve(BridgeIo(ingress_stream, egress_stream)).await;
                }.instrument(relay_upgrade_span));

                Ok(res.map(Body::new))
            } else {
                tracing::trace!("HttpUpgradeMitmRelay: aborted: no response match");
                Ok(res.map(Body::new))
            }
        } else {
            let res = self.inner_svc.serve(req).await?;
            Ok(res.map(Body::new))
        }
    }
}
