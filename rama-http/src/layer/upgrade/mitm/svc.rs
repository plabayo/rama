use super::HttpUpgradeMitmRelayExtensions;
use std::fmt;
use std::sync::Arc;

use crate::{
    Body, Request, Response, StreamingBody, io::upgrade::Upgraded,
    opentelemetry::version_as_protocol_version, service::web::response::IntoResponse,
};
use rama_core::{
    Service, bytes,
    error::{BoxError, ErrorExt as _},
    error_sink::{ErrorSink, TracingErrorSink},
    extensions::ExtensionsRef,
    io::BridgeIo,
    matcher::service::{ServiceMatch, ServiceMatcher},
    rt::Executor,
    telemetry::tracing::{self, Instrument as _},
};

#[derive(Clone)]
/// Http middleware that can be used by MITM proxies,
/// such as transparent (L4) proxies to relay a HTTP upgrade-request
/// as-is and pipe the upgraded upgrade request on both ends
/// via the upgrade (bridgeIo) svc.
///
/// Matchers and response middleware select protocol metadata with
/// [`HttpUpgradeMitmRelayExtensions`]. Request selections reach the ingress
/// transport and response selections reach the egress transport, after both
/// upgrades succeed. Each upgraded transport otherwise retains its own
/// connection or HTTP/2 stream state.
///
/// Response extensions are no longer copied wholesale onto the egress
/// transport. Middleware that relied on this behavior must explicitly select
/// the values it needs through [`HttpUpgradeMitmRelayExtensions`]; see that
/// type's migration example.
pub struct HttpUpgradeMitmRelay<M, S> {
    exec: Executor,
    nested_matcher_svc: M,
    inner_svc: S,
    error_sink: Arc<dyn ErrorSink>,
}

impl<M, S> HttpUpgradeMitmRelay<M, S> {
    #[inline(always)]
    #[must_use]
    /// Create a new [`HttpUpgradeMitmRelay`].
    pub fn new(exec: Executor, nested_matcher_svc: M, inner_svc: S) -> Self {
        Self {
            exec,
            nested_matcher_svc,
            inner_svc,
            error_sink: Arc::new(TracingErrorSink::default()),
        }
    }

    /// Set a custom [`ErrorSink`] used to observe errors from the detached
    /// relay task (relay-service failures and upgrade failures on either side).
    ///
    /// Defaults to [`TracingErrorSink::default`] (traces at DEBUG level).
    #[must_use]
    pub fn with_error_sink(mut self, sink: impl ErrorSink) -> Self {
        self.error_sink = Arc::new(sink);
        self
    }
}

impl<M: fmt::Debug, S: fmt::Debug> fmt::Debug for HttpUpgradeMitmRelay<M, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpUpgradeMitmRelay")
            .field("exec", &self.exec)
            .field("nested_matcher_svc", &self.nested_matcher_svc)
            .field("inner_svc", &self.inner_svc)
            .finish()
    }
}

impl<M, S, ReqBody, ModReqBody, ResBody, ModResBody> Service<Request<ReqBody>>
    for HttpUpgradeMitmRelay<M, S>
where
    M: ServiceMatcher<
            Request<ReqBody>,
            Error: IntoResponse,
            ModifiedInput = Request<ModReqBody>,
            Service: ServiceMatcher<
                Response<ResBody>,
                Error: Into<S::Error>,
                ModifiedInput = Response<ModResBody>,
                Service: Service<BridgeIo<Upgraded, Upgraded>, Error: Into<BoxError>>,
            >,
        >,
    S: Service<Request, Output = Response<ResBody>>,
    ReqBody: StreamingBody<Data = bytes::Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    ModReqBody: StreamingBody<Data = bytes::Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    ResBody: StreamingBody<Data = bytes::Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    ModResBody: StreamingBody<Data = bytes::Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
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
            tracing::debug!("HttpUpgradeMitmRelay: upgrade MITM relay req match made...");

            // Select only this message's explicit payload, never a parent's
            // selection or the message's structural connection/upgrade state.
            let ingress_extensions = req
                .extensions()
                .self_get_ref::<HttpUpgradeMitmRelayExtensions>()
                .cloned();
            let on_upgrade_ingress = crate::io::upgrade::handle_upgrade(&req);

            let relay_upgrade_span = tracing::trace_root_span!(
                "upgrade::mitm_relay::serve",
                otel.kind = "server",
                http.request.method = %req.method().as_str(),
                url.full = %req.request_uri(),
                url.path = %req.uri().path_or_root().as_ref(),
                url.query = %req.uri().query_or_empty().as_ref(),
                url.scheme = %req.uri().scheme_str().unwrap_or_default(),
                network.protocol.name = "http",
                network.protocol.version = version_as_protocol_version(req.version()),
            );

            tracing::trace!(
                "HttpUpgradeMitmRelay: matched req flow: request response from inner svc"
            );

            let res = self.inner_svc.serve(req.map(Body::new)).await?;

            tracing::trace!(
                "HttpUpgradeMitmRelay: matched req flow: received res from inner flow... continue match making"
            );

            let ServiceMatch {
                input: res,
                service: maybe_relay_svc,
            } = res_svc_matcher
                .into_match_service(res)
                .await
                .map_err(Into::into)?;

            if let Some(relay_svc) = maybe_relay_svc {
                tracing::debug!(
                    "HttpUpgradeMitmRelay: upgrade MITM relay res match made... spawning relay task..."
                );

                let on_upgrade_egress = crate::io::upgrade::handle_upgrade(&res);
                // Reserve the shared selection before returning the response:
                // outer middleware can still append capture/inspection state
                // before the server completes the ingress upgrade.
                let egress_extensions = res
                    .extensions()
                    .self_get_ref_or_insert(HttpUpgradeMitmRelayExtensions::default)
                    .clone();
                let error_sink = self.error_sink.clone();
                tracing::trace!("HttpUpgradeMitmRelay: spawn relay svc on its own task");

                self.exec.spawn_task(async move {
                    tracing::debug!(
                        "HttpUpgradeMitmRelay: spawned task active"
                    );

                    let (ingress_stream, egress_stream) = match tokio::try_join!(on_upgrade_ingress, on_upgrade_egress) {
                        Ok(streams) => streams,
                        Err(err) => {
                            // routed to the sink instead of swallowed: the relay
                            // task is detached, so this is its only error outlet.
                            error_sink.sink_error(
                                err.context("mitm relay: upgrade failed on one or both sides"),
                            );
                            return;
                        }
                    };

                    if let Some(extensions) = ingress_extensions {
                        ingress_stream.extensions().extend(&extensions.0);
                    }
                    egress_stream.extensions().extend(&egress_extensions.0);

                    tracing::trace!(
                        "HttpUpgradeMitmRelay: relay task: bidirectional upgrade complete: continue serving via upgrade relay svc"
                    );
                    if let Err(err) = relay_svc.serve(BridgeIo(ingress_stream, egress_stream)).await {
                        error_sink.sink_error(err.context("mitm relay handler failed"));
                    }
                }.instrument(relay_upgrade_span));

                Ok(res.map(Body::new))
            } else {
                tracing::debug!(
                    "HttpUpgradeMitmRelay: aborted: req was matched... but no response match"
                );
                Ok(res.map(Body::new))
            }
        } else {
            let res = self.inner_svc.serve(req.map(Body::new)).await?;
            Ok(res.map(Body::new))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::upgrade::{self, OnUpgrade};
    use rama_core::{
        ServiceInput,
        extensions::{Extension, Extensions},
        matcher::service::MatcherServicePair,
        service::service_fn,
    };
    use std::{convert::Infallible, time::Duration};

    #[derive(Debug, PartialEq, Extension)]
    struct Selected(&'static str);
    #[derive(Debug, Extension)]
    struct MessageOnly;
    #[derive(Debug, Extension)]
    struct Lifetime(#[expect(dead_code, reason = "lifetime probe")] Arc<()>);

    fn upgraded() -> Upgraded {
        Upgraded::new(
            ServiceInput::new(tokio::io::duplex(64).0),
            bytes::Bytes::new(),
        )
    }

    async fn bounded<T>(future: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(3), future)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn transfers_only_explicit_message_local_metadata_to_each_side() {
        for response_selection in [false, true] {
            let (ingress_pending, ingress_upgrade) = upgrade::pending();
            let (egress_pending, egress_upgrade) = upgrade::pending();
            let ingress = upgraded();
            let egress = upgraded();
            let ingress_transport = ingress.extensions().parent().unwrap().clone();
            let egress_transport = egress.extensions().parent().unwrap().clone();
            ingress_pending.fulfill(ingress);
            egress_pending.fulfill(egress);

            let req = Request::new(Body::empty());
            req.extensions().insert(ingress_upgrade);
            req.extensions().insert(MessageOnly);
            let selected = HttpUpgradeMitmRelayExtensions::default();
            selected.0.insert(Selected("ingress"));
            req.extensions().insert(selected);
            let upstream = service_fn(move |req: Request| {
                let res = Response::new(Body::empty()).with_extensions(req.extensions().fork());
                res.extensions().insert(egress_upgrade.clone());
                res.extensions().insert(MessageOnly);
                if response_selection {
                    let selected = HttpUpgradeMitmRelayExtensions::default();
                    selected.0.insert(Selected("egress"));
                    res.extensions().insert(selected);
                }
                async { Ok::<_, Infallible>(res) }
            });
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let relay = service_fn(move |bridge: BridgeIo<Upgraded, Upgraded>| {
                tx.send(bridge).unwrap();
                async { Ok::<_, Infallible>(()) }
            });
            let matcher = MatcherServicePair::new(true, MatcherServicePair::new(true, relay));
            let res = HttpUpgradeMitmRelay::new(Executor::new(), matcher, upstream)
                .serve(req)
                .await
                .unwrap();
            let BridgeIo(ingress, egress) = bounded(rx.recv()).await.unwrap();
            assert_eq!(
                ingress.extensions().get_ref::<Selected>(),
                Some(&Selected("ingress"))
            );
            assert_eq!(
                egress.extensions().get_ref::<Selected>(),
                response_selection.then_some(&Selected("egress"))
            );
            for stream in [&ingress, &egress] {
                assert!(stream.extensions().get_ref::<MessageOnly>().is_none());
                assert!(stream.extensions().get_ref::<OnUpgrade>().is_none());
                assert!(
                    stream
                        .extensions()
                        .get_ref::<HttpUpgradeMitmRelayExtensions>()
                        .is_none()
                );
            }
            for transport in [ingress_transport, egress_transport] {
                assert!(transport.get_ref::<Selected>().is_none());
            }
            drop(res);
        }
    }

    #[tokio::test]
    async fn either_upgrade_failure_releases_selected_metadata_and_reports_error() {
        for fail_ingress in [false, true] {
            let (ingress_pending, ingress_upgrade) = upgrade::pending();
            let (egress_pending, egress_upgrade) = upgrade::pending();
            let req = Request::new(Body::empty());
            req.extensions().insert(ingress_upgrade);
            let ingress_lifetime = Arc::new(());
            let ingress_weak = Arc::downgrade(&ingress_lifetime);
            let selected = HttpUpgradeMitmRelayExtensions::default();
            selected.0.insert(Lifetime(ingress_lifetime));
            req.extensions().insert(selected);
            let egress_lifetime = Arc::new(());
            let egress_weak = Arc::downgrade(&egress_lifetime);
            let response_extensions = Extensions::new();
            response_extensions.insert(egress_upgrade);
            let selected = HttpUpgradeMitmRelayExtensions::default();
            selected.0.insert(Lifetime(egress_lifetime));
            response_extensions.insert(selected);
            let upstream = service_fn(move |_: Request| {
                let res = Response::new(Body::empty()).with_extensions(response_extensions.clone());
                async { Ok::<_, Infallible>(res) }
            });
            let relay = service_fn(|_: BridgeIo<Upgraded, Upgraded>| async {
                panic!("a failed upgrade must not invoke the relay");
                #[expect(unreachable_code, reason = "fix the service result type")]
                Ok::<_, Infallible>(())
            });
            let matcher = MatcherServicePair::new(true, MatcherServicePair::new(true, relay));
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let service = HttpUpgradeMitmRelay::new(Executor::new(), matcher, upstream)
                .with_error_sink(move |error: BoxError| {
                    tx.send(error.to_string()).unwrap();
                });
            let res = service.serve(req).await.unwrap();
            drop((res, service));
            if fail_ingress {
                egress_pending.fulfill(upgraded());
                drop(ingress_pending);
            } else {
                ingress_pending.fulfill(upgraded());
                drop(egress_pending);
            }
            let error = bounded(rx.recv()).await.unwrap();
            assert!(error.contains("mitm relay: upgrade failed on one or both sides"));
            // Channel closure proves the detached task has finished dropping
            // its selected payloads, rather than racing its error callback.
            assert!(bounded(rx.recv()).await.is_none());
            assert!(ingress_weak.upgrade().is_none());
            assert!(egress_weak.upgrade().is_none());
        }
    }
}
