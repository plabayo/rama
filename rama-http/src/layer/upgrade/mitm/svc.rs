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
                Service: Service<BridgeIo<Upgraded, Upgraded>, Output = (), Error: Into<BoxError>>,
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
                // The relay service reads its negotiated config from the
                // upgraded EGRESS stream's extensions (a WS relay's
                // `RelayWebSocketConfig`, carrying the agreed permessage-deflate
                // params). On HTTP/1 the upgraded stream is fulfilled from the
                // bare connection io and does NOT inherit the response
                // extensions — only the h2 client threads `res.extensions()`
                // into its upgraded io. Graft them on here so h1 and h2 behave
                // identically; without it an h1 WS relay builds its sockets
                // WITHOUT deflate and resets the first compressed frame.
                //
                // On h2 this graft is technically redundant — the upgraded
                // io's extension store and `res.extensions()` share the same
                // top-level `Arc`, so `extend` duplicates the top-level
                // entries into the same `AppendOnlyVec`. `get_ref` walks
                // newest-first and returns the (identical) duplicate, so it's
                // correctness-neutral; the cost is one extra entry per
                // top-level item per WS upgrade. Filtering to the specific
                // entries the relay reads would couple this layer to
                // rama-ws-side types (e.g. `RelayWebSocketConfig`), which
                // we'd rather not — the over-graft is bounded and benign.
                //
                // NOTE: grafted per call site rather than inside
                // `handle_upgrade` ON PURPOSE, and it grafts the ENTIRE
                // top-level of `res.extensions()` (not a curated subset).
                // This is safe because `extend` copies only the TOP-LEVEL
                // entries of the source (it does NOT walk the parent chain),
                // and a client-received response's top level is a `fork()` of
                // the request (h1: `conn.rs` client branch; h2: the stream
                // equivalent) — so it does NOT carry the connection's own
                // `Ingress`/`Egress(self.io.extensions())` self-wrapper. That
                // wrapper, when present, lives in the parent chain, which
                // `extend` skips. So grafting the response top level onto the
                // egress upgraded stream cannot introduce a back-pointer to
                // that stream's own store.
                //
                // Centralizing this inside `handle_upgrade` is NOT safe: it
                // would also run on the server-acceptor path, where the
                // request's TOP level *does* carry
                // `Ingress(self.io.extensions())` (`conn.rs:221`) and
                // `Upgraded::new` shares that same io extension `Arc`. The
                // graft would then make the io's store contain a wrapper
                // pointing back at itself — a self-referential `Extensions`
                // cycle → stack overflow on `get_ref` traversal (confirmed
                // empirically: centralizing SIGABRTs the WS suite).
                let egress_msg_ext = res.extensions().clone();
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

                    egress_stream.extensions().extend(&egress_msg_ext);

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
