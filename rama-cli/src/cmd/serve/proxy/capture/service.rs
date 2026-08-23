use super::*;

#[derive(Clone)]
struct EncryptedBodySink {
    store: CaptureStore,
    exchange_id: u64,
    direction: BodyDirection,
}

impl BodyCaptureSink for EncryptedBodySink {
    fn capture(&self, event: BodyCaptureEvent) -> impl Future<Output = ()> + Send + 'static {
        let this = self.clone();
        async move {
            this.store
                .body_event(this.exchange_id, this.direction, event)
                .await;
        }
    }

    fn aborted(&self) {
        let this = self.clone();
        tokio::spawn(async move {
            this.store
                .body_event(
                    this.exchange_id,
                    this.direction,
                    BodyCaptureEvent::End(CaptureOutcome::Aborted),
                )
                .await;
        });
    }
}

#[derive(Debug, Clone)]
pub(in crate::cmd::serve::proxy) struct CaptureHttpLayer {
    store: Option<CaptureStore>,
}

impl CaptureHttpLayer {
    pub(in crate::cmd::serve::proxy) fn new(store: Option<CaptureStore>) -> Self {
        Self { store }
    }
}

impl<S> Layer<S> for CaptureHttpLayer {
    type Service = CaptureHttpService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CaptureHttpService {
            inner,
            store: self.store.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub(in crate::cmd::serve::proxy) struct CaptureHttpService<S> {
    inner: S,
    store: Option<CaptureStore>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for CaptureHttpService<S>
where
    S: Service<Request<Body>, Output = Response<ResBody>>,
    ReqBody:
        StreamingBody<Data = rama::bytes::Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    ResBody:
        StreamingBody<Data = rama::bytes::Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    type Output = Response<Body>;
    type Error = S::Error;

    async fn serve(&self, request: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let (parts, body) = request.into_parts();
        let Some(store) = &self.store else {
            return self
                .inner
                .serve(Request::from_parts(parts, Body::new(body)))
                .await
                .map(|response| response.map(Body::new));
        };
        let id = match store.begin_exchange(&parts).await {
            Ok(id) => id,
            Err(error) => {
                rama::telemetry::tracing::error!("failed to begin MITM capture: {error}");
                return self
                    .inner
                    .serve(Request::from_parts(parts, Body::new(body)))
                    .await
                    .map(|response| response.map(Body::new));
            }
        };
        parts.extensions.insert(ExchangeId(id));
        let request = Request::from_parts(
            parts,
            Body::new(CaptureBody::new(
                body.map_err(Into::into),
                EncryptedBodySink {
                    store: store.clone(),
                    exchange_id: id,
                    direction: BodyDirection::Request,
                },
            )),
        );
        let response = match self.inner.serve(request).await {
            Ok(response) => response,
            Err(error) => {
                store
                    .body_event(
                        id,
                        BodyDirection::Response,
                        BodyCaptureEvent::End(CaptureOutcome::Error),
                    )
                    .await;
                return Err(error);
            }
        };
        let (parts, body) = response.into_parts();
        // Upgrade relays continue from the response-side transport. Preserve
        // the capture identity on that side as well so message middleware in
        // both directions can associate WebSocket events with this exchange.
        parts.extensions.insert(ExchangeId(id));
        if let Err(error) = store.response_head(id, &parts).await {
            rama::telemetry::tracing::debug!("failed to capture response head: {error}");
        }
        Ok(Response::from_parts(
            parts,
            Body::new(CaptureBody::new(
                body.map_err(Into::into),
                EncryptedBodySink {
                    store: store.clone(),
                    exchange_id: id,
                    direction: BodyDirection::Response,
                },
            )),
        ))
    }
}

/// Bind an inspector exchange to the lifetime of the actual WebSocket relay.
///
/// Response-scoped metadata reaches the egress upgraded transport. This layer
/// copies only the inspector's typed exchange identifier to ingress so both
/// directional event streams can be associated without changing the generic
/// HTTP upgrade machinery. Completion follows the relay service future, which
/// also covers idle sockets and abnormal disconnects.
#[derive(Debug, Clone)]
pub(in crate::cmd::serve::proxy) struct CaptureWebSocketLayer {
    store: Option<CaptureStore>,
}

impl CaptureWebSocketLayer {
    pub(in crate::cmd::serve::proxy) fn new(store: Option<CaptureStore>) -> Self {
        Self { store }
    }
}

impl<S> Layer<S> for CaptureWebSocketLayer {
    type Service = CaptureWebSocketService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CaptureWebSocketService {
            inner,
            store: self.store.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub(in crate::cmd::serve::proxy) struct CaptureWebSocketService<S> {
    inner: S,
    store: Option<CaptureStore>,
}

impl<S, Ingress, Egress> Service<WebSocketBridge<Ingress, Egress>> for CaptureWebSocketService<S>
where
    S: Service<WebSocketBridge<Ingress, Egress>>,
    Ingress: rama::extensions::ExtensionsRef + Send + 'static,
    Egress: rama::extensions::ExtensionsRef + Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(
        &self,
        bridge: WebSocketBridge<Ingress, Egress>,
    ) -> Result<Self::Output, Self::Error> {
        let exchange_id = bridge.egress.extensions().get_ref::<ExchangeId>().copied();
        if let Some(exchange_id) = exchange_id {
            bridge.ingress.extensions().insert(exchange_id);
        }

        let _capture_guard = self
            .store
            .as_ref()
            .zip(exchange_id)
            .map(|(store, exchange_id)| store.websocket_exchange_guard(exchange_id.0));
        self.inner.serve(bridge).await
    }
}

#[derive(Debug, Clone)]
pub(in crate::cmd::serve::proxy) struct ObserveConnectionLayer {
    store: CaptureStore,
    label: &'static str,
}

impl ObserveConnectionLayer {
    pub(in crate::cmd::serve::proxy) fn new(store: CaptureStore, label: &'static str) -> Self {
        Self { store, label }
    }
}

impl<S> Layer<S> for ObserveConnectionLayer {
    type Service = ObserveConnectionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ObserveConnectionService {
            inner,
            store: self.store.clone(),
            label: self.label,
        }
    }
}

#[derive(Debug, Clone)]
pub(in crate::cmd::serve::proxy) struct ObserveConnectionService<S> {
    inner: S,
    store: CaptureStore,
    label: &'static str,
}

impl<S, IO> Service<IO> for ObserveConnectionService<S>
where
    IO: rama::io::Io + Unpin + rama::extensions::ExtensionsRef + 'static,
    S: Service<IO>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: IO) -> Result<Self::Output, Self::Error> {
        let socket = input.extensions().get_ref::<SocketInfo>().cloned();
        let id = self.store.begin_connection(socket, self.label);
        input.extensions().insert(ConnectionId(id));
        let _guard = self.store.connection_guard(id);
        self.inner.serve(input).await
    }
}

#[derive(Debug, Clone)]
pub(in crate::cmd::serve::proxy) struct MarkProtocolLayer {
    store: Option<CaptureStore>,
    protocol: &'static str,
}

impl MarkProtocolLayer {
    pub(in crate::cmd::serve::proxy) fn new(
        store: Option<CaptureStore>,
        protocol: &'static str,
    ) -> Self {
        Self { store, protocol }
    }
}

impl<S> Layer<S> for MarkProtocolLayer {
    type Service = MarkProtocolService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MarkProtocolService {
            inner,
            store: self.store.clone(),
            protocol: self.protocol,
        }
    }
}

#[derive(Debug, Clone)]
pub(in crate::cmd::serve::proxy) struct MarkProtocolService<S> {
    inner: S,
    store: Option<CaptureStore>,
    protocol: &'static str,
}

impl<S, IO> Service<IO> for MarkProtocolService<S>
where
    IO: rama::extensions::ExtensionsRef + Send + Sync + 'static,
    S: Service<IO>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: IO) -> Result<Self::Output, Self::Error> {
        input.extensions().insert(IngressProtocol(self.protocol));
        if let Some(id) = input.extensions().get_ref::<ConnectionId>()
            && let Some(store) = &self.store
        {
            store.set_connection_protocol(id.0, self.protocol);
            if self.protocol != "http" {
                store.confirm_connection(id.0);
            }
        }
        self.inner.serve(input).await
    }
}
