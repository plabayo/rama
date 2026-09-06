use super::*;
use rama::{extensions::ExtensionsRef as _, http::StatusCode};

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
        rama::rt::spawn(async move {
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
    policy: Option<super::super::mitm_policy::MitmPolicy>,
}

impl CaptureHttpLayer {
    pub(in crate::cmd::serve::proxy) fn new(store: Option<CaptureStore>) -> Self {
        Self {
            store,
            policy: None,
        }
    }
    pub(in crate::cmd::serve::proxy) fn with_policy(
        mut self,
        policy: super::super::mitm_policy::MitmPolicy,
    ) -> Self {
        self.policy = Some(policy);
        self
    }
}

impl<S> Layer<S> for CaptureHttpLayer {
    type Service = CaptureHttpService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CaptureHttpService {
            inner,
            store: self.store.clone(),
            policy: self.policy.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub(in crate::cmd::serve::proxy) struct CaptureHttpService<S> {
    inner: S,
    store: Option<CaptureStore>,
    policy: Option<super::super::mitm_policy::MitmPolicy>,
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
        use super::super::control::{
            ControlConnection, Decision, WebSocketContext, http_message, parse_headers,
        };
        let (mut parts, body) = request.into_parts();
        let Some(store) = &self.store else {
            return self
                .inner
                .serve(Request::from_parts(parts, Body::new(body)))
                .await
                .map(|r| r.map(Body::new));
        };
        if !store.inspection_state().is_enabled() {
            return self
                .inner
                .serve(Request::from_parts(parts, Body::new(body)))
                .await
                .map(|r| r.map(Body::new));
        }
        let connection = parts
            .extensions
            .get_ref::<ControlConnection>()
            .cloned()
            .unwrap_or_else(|| store.new_control_connection());
        parts.extensions.insert(connection.clone());
        let mut message = http_message(&parts);
        let in_scope = self.policy.as_ref().is_none_or(|p| {
            rama::net::address::Host::try_from(message.host.as_str())
                .is_ok_and(|h| p.should_inspect_host(&h))
        });
        if self.policy.is_some() {
            store.control().observe(
                &connection,
                &message.host,
                in_scope,
                "HTTP authority",
                if in_scope {
                    "inspected HTTP"
                } else {
                    "outside MITM scope"
                },
            );
        }
        if !in_scope {
            return self
                .inner
                .serve(Request::from_parts(parts, Body::new(body)))
                .await
                .map(|r| r.map(Body::new));
        }
        let id = match store.begin_exchange(&parts).await {
            Ok(id) => id,
            Err(error) => {
                rama::telemetry::tracing::error!("failed to begin MITM capture: {error}");
                None
            }
        };
        message.exchange = id;
        message.connection = connection.0.id;
        if let Some(id) = id {
            parts.extensions.insert(ExchangeId(id));
        }
        let mut exchange_guard = id.map(|id| store.http_exchange_guard(id));
        let control = store.control();
        let (decision, reason) = control.decide(&connection, message.clone()).await;
        let request_body = Body::new(body);
        let local = match decision {
            Decision::Forward { headers, .. } => {
                if let Some(headers) = headers {
                    match parse_headers(&headers) {
                        Ok(headers) => parts.headers = headers,
                        Err(_) => {
                            return Ok(super::super::control::ResponseSpec::error(
                                500,
                                "Invalid interception headers",
                            )
                            .build(&message));
                        }
                    }
                }
                None
            }
            Decision::Respond { response } => Some(response.build(&message)),
            _ => Some(super::super::control::ResponseSpec::default().build(&message)),
        };
        if let (Some(id), Some(reason)) = (id, reason) {
            let outcome = format!(
                "{} · {reason}",
                if local.is_some() {
                    "Responded locally"
                } else {
                    "Forwarded"
                }
            );
            store
                .record_decision(
                    id,
                    &message,
                    &outcome,
                    local.is_none().then_some(&parts.headers),
                )
                .await;
        }
        message.conditional = matches!(
            parts.method,
            rama::http::Method::GET | rama::http::Method::HEAD
        ) && (parts
            .headers
            .contains_key(rama::http::header::IF_NONE_MATCH)
            || parts
                .headers
                .contains_key(rama::http::header::IF_MODIFIED_SINCE));
        let websocket_context = is_websocket_handshake(&parts).then(|| WebSocketContext {
            connection: connection.clone(),
            request: http_message(&parts),
        });
        if let Some(context) = &websocket_context {
            parts.extensions.insert(context.clone());
        }
        let mut response = if let Some(response) = local {
            // Discard unread body; the response closes HTTP/1 and HTTP/2 cancels only this stream.
            drop(request_body);
            if let Some(id) = id {
                store
                    .body_event(
                        id,
                        BodyDirection::Request,
                        BodyCaptureEvent::End(CaptureOutcome::Aborted),
                    )
                    .await;
            }
            response
        } else {
            let body = request_body;
            let body = if let Some(id) = id {
                Body::new(CaptureBody::new(
                    body,
                    EncryptedBodySink {
                        store: store.clone(),
                        exchange_id: id,
                        direction: BodyDirection::Request,
                    },
                ))
            } else {
                body
            };
            match self.inner.serve(Request::from_parts(parts, body)).await {
                Ok(response) => {
                    let (mut parts, body) = response.into_parts();
                    let mut original = message.clone();
                    original.direction = "response".into();
                    original.status = Some(parts.status.as_u16());
                    original.headers = headers_to_vec(&parts.headers);
                    let (decision, reason) = control.decide(&connection, original.clone()).await;
                    let mut forwarded = true;
                    let response = match decision {
                        Decision::Forward {
                            headers, status, ..
                        } => {
                            if let Some(headers) = headers {
                                match parse_headers(&headers) {
                                    Ok(headers) => parts.headers = headers,
                                    Err(_) => {
                                        return Ok(super::super::control::ResponseSpec::error(
                                            500,
                                            "Invalid interception headers",
                                        )
                                        .build(&original));
                                    }
                                }
                            }
                            if let Some(status) = status {
                                parts.status = StatusCode::from_u16(status)
                                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                            }
                            Response::from_parts(parts, Body::new(body))
                        }
                        Decision::Respond { response } => {
                            forwarded = false;
                            drop(body);
                            response.build(&original)
                        }
                        _ => {
                            forwarded = false;
                            drop(body);
                            super::super::control::ResponseSpec::default().build(&original)
                        }
                    };
                    if let (Some(id), Some(reason)) = (id, reason) {
                        store
                            .record_decision(
                                id,
                                &original,
                                &format!(
                                    "{} · {reason}",
                                    if forwarded {
                                        "Forwarded"
                                    } else {
                                        "Responded locally"
                                    }
                                ),
                                Some(response.headers()),
                            )
                            .await;
                    }
                    response
                }
                Err(error) => {
                    if let Some(id) = id {
                        store
                            .body_event(
                                id,
                                BodyDirection::Response,
                                BodyCaptureEvent::End(CaptureOutcome::Error),
                            )
                            .await;
                    }
                    if let Some(guard) = &mut exchange_guard {
                        guard.disarm();
                    }
                    return Err(error);
                }
            }
        };
        if let Some(context) = websocket_context {
            response.extensions().insert(context);
        }
        if let Some(id) = id {
            let (parts, body) = response.into_parts();
            parts.extensions.insert(ExchangeId(id));
            if let Err(error) = store.response_head(id, &parts).await {
                rama::telemetry::tracing::debug!("failed to capture response head: {error}");
            }
            if let Some(guard) =
                store.websocket_exchange_guard_for_response(id, parts.status.as_u16())
            {
                parts.extensions.insert(guard);
            }
            response = Response::from_parts(
                parts,
                Body::new(CaptureBody::new(
                    body,
                    EncryptedBodySink {
                        store: store.clone(),
                        exchange_id: id,
                        direction: BodyDirection::Response,
                    },
                )),
            );
        }
        if let Some(guard) = &mut exchange_guard {
            guard.disarm();
        }
        Ok(response)
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
        if let Some(context) = bridge
            .egress
            .extensions()
            .get_ref::<super::super::control::WebSocketContext>()
            .cloned()
        {
            bridge.ingress.extensions().insert(context);
        }
        if self.store.is_some() {
            let limits = rama::http::ws::handshake::mitm::WebSocketRelayReadAhead {
                max_messages: std::num::NonZeroUsize::MIN.saturating_add(15),
                max_bytes: std::num::NonZeroUsize::MIN.saturating_add(256 * 1024 - 1),
            };
            bridge.ingress.extensions().insert(limits);
            bridge.egress.extensions().insert(limits);
        }
        let exchange_id = bridge.egress.extensions().get_ref::<ExchangeId>().copied();
        if let Some(exchange_id) = exchange_id {
            bridge.ingress.extensions().insert(exchange_id);
        }

        let response_guard = bridge
            .egress
            .extensions()
            .get_arc::<CaptureWebSocketExchangeGuard>();
        let fallback_guard = if response_guard.is_none() {
            self.store
                .as_ref()
                .zip(exchange_id)
                .map(|(store, exchange_id)| store.websocket_exchange_guard(exchange_id.0))
        } else {
            None
        };
        let output = self.inner.serve(bridge).await;
        if let Some((store, exchange_id)) = self.store.as_ref().zip(exchange_id) {
            // Response extensions can have incidental owners beyond the
            // upgraded streams. The relay future itself is the authoritative
            // completion boundary once it starts, so finish eagerly here;
            // guard Drop remains the pre-relay failure fallback.
            store.finish_websocket_exchange(exchange_id.0);
        }
        drop(response_guard);
        drop(fallback_guard);
        output
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
        let connection = self.store.new_control_connection();
        let id = self
            .store
            .begin_observed_connection(connection.0.id, socket, self.label);
        input.extensions().insert(connection);
        if let Some(id) = id {
            input.extensions().insert(ConnectionId(id));
        }
        let _guard = id.map(|id| self.store.connection_guard(id));
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
            store.set_connection_protocol_if_enabled(id.0, self.protocol);
            if self.protocol != "http" {
                store.confirm_connection_if_enabled(id.0);
            }
        }
        self.inner.serve(input).await
    }
}
