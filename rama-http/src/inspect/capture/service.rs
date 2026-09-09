use rama_core::extensions::ExtensionsRef as _;

use super::*;
use crate::inspect::control::{ControlConnection, Decision, HttpUpgradeContext, http_message};

#[derive(Clone)]
struct CaptureBodySink {
    store: CaptureStore,
    exchange_id: u64,
    direction: BodyDirection,
}

impl BodyCaptureSink for CaptureBodySink {
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
        rama_core::rt::spawn(async move {
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
pub struct CaptureHttpLayer {
    store: Option<CaptureStore>,
    policy: Option<crate::inspect::mitm_policy::MitmPolicy>,
}

impl CaptureHttpLayer {
    pub fn new(store: Option<CaptureStore>) -> Self {
        Self {
            store,
            policy: None,
        }
    }

    #[must_use]
    pub fn with_policy(mut self, policy: crate::inspect::mitm_policy::MitmPolicy) -> Self {
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
pub struct CaptureHttpService<S> {
    inner: S,
    store: Option<CaptureStore>,
    policy: Option<crate::inspect::mitm_policy::MitmPolicy>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for CaptureHttpService<S>
where
    S: Service<Request<Body>, Output = Response<ResBody>>,
    ReqBody: StreamingBody<Data = rama_core::bytes::Bytes, Error: Into<BoxError>>
        + Send
        + Sync
        + 'static,
    ResBody: StreamingBody<Data = rama_core::bytes::Bytes, Error: Into<BoxError>>
        + Send
        + Sync
        + 'static,
{
    type Output = Response<Body>;
    type Error = S::Error;

    async fn serve(&self, request: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
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
            message
                .host
                .as_ref()
                .is_some_and(|host| p.should_inspect_host(host))
        });
        if self.policy.is_some()
            && let Some(host) = &message.host
        {
            store.control().observe(
                &connection,
                host,
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
                rama_core::telemetry::tracing::error!("failed to begin MITM capture: {error}");
                None
            }
        };
        message.exchange = id;
        message.connection = connection.0.id;
        if let Some(id) = id {
            parts.extensions.insert(HttpExchangeId(id));
        }
        let mut exchange_guard = id.map(|id| store.http_exchange_guard(id));
        let control = store.control();
        let (decision, reason) = control.decide(&connection, message.clone()).await;
        let request_body = Body::new(body);
        let local = match decision {
            Decision::Forward { headers, .. } => {
                if let Some(headers) = headers {
                    parts.headers = headers;
                }
                None
            }
            Decision::Respond { response } => Some(response.build(&message)),
            _ => Some(crate::inspect::control::ResponseSpec::default().build(&message)),
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
        message.conditional = matches!(parts.method, crate::Method::GET | crate::Method::HEAD)
            && (parts.headers.contains_key(crate::header::IF_NONE_MATCH)
                || parts.headers.contains_key(crate::header::IF_MODIFIED_SINCE));
        let upgrade_context = is_upgrade_request(&parts).then(|| HttpUpgradeContext {
            connection: connection.clone(),
            request: http_message(&parts),
        });
        if let Some(context) = &upgrade_context {
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
                    CaptureBodySink {
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
                    original.direction = crate::inspect::control::Direction::Egress;
                    original.status = Some(parts.status);
                    original.headers = parts.headers.clone();
                    let (decision, reason) = control.decide(&connection, original.clone()).await;
                    let mut forwarded = true;
                    let response = match decision {
                        Decision::Forward {
                            headers, status, ..
                        } => {
                            if let Some(headers) = headers {
                                parts.headers = headers;
                            }
                            if let Some(status) = status {
                                parts.status = status;
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
                            crate::inspect::control::ResponseSpec::default().build(&original)
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
                                forwarded.then(|| response.headers()),
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
        if let Some(context) = upgrade_context {
            response.extensions().insert(context);
        }
        if let Some(id) = id {
            let (parts, body) = response.into_parts();
            parts.extensions.insert(HttpExchangeId(id));
            if let Err(error) = store.response_head(id, &parts).await {
                rama_core::telemetry::tracing::debug!("failed to capture response head: {error}");
            }
            if let Some(guard) = store.upgrade_guard_for_response(id, parts.status.as_u16()) {
                parts.extensions.insert(guard);
            }
            response = Response::from_parts(
                parts,
                Body::new(CaptureBody::new(
                    body,
                    CaptureBodySink {
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

#[derive(Debug, Clone)]
pub struct MarkProtocolLayer {
    store: Option<CaptureStore>,
    protocol: Protocol,
}

impl MarkProtocolLayer {
    pub fn new(store: Option<CaptureStore>, protocol: Protocol) -> Self {
        Self { store, protocol }
    }
}

impl<S> Layer<S> for MarkProtocolLayer {
    type Service = MarkProtocolService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MarkProtocolService {
            inner,
            store: self.store.clone(),
            protocol: self.protocol.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MarkProtocolService<S> {
    inner: S,
    store: Option<CaptureStore>,
    protocol: Protocol,
}

impl<S, IO> Service<IO> for MarkProtocolService<S>
where
    IO: rama_core::extensions::ExtensionsRef + Send + Sync + 'static,
    S: Service<IO>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: IO) -> Result<Self::Output, Self::Error> {
        if let Some(id) = input.extensions().get_ref::<ConnectionId>()
            && let Some(store) = &self.store
        {
            store.set_connection_protocol_if_enabled(id.0, self.protocol.clone());
            if self.protocol != Protocol::HTTP {
                store.confirm_connection_if_enabled(id.0);
            }
        }
        self.inner.serve(input).await
    }
}

#[derive(Debug, Clone)]
pub struct ObserveConnectionLayer {
    store: CaptureStore,
    label: Protocol,
}

impl ObserveConnectionLayer {
    pub fn new(store: CaptureStore, label: Protocol) -> Self {
        Self { store, label }
    }
}

impl<S> Layer<S> for ObserveConnectionLayer {
    type Service = ObserveConnectionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ObserveConnectionService {
            inner,
            store: self.store.clone(),
            label: self.label.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ObserveConnectionService<S> {
    inner: S,
    store: CaptureStore,
    label: Protocol,
}

impl<S, IO> Service<IO> for ObserveConnectionService<S>
where
    IO: rama_core::io::Io + Unpin + rama_core::extensions::ExtensionsRef + 'static,
    S: Service<IO>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: IO) -> Result<Self::Output, Self::Error> {
        let socket = input.extensions().get_ref::<SocketInfo>().cloned();
        let connection = self.store.new_control_connection();
        let id = self
            .store
            .begin_observed_connection(connection.0.id, socket, self.label.clone());
        input.extensions().insert(connection);
        if let Some(id) = id {
            input.extensions().insert(ConnectionId(id));
        }
        let _guard = id.map(|id| self.store.connection_guard(id));
        self.inner.serve(input).await
    }
}
