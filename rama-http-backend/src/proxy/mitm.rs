use std::convert::TryFrom;
use std::sync::Arc;

use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    extensions::ExtensionsMut,
    graceful::{Shutdown, ShutdownGuard},
    io::{BridgeIo, GracefulIo, Io},
    layer::{
        ArcLayer, ConsumeErrLayer,
        consume_err::{StaticOutput, Trace},
    },
    rt::Executor,
    service::service_fn,
    telemetry::tracing,
};
use rama_http::{
    Body, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, Version,
    service::web::response::IntoResponse,
};
use rama_http_core::server::conn::{
    auto::Builder as AutoConnBuilder, http1::Builder as Http1ConnBuilder,
    http2::Builder as H2ConnBuilder,
};
use rama_net::client::EstablishedClientConnection;

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::{
    client::{HttpClientService, http_connect},
    server::HttpServer,
};

#[derive(Debug, Clone, Copy, Default)]
/// Default [`Response`] used in case the inner (egress)
/// client of the [`HttpMitmRelay`] is erroring.
pub struct DefaultErrorResponse;

impl DefaultErrorResponse {
    #[inline(always)]
    pub fn new() -> Self {
        Self
    }

    #[inline(always)]
    fn response() -> Response {
        (
            [
                (
                    HeaderName::from_static("x-proxy-framework-name"),
                    HeaderValue::from_static(rama_utils::info::NAME),
                ),
                (
                    HeaderName::from_static("x-proxy-framework-version"),
                    HeaderValue::from_static(rama_utils::info::VERSION),
                ),
            ],
            StatusCode::BAD_GATEWAY,
        )
            .into_response()
    }

    #[inline(always)]
    fn response_for_version(version: Version) -> Response {
        let mut response = Self::response();
        if matches!(
            version,
            Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11
        ) {
            response.headers_mut().insert(
                HeaderName::from_static("connection"),
                HeaderValue::from_static("close"),
            );
        }
        response
    }

    #[inline(always)]
    fn best_effort_response_after_ingress_cancellation(version: Version) -> Response {
        // Once ingress cancellation has fired, GracefulIo may cut off the downstream transport
        // before this response can actually be written. This placeholder only exists because
        // the service contract still requires a response value.
        Self::response_for_version(version)
    }

    #[inline(always)]
    fn cancel_ingress_and_return_best_effort_response(
        version: Version,
        close_ingress: &CancellationToken,
    ) -> Response {
        close_ingress.cancel();
        Self::best_effort_response_after_ingress_cancellation(version)
    }
}

impl From<DefaultErrorResponse> for Response {
    #[inline(always)]
    fn from(_: DefaultErrorResponse) -> Self {
        DefaultErrorResponse::response()
    }
}

/// Default middleware used by [`HttpMitmRelay`],
/// most likely you'll want to overwrite it with custom middleware,
/// unless you do not require MITM middleware.
pub type DefaultMiddleware = (
    ConsumeErrLayer<Trace, StaticOutput<DefaultErrorResponse>>,
    ArcLayer,
);

#[derive(Debug, Clone)]
/// A utility that can be used by MITM services such as transparent proxies,
/// in order to relay HTTP requests and responses between a client and server,
/// as part of a deep protocol inspection protocol (DPI) flow.
///
/// Useful if you have a fairly standard MITM http flow and already
/// have pre-established ingress and egress connections (e.g. because
/// you already MITM'd the <L7 layers, such as SOCKS5 MITM'ng, TLS, ...).
pub struct HttpMitmRelay<M = DefaultMiddleware> {
    http_server: HttpServer<AutoConnBuilder>,
    middleware: M,
    exec: Executor,
}

impl HttpMitmRelay {
    #[inline(always)]
    #[must_use]
    /// Create a new [`HttpMitmRelay`], ready to serve.
    pub fn new(exec: Executor) -> Self {
        let mut http_server = HttpServer::auto(exec.clone());
        http_server.h2_mut().set_enable_connect_protocol();
        Self {
            http_server,
            middleware: (
                ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse),
                ArcLayer::new(),
            ),
            exec,
        }
    }

    /// Set HTTP middleware to use between server and client.
    ///
    /// By default the identity middleware `()` is used,
    /// which preserves the requests and responses as is...
    pub fn with_http_middleware<M>(self, middleware: M) -> HttpMitmRelay<M> {
        HttpMitmRelay {
            http_server: self.http_server,
            middleware,
            exec: self.exec,
        }
    }
}

impl<M> HttpMitmRelay<M> {
    #[inline(always)]
    /// Http1 builder.
    pub fn http1(&self) -> &Http1ConnBuilder {
        self.http_server.http1()
    }

    #[inline(always)]
    /// Http1 mutable builder.
    pub fn http1_mut(&mut self) -> &mut Http1ConnBuilder {
        self.http_server.http1_mut()
    }

    #[inline(always)]
    /// H2 builder.
    pub fn h2(&self) -> &H2ConnBuilder {
        self.http_server.h2()
    }

    #[inline(always)]
    /// H2 mutable builder.
    pub fn h2_mut(&mut self) -> &mut H2ConnBuilder {
        self.http_server.h2_mut()
    }
}

impl<Ingress, Egress, M> Service<BridgeIo<Ingress, Egress>> for HttpMitmRelay<M>
where
    Ingress: Io + Unpin + ExtensionsMut,
    Egress: Io + Unpin + ExtensionsMut,
    M: Layer<
            HttpClientService<Body>,
            Service: Service<Request, Output = Response, Error: Into<BoxError>> + Clone,
        >
        + Send
        + Sync
        + 'static
        + Clone,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(
        &self,
        BridgeIo(ingress_stream, egress_stream): BridgeIo<Ingress, Egress>,
    ) -> Result<Self::Output, Self::Error> {
        let token = CancellationToken::new();
        let cancelled = token.clone().cancelled_owned();

        // TODO: see if <https://github.com/plabayo/rama/issues/830>,
        // warrants this logic to change also slightly, relating to the graceful setup...

        let graceful_guard = self.exec.guard().cloned();
        let graceful = Shutdown::new(async move {
            if let Some(guard) = graceful_guard {
                tokio::select! {
                    _ = cancelled => {
                        tracing::trace!("HTTP MITM Relay: Shutdown: cancelation token");
                    },
                    _ = guard.cancelled() => {
                        tracing::trace!("HTTP MITM Relay: Shutdown: parent guard cancellation");
                    },
                }
            } else {
                let _ = cancelled.await;
            }
        });

        let _cancel_guard = token.clone().drop_guard();
        let relay_state = Arc::new(Mutex::new(RelayState::new(
            egress_stream,
            self.middleware.clone(),
        )));
        let request_guard = self.exec.guard().cloned();

        let graceful_shutdown_fut = graceful.shutdown();

        let result = self
            .http_server
            .serve(
                GracefulIo::new(token.clone().cancelled_owned(), ingress_stream),
                service_fn(move |req: Request| {
                    let relay_state = relay_state.clone();
                    let close_ingress = token.clone();
                    let guard = request_guard.clone();
                    async move {
                        Ok(handle_relay_request(&relay_state, req, guard, close_ingress).await)
                    }
                }),
            )
            .await
            .context("serve HTTP MITM relay");

        graceful_shutdown_fut.await;
        result
    }
}

#[derive(Debug, Clone, Copy)]
enum RelayMode {
    Http1,
    Http2,
}

impl RelayMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Http1 => "http1",
            Self::Http2 => "http2",
        }
    }
}

impl TryFrom<Version> for RelayMode {
    type Error = BoxError;

    fn try_from(version: Version) -> Result<Self, Self::Error> {
        match version {
            Version::HTTP_2 => Ok(Self::Http2),
            Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => Ok(Self::Http1),
            version => Err(BoxError::from("unsupported request version for MITM relay")
                .context_debug_field("version", version)),
        }
    }
}

enum RelayState<Egress, Middleware>
where
    Egress: Io + Unpin + ExtensionsMut,
    Middleware: Layer<HttpClientService<Body>>,
{
    Uninitialized {
        egress_stream: Option<Egress>,
        middleware: Middleware,
    },
    Http1 {
        client: Middleware::Service,
    },
    Http2 {
        client: Middleware::Service,
    },
    Closed,
}

impl<Egress, Middleware> RelayState<Egress, Middleware>
where
    Egress: Io + Unpin + ExtensionsMut,
    Middleware: Layer<HttpClientService<Body>>,
{
    fn new(egress_stream: Egress, middleware: Middleware) -> Self {
        Self::Uninitialized {
            egress_stream: Some(egress_stream),
            middleware,
        }
    }
}

async fn handle_relay_request<Egress, Middleware>(
    relay_state: &Arc<Mutex<RelayState<Egress, Middleware>>>,
    req: Request,
    guard: Option<ShutdownGuard>,
    close_ingress: CancellationToken,
) -> Response
where
    Egress: Io + Unpin + ExtensionsMut,
    Middleware: Layer<
            HttpClientService<Body>,
            Service: Service<Request, Output = Response, Error: Into<BoxError>> + Clone,
        > + Clone,
{
    let method = req.method().clone();
    let uri = req.uri().clone();
    let version = req.version();

    let relay_mode = match RelayMode::try_from(version) {
        Ok(mode) => mode,
        Err(err) => {
            tracing::debug!("failed to derive relay mode from request version: {err}");
            return DefaultErrorResponse::cancel_ingress_and_return_best_effort_response(
                version,
                &close_ingress,
            );
        }
    };
    tracing::trace!(
        http.request.method = %method,
        url.full = %uri,
        ?version,
        mode = relay_mode.as_str(),
        "dispatching request on MITM relay egress"
    );

    match relay_mode {
        RelayMode::Http1 => {
            let mut state = relay_state.lock().await;
            let resp = serve_http1_request(
                &mut *state,
                req,
                guard,
                &method,
                &uri,
                version,
                close_ingress.clone(),
            )
            .await;
            if let Ok(ref resp) = resp {
                tracing::trace!(
                    http.request.method = %method,
                    url.full = %uri,
                    ?version,
                    http.response.status_code = resp.status().as_u16(),
                    "received response from MITM relay egress"
                );
            }
            resp.unwrap_or_else(|_| {
                DefaultErrorResponse::best_effort_response_after_ingress_cancellation(version)
            })
        }
        RelayMode::Http2 => {
            let client_and_req = {
                let mut state = relay_state.lock().await;
                relay_connect_http2_if_needed(&mut *state, req, guard, close_ingress.clone()).await
            };

            match client_and_req {
                Ok((client, req)) => {
                    let mut state = relay_state.lock().await;
                    let resp = serve_relay_request(
                        &client,
                        req,
                        &method,
                        &uri,
                        version,
                        close_ingress.clone(),
                        &mut *state,
                    )
                    .await;
                    if let Ok(ref resp) = resp {
                        tracing::trace!(
                            http.request.method = %method,
                            url.full = %uri,
                            ?version,
                            http.response.status_code = resp.status().as_u16(),
                            "received response from MITM relay egress"
                        );
                    }
                    resp.unwrap_or_else(|_| {
                        DefaultErrorResponse::best_effort_response_after_ingress_cancellation(
                            version,
                        )
                    })
                }
                Err(resp) => resp,
            }
        }
    }
}

async fn serve_http1_request<Egress, Middleware>(
    state: &mut RelayState<Egress, Middleware>,
    req: Request,
    guard: Option<ShutdownGuard>,
    method: &Method,
    uri: &Uri,
    version: Version,
    close_ingress: CancellationToken,
) -> Result<Response, BoxError>
where
    Egress: Io + Unpin + ExtensionsMut,
    Middleware: Layer<
            HttpClientService<Body>,
            Service: Service<Request, Output = Response, Error: Into<BoxError>> + Clone,
        > + Clone,
{
    let req = match relay_connect_http1_if_needed(state, req, guard, close_ingress.clone()).await {
        Ok(req) => req,
        Err(resp) => return Ok(resp),
    };

    match state {
        RelayState::Http1 { client } => {
            let result = client.serve(req).await.into_box_error();
            match result {
                Ok(resp) => Ok(resp),
                Err(err) => {
                    tracing::debug!(
                        http.request.method = %method,
                        url.full = %uri,
                        ?version,
                        "upstream MITM relay request failed: {err}"
                    );
                    *state = RelayState::Closed;
                    close_ingress.cancel();
                    Err(err)
                }
            }
        }
        RelayState::Closed => Ok(DefaultErrorResponse::response_for_version(version)),
        RelayState::Http2 { .. } | RelayState::Uninitialized { .. } => {
            close_ingress.cancel();
            *state = RelayState::Closed;
            Ok(DefaultErrorResponse::best_effort_response_after_ingress_cancellation(version))
        }
    }
}

async fn relay_connect_http1_if_needed<Egress, Middleware>(
    state: &mut RelayState<Egress, Middleware>,
    req: Request,
    guard: Option<ShutdownGuard>,
    close_ingress: CancellationToken,
) -> Result<Request, Response>
where
    Egress: Io + Unpin + ExtensionsMut,
    Middleware: Layer<
            HttpClientService<Body>,
            Service: Service<Request, Output = Response, Error: Into<BoxError>> + Clone,
        > + Clone,
{
    match state {
        RelayState::Http1 { .. } => Ok(req),
        RelayState::Http2 { .. } => {
            tracing::debug!("received HTTP/1 relay request on HTTP/2 relay state; closing relay");
            *state = RelayState::Closed;
            Err(
                DefaultErrorResponse::cancel_ingress_and_return_best_effort_response(
                    req.version(),
                    &close_ingress,
                ),
            )
        }
        RelayState::Closed => Err(
            DefaultErrorResponse::cancel_ingress_and_return_best_effort_response(
                req.version(),
                &close_ingress,
            ),
        ),
        RelayState::Uninitialized { .. } => {
            let req = connect_relay(state, req, guard, close_ingress.clone()).await?;
            if let RelayState::Http1 { .. } = state {
                Ok(req)
            } else {
                tracing::debug!("failed to initialize HTTP/1 relay state from first request");
                *state = RelayState::Closed;
                Err(
                    DefaultErrorResponse::cancel_ingress_and_return_best_effort_response(
                        req.version(),
                        &close_ingress,
                    ),
                )
            }
        }
    }
}

async fn relay_connect_http2_if_needed<Egress, Middleware>(
    state: &mut RelayState<Egress, Middleware>,
    req: Request,
    guard: Option<ShutdownGuard>,
    close_ingress: CancellationToken,
) -> Result<(Middleware::Service, Request), Response>
where
    Egress: Io + Unpin + ExtensionsMut,
    Middleware: Layer<
            HttpClientService<Body>,
            Service: Service<Request, Output = Response, Error: Into<BoxError>> + Clone,
        > + Clone,
{
    match state {
        RelayState::Http2 { client } => Ok((client.clone(), req)),
        RelayState::Http1 { .. } => {
            tracing::debug!("received HTTP/2 relay request on HTTP/1 relay state; closing relay");
            *state = RelayState::Closed;
            Err(
                DefaultErrorResponse::cancel_ingress_and_return_best_effort_response(
                    req.version(),
                    &close_ingress,
                ),
            )
        }
        RelayState::Closed => Err(
            DefaultErrorResponse::cancel_ingress_and_return_best_effort_response(
                req.version(),
                &close_ingress,
            ),
        ),
        RelayState::Uninitialized { .. } => {
            let version = req.version();
            let req = connect_relay(state, req, guard, close_ingress.clone()).await?;
            if let RelayState::Http2 { client } = state {
                Ok((client.clone(), req))
            } else {
                tracing::debug!("failed to initialize HTTP/2 relay state from first request");
                *state = RelayState::Closed;
                Err(
                    DefaultErrorResponse::cancel_ingress_and_return_best_effort_response(
                        version,
                        &close_ingress,
                    ),
                )
            }
        }
    }
}

async fn connect_relay<Egress, Middleware>(
    state: &mut RelayState<Egress, Middleware>,
    req: Request,
    guard: Option<ShutdownGuard>,
    close_ingress: CancellationToken,
) -> Result<Request, Response>
where
    Egress: Io + Unpin + ExtensionsMut,
    Middleware: Layer<
            HttpClientService<Body>,
            Service: Service<Request, Output = Response, Error: Into<BoxError>> + Clone,
        > + Clone,
{
    let RelayState::Uninitialized {
        egress_stream,
        middleware,
    } = state
    else {
        return Ok(req);
    };

    let req_version = req.version();
    let Some(egress_stream) = egress_stream.take() else {
        *state = RelayState::Closed;
        return Err(
            DefaultErrorResponse::cancel_ingress_and_return_best_effort_response(
                req_version,
                &close_ingress,
            ),
        );
    };

    let exec = guard.map_or_else(Executor::default, Executor::graceful);
    match http_connect(egress_stream, req, exec).await {
        Ok(EstablishedClientConnection { input, conn }) => {
            let version = input.version();
            let client = middleware.clone().into_layer(conn);
            match RelayMode::try_from(version) {
                Ok(RelayMode::Http1) => {
                    *state = RelayState::Http1 { client };
                    Ok(input)
                }
                Ok(RelayMode::Http2) => {
                    *state = RelayState::Http2 { client };
                    Ok(input)
                }
                Err(err) => {
                    tracing::debug!("failed to derive relay mode after egress connect: {err}");
                    *state = RelayState::Closed;
                    Err(
                        DefaultErrorResponse::cancel_ingress_and_return_best_effort_response(
                            version,
                            &close_ingress,
                        ),
                    )
                }
            }
        }
        Err(err) => {
            tracing::debug!("failed to establish egress HTTP connection: {err}");
            *state = RelayState::Closed;
            Err(
                DefaultErrorResponse::cancel_ingress_and_return_best_effort_response(
                    req_version,
                    &close_ingress,
                ),
            )
        }
    }
}

async fn serve_relay_request<Egress, Middleware, Client>(
    client: &Client,
    req: Request,
    method: &Method,
    uri: &Uri,
    version: Version,
    close_ingress: CancellationToken,
    state: &mut RelayState<Egress, Middleware>,
) -> Result<Response, BoxError>
where
    Egress: Io + Unpin + ExtensionsMut,
    Middleware: Layer<HttpClientService<Body>>,
    Client: Service<Request, Output = Response, Error: Into<BoxError>>,
{
    match client.serve(req).await {
        Ok(resp) => Ok(resp),
        Err(err) => {
            let err = err.into_box_error();
            tracing::debug!(
                http.request.method = %method,
                url.full = %uri,
                ?version,
                "upstream MITM relay request failed: {err}"
            );
            *state = RelayState::Closed;
            close_ingress.cancel();
            Err(err)
        }
    }
}
