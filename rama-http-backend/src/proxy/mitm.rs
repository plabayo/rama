use std::convert::TryFrom;
use std::sync::Arc;
use std::time::Duration;

use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext as _, ErrorExt as _, extra::OpaqueError},
    extensions::ExtensionsRef,
    graceful::ShutdownGuard,
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
    conn::{H2ServerContextParams, TargetHttpVersion},
    service::web::response::IntoResponse,
};
use rama_http_core::server::conn::{
    auto::Builder as AutoConnBuilder, http1::Builder as Http1ConnBuilder,
    http2::Builder as H2ConnBuilder,
};
use rama_http_types::proto::h2::frame::Settings;
use rama_net::client::EstablishedClientConnection;

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::{
    client::{HttpClientService, http_connect, http2_eager_handshake},
    server::HttpServer,
};

/// Default hard cap on how long we wait for the upstream's initial h2
/// SETTINGS frame during eager egress handshake before giving up and
/// treating the connection as non-compliant. Keeps adversarial /
/// dead-but-open peers from stalling the relay indefinitely. Override
/// per-instance with [`HttpMitmRelay::with_eager_peer_settings_timeout`].
pub const DEFAULT_EAGER_PEER_SETTINGS_TIMEOUT: Duration = Duration::from_secs(5);

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
    eager_peer_settings_timeout: Duration,
}

impl HttpMitmRelay {
    #[inline(always)]
    #[must_use]
    /// Create a new [`HttpMitmRelay`], ready to serve.
    pub fn new(exec: Executor) -> Self {
        // CONNECT-protocol advertisement (RFC 8441) is no longer set
        // unconditionally here. When the egress IO carries
        // `TargetHttpVersion(HTTP_2)`, the relay's eager phase-2 init
        // (see `serve`) handshakes egress first, captures the upstream's
        // initial SETTINGS, and mirrors them onto the ingress connection
        // via `H2ServerContextParams` — so we now only advertise CONNECT
        // when the upstream actually supports it.
        let http_server = HttpServer::auto(exec.clone());
        Self {
            http_server,
            middleware: (
                ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse),
                ArcLayer::new(),
            ),
            exec,
            eager_peer_settings_timeout: DEFAULT_EAGER_PEER_SETTINGS_TIMEOUT,
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
            eager_peer_settings_timeout: self.eager_peer_settings_timeout,
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

    rama_utils::macros::generate_set_and_with! {
        /// Hard cap on how long the eager phase-2 init waits for the
        /// upstream's initial h2 SETTINGS frame before giving up and
        /// proceeding without mirroring. Defaults to
        /// [`DEFAULT_EAGER_PEER_SETTINGS_TIMEOUT`]. Only applies when
        /// the egress IO carries `TargetHttpVersion(HTTP_2)`.
        pub fn eager_peer_settings_timeout(mut self, timeout: Duration) -> Self {
            self.eager_peer_settings_timeout = timeout;
            self
        }
    }
}

impl<Ingress, Egress, M> Service<BridgeIo<Ingress, Egress>> for HttpMitmRelay<M>
where
    Ingress: Io + Unpin + ExtensionsRef,
    Egress: Io + Unpin + ExtensionsRef,
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
        let request_guard = self.exec.guard().cloned();

        tracing::debug!("HTTP MITM Relay: start");

        // Eager phase-2 init: when the egress IO already exposes ALPN
        // (or any other authoritative signal) as
        // `TargetHttpVersion(HTTP_2)`, handshake the egress connection
        // *now* so we can observe the upstream's initial SETTINGS frame
        // and mirror the relevant bits onto the ingress server before
        // its own initial SETTINGS frame is written. Other versions
        // fall through to the original lazy path.
        //
        // BY DESIGN: only the *initial* SETTINGS frame is mirrored.
        // RFC 9113 §6.5 allows either peer to send SETTINGS updates
        // mid-connection, but the ingress h2 server's SETTINGS frame
        // is written once at handshake — we don't re-issue it. This is
        // sufficient for the relay's job: initial parity is what
        // governs the downstream client's protocol choices (e.g. RFC
        // 8441 Extended CONNECT), and once a stream is open the h2
        // stack on both sides handles dynamic adjustments
        // (WINDOW_UPDATE for flow control, per-stream limits) without
        // needing the SETTINGS frame to be reissued.
        let egress_is_h2 = egress_stream
            .extensions()
            .get_ref::<TargetHttpVersion>()
            .map(|t| t.0 == Version::HTTP_2)
            .unwrap_or(false);

        let relay_state = if egress_is_h2 {
            let exec = request_guard
                .clone()
                .map_or_else(Executor::default, Executor::graceful);
            match http2_eager_handshake::<_, Body>(egress_stream, exec).await {
                Ok((conn, peer_handle)) => {
                    let timeout_dur = self.eager_peer_settings_timeout;
                    let peer_settings =
                        tokio::time::timeout(timeout_dur, peer_handle.await_settings())
                            .await
                            .unwrap_or_else(|_| {
                                tracing::debug!(
                                    "eager egress h2 peer SETTINGS not received within {:?}",
                                    timeout_dur,
                                );
                                None
                            });
                    let mirrored = if let Some(settings) = peer_settings.as_ref() {
                        tracing::trace!(
                            "mirroring upstream h2 SETTINGS onto ingress: {settings:?}",
                        );
                        mirror_peer_settings(settings)
                    } else {
                        // Fail-safe: even when capture fails, we MUST
                        // explicitly disable CONNECT on the ingress.
                        // Otherwise, a user who set
                        // `relay.h2_mut().set_enable_connect_protocol()`
                        // on the builder defaults would have us
                        // unconditionally re-advertise CONNECT to a
                        // downstream client whose upstream may not
                        // support it — reintroducing issue #932.
                        tracing::debug!(
                            "no upstream h2 SETTINGS captured; forcing CONNECT off on ingress",
                        );
                        H2ServerContextParams {
                            enable_connect_protocol: Some(false),
                            ..H2ServerContextParams::default()
                        }
                    };
                    ingress_stream.extensions().insert(mirrored);
                    let client = self.middleware.clone().layer(conn);
                    Arc::new(Mutex::new(RelayState::Http2 { client }))
                }
                Err(err) => {
                    tracing::debug!("eager egress h2 handshake failed: {err}");
                    return Err(err.into());
                }
            }
        } else {
            Arc::new(Mutex::new(RelayState::new(
                egress_stream,
                self.middleware.clone(),
            )))
        };

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

        tracing::debug!("HTTP MITM Relay: Shutdown: done");
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
            version => Err(OpaqueError::from_static_str(
                "unsupported request version for MITM relay",
            )
            .context_debug_field("version", version)),
        }
    }
}

enum RelayState<Egress, Middleware>
where
    Egress: Io + Unpin + ExtensionsRef,
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
    Egress: Io + Unpin + ExtensionsRef,
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
    Egress: Io + Unpin + ExtensionsRef,
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
            // Acquire-release: only briefly grab the state lock to
            // ensure the egress h2 client is connected, then drop
            // it. The actual upstream serve must NOT hold the lock
            // (see `serve_relay_request` rationale).
            let client_and_req = {
                let mut state = relay_state.lock().await;
                relay_connect_http2_if_needed(&mut *state, req, guard, close_ingress.clone()).await
            };

            match client_and_req {
                Ok((client, req)) => {
                    let resp = serve_relay_request(
                        &client,
                        req,
                        &method,
                        &uri,
                        version,
                        close_ingress.clone(),
                        relay_state,
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
    Egress: Io + Unpin + ExtensionsRef,
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
    Egress: Io + Unpin + ExtensionsRef,
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
    Egress: Io + Unpin + ExtensionsRef,
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
    Egress: Io + Unpin + ExtensionsRef,
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
            let client = middleware.layer(conn);
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
    relay_state: &Arc<Mutex<RelayState<Egress, Middleware>>>,
) -> Result<Response, BoxError>
where
    Egress: Io + Unpin + ExtensionsRef,
    Middleware: Layer<HttpClientService<Body>>,
    Client: Service<Request, Output = Response, Error: Into<BoxError>>,
{
    // Do NOT hold `relay_state.lock()` across the upstream serve.
    // For h2, multiple streams share one `RelayState`; locking across
    // `client.serve(req).await` serialises every stream on the
    // mutex and kills multiplexing.
    //
    // The lock is only needed to mark state Closed on error.
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
            // A peer `RST_STREAM` is scoped to this one h2 stream; the
            // shared egress connection and its sibling streams are
            // unaffected. Fail only this stream so we don't escalate to
            // tearing down the whole ingress connection (GOAWAY for all
            // siblings) — which would happen via the `Closed` + cancel
            // below. `GOAWAY` / transport errors are connection-scoped
            // and still take that path.
            if egress_error_is_stream_scoped(&err) {
                return Ok(DefaultErrorResponse::response_for_version(version));
            }
            *relay_state.lock().await = RelayState::Closed;
            close_ingress.cancel();
            Err(err)
        }
    }
}

/// Project an upstream's initial h2 SETTINGS frame onto an
/// [`H2ServerContextParams`] suitable for stamping on the relay's
/// ingress IO.
///
/// Two fields are carried forward, and only two:
///
/// 1. **`enable_connect_protocol`** (RFC 8441) — a capability
///    advertisement that is transitively meaningful across the relay.
///    If upstream advertises Extended CONNECT, the relay can advertise
///    it downstream because it just forwards. If upstream omits it, the
///    relay MUST omit it (this is #932's core fix). Authoritative-wins:
///    we always emit `Some(true|false)`, overriding any builder default
///    a user may have set on the relay's h2 builder — without that, a
///    user who opted into CONNECT defaults would re-trigger #932 when
///    talking to a non-CONNECT upstream.
///
/// 2. **`max_concurrent_streams`** — kept as an *explicit backpressure
///    policy*, not as a transparent mirror. h2 SETTINGS frames are
///    per-direction: upstream's value bounds upstream's accept capacity
///    *from the relay-as-client*, which is not the same as the relay's
///    accept capacity *from a downstream-as-client*. We use upstream's
///    value anyway because it caps how much concurrency the relay can
///    actually forward through its single egress h2 connection.
///    Floored at 1 to guard against pathological upstream `Some(0)`.
///
/// Other initial-SETTINGS fields (`header_table_size`, `max_frame_size`,
/// `max_header_list_size`, `initial_stream_window_size`) describe
/// independent per-direction buffer/decoder budgets that have no
/// cross-direction meaning. Mirroring them would silently couple
/// budgets that should be independent, which is why we don't. These
/// fields remain part of [`H2ServerContextParams`] for callers who
/// want to set them directly per-connection.
fn mirror_peer_settings(settings: &Settings) -> H2ServerContextParams {
    let cfg = &settings.config;
    H2ServerContextParams {
        enable_connect_protocol: Some(cfg.enable_connect_protocol.map(|v| v != 0).unwrap_or(false)),
        // `max(1)`: protect the ingress server from upstream advertising
        // `Some(0)` (legal on the wire but produces a non-functional
        // connection). Any saner upstream value passes through unchanged.
        max_concurrent_streams: cfg.max_concurrent_streams.map(|n| n.max(1)),
        // Intentionally not mirrored — see fn docstring.
        header_table_size: None,
        max_frame_size: None,
        max_header_list_size: None,
        initial_stream_window_size: None,
        initial_connection_window_size: None,
        adaptive_window: None,
    }
}

/// Whether an egress request error is scoped to a single h2 stream (a
/// `RST_STREAM`) rather than the whole connection. Walks the cause
/// chain because the reset may be wrapped in a `rama_http_core::Error`.
fn egress_error_is_stream_scoped(err: &BoxError) -> bool {
    if let Some(h2) = err.downcast_ref::<rama_http_core::h2::Error>() {
        return h2.is_reset();
    }
    let mut current = err.source();
    while let Some(cause) = current {
        if let Some(h2) = cause.downcast_ref::<rama_http_core::h2::Error>() {
            return h2.is_reset();
        }
        current = cause.source();
    }
    false
}
