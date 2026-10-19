use std::{convert::TryFrom, sync::Arc, time::Duration};

use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
    extensions::ExtensionsRef,
    graceful::ShutdownGuard,
    io::{BridgeIo, GracefulIo, Io, rewind::Rewind},
    layer::{
        ArcLayer, ConsumeErrLayer,
        consume_err::{StaticOutput, Trace},
    },
    matcher::Matcher,
    rt::Executor,
    service::service_fn,
    telemetry::tracing,
};
use rama_http::{
    Body, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version,
    conn::{H2ClientContextParams, H2ServerContextParams, H2SettingsLimits, TargetHttpVersion},
    header::{self, trailer::ForbiddenTrailers},
    io::upgrade::OnUpgrade,
    layer::{
        remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
        validate_request::{BoundAuthority, ValidateRequest, ValidateRequestHeaderLayer},
    },
    service::web::response::IntoResponse,
};
use rama_http_core::h2::{
    Error as H2Error, MAX_WINDOW_SIZE, UserError,
    initial_credit::{PeerInitialCredit, ReceiveInitialCredit},
    server::inspect_client_initial_settings,
};
use rama_http_core::server::conn::{
    auto::Builder as AutoConnBuilder, http1::Builder as Http1ConnBuilder,
    http2::Builder as H2ConnBuilder,
};
use rama_http_types::proto::{
    h1::ext::{CloseDelimitedResponse, ConnectionClose, OriginalResponseBodyFraming},
    h2::{
        ext::ResetStream,
        frame::{DEFAULT_INITIAL_WINDOW_SIZE, Reason},
    },
};
use rama_net::{
    client::EstablishedClientConnection,
    conn::{ConnectionHealth, ConnectionHealthWatcher},
    uri::Uri,
};
use tokio::{
    sync::{Mutex, watch},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use crate::{
    client::{HttpClientService, SendAttempts, http_connect, http2_eager_handshake},
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

    /// `retry_safe` only for requests the egress provably never
    /// processed: h2 then resets the stream with `REFUSED_STREAM`, which
    /// clients may replay (even a POST), so never for anything else.
    #[inline(always)]
    fn response_for_version(version: Version, retry_safe: bool) -> Response {
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
        if retry_safe {
            response
                .extensions()
                .insert(ResetStream(Reason::REFUSED_STREAM));
        }
        response
    }

    /// Once ingress is cancelled, `GracefulIo` may cut the transport before
    /// this response is written; it only exists because the service
    /// contract requires one.
    #[inline(always)]
    fn cancel_ingress_and_return_best_effort_response(
        version: Version,
        close_ingress: &CancellationToken,
    ) -> Response {
        close_ingress.cancel();
        Self::response_for_version(version, false)
    }
}

impl From<DefaultErrorResponse> for Response {
    #[inline(always)]
    fn from(_: DefaultErrorResponse) -> Self {
        DefaultErrorResponse::response()
    }
}

/// Default middleware used by [`HttpMitmRelay`].
///
/// It handles relay errors and makes the resulting service shareable.
pub type DefaultMiddleware = (
    ConsumeErrLayer<Trace, StaticOutput<DefaultErrorResponse>>,
    ArcLayer,
);

/// Explicit receive-credit ceilings for the two physical HTTP/2 relay legs.
/// No default is chosen: callers must budget both directions independently.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct H2InitialCreditLimits {
    ingress: u32,
    egress: u32,
}

impl H2InitialCreditLimits {
    /// Validate local receive maxima for ingress and egress. Both must cover
    /// the mandatory initial HTTP/2 window and fit its protocol maximum.
    pub fn try_new(ingress: u32, egress: u32) -> Result<Self, H2Error> {
        let allowed = DEFAULT_INITIAL_WINDOW_SIZE..=MAX_WINDOW_SIZE;
        if !allowed.contains(&ingress) || !allowed.contains(&egress) {
            return Err(UserError::InitialCreditConfiguration.into());
        }
        Ok(Self { ingress, egress })
    }
}

#[derive(Debug, Clone)]
/// A utility that can be used by MITM services such as transparent proxies,
/// in order to relay HTTP requests and responses between a client and server,
/// as part of a deep protocol inspection protocol (DPI) flow.
///
/// Useful if you have a fairly standard MITM http flow and already
/// have pre-established ingress and egress connections (e.g. because
/// you already MITM'd the <L7 layers, such as SOCKS5 MITM'ng, TLS, ...).
///
/// HTTP/1 responses originally delimited by EOF (without Content-Length or
/// Transfer-Encoding) retain that framing downstream, including HTTP/1.1.
/// They stream without chunking and close the downstream connection at body EOF.
/// Preserving EOF framing sacrifices downstream connection reuse and explicit truncation detection.
/// Middleware can select different framing by adding Content-Length or
/// Transfer-Encoding; a Trailer header also prevents automatic EOF framing.
/// HTTP/2 framing is unaffected.
///
/// When an HTTP/2 egress connection ends (EOF, `GOAWAY`, error), the
/// ingress connection is shut down gracefully with a `GOAWAY`, so idle
/// clients reconnect instead of sending into a dead relay. Ingress
/// requests the egress provably never processed (over all attempts
/// middleware made for them) are reset with `REFUSED_STREAM`, which
/// clients may safely retry: they raced that close (never sent, or not
/// covered by the egress `GOAWAY`), or the egress refused their stream.
/// This replaces any response middleware made for such a request, e.g.
/// the default `502`.
///
/// The relay does not consume proxy-authentication fields: a transparent
/// intermediary may be forwarding them to the proxy that owns the exchange.
/// A proxy that owns that exchange should explicitly apply the `proxy_auth`
/// request and response removal layers in its middleware.
pub struct HttpMitmRelay<M = DefaultMiddleware, P = bool> {
    http_server: HttpServer<AutoConnBuilder>,
    middleware: M,
    authority: Option<BoundAuthority<P>>,
    exec: Executor,
    eager_peer_settings_timeout: Duration,
    forbidden_trailers: ForbiddenTrailers,
    mirror_initial_h2_credit: Option<H2InitialCreditLimits>,
}

impl HttpMitmRelay {
    #[inline(always)]
    #[must_use]
    /// Create a new [`HttpMitmRelay`], ready to serve.
    pub fn new(exec: Executor) -> Self {
        // Baseline CONNECT-on for the *lazy* path (plain h2, no ALPN).
        // The eager path in `serve()` overrides this per-conn via
        // `H2ServerContextParams`, which is what closes #932 for TLS h2.
        // See `rama_http_core::server::conn::http2::apply_h2_server_context_params`.
        let mut http_server = HttpServer::auto(exec.clone());
        // Request EOF must not discard a response still being produced by the origin.
        http_server.http1_mut().set_half_close(true);
        http_server.h2_mut().set_enable_connect_protocol();
        http_server.h2_mut().set_observe_early_frames(true);
        Self {
            http_server,
            middleware: (
                ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse),
                ArcLayer::new(),
            ),
            exec,
            authority: None,
            eager_peer_settings_timeout: DEFAULT_EAGER_PEER_SETTINGS_TIMEOUT,
            forbidden_trailers: ForbiddenTrailers::AllowAll,
            mirror_initial_h2_credit: None,
        }
    }
}

impl<M, P> HttpMitmRelay<M, P> {
    /// Bind this intercepted connection to its trusted logical origin and policy.
    ///
    /// Every request is checked before dispatch and again after HTTP middleware.
    /// Authority mismatches and revoked policy return 421 without allocating an
    /// upstream request stream. The origin comes from the interception decision,
    /// not the first request, SNI alone, or a physical connector override.
    pub fn with_bound_authority<Q>(self, authority: BoundAuthority<Q>) -> HttpMitmRelay<M, Q> {
        HttpMitmRelay {
            http_server: self.http_server,
            middleware: self.middleware,
            authority: Some(authority),
            exec: self.exec,
            eager_peer_settings_timeout: self.eager_peer_settings_timeout,
            forbidden_trailers: self.forbidden_trailers,
            mirror_initial_h2_credit: self.mirror_initial_h2_credit,
        }
    }

    /// Set HTTP middleware to use between server and client.
    ///
    /// Context-aware hop-by-hop sanitation remains at the relay boundary.
    /// Fields received from each connection are consumed before this
    /// middleware handles the message. Transport intent added by the
    /// middleware is therefore originated for the next connection.
    pub fn with_http_middleware<N>(self, middleware: N) -> HttpMitmRelay<N, P> {
        HttpMitmRelay {
            http_server: self.http_server,
            middleware,
            authority: self.authority,
            exec: self.exec,
            eager_peer_settings_timeout: self.eager_peer_settings_timeout,
            forbidden_trailers: self.forbidden_trailers,
            mirror_initial_h2_credit: self.mirror_initial_h2_credit,
        }
    }

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

    rama_utils::macros::generate_set_and_with! {
        /// Mirror cumulative initial HTTP/2 connection credit between the two
        /// physical connections within explicit directional receive budgets.
        /// `None` is the default and creates no observation cells.
        /// Applies only when the eager egress and inspected ingress both use H2.
        ///
        /// Both IOs must explicitly select connection window 65535 and adaptive
        /// flow control off through their existing H2 context params. Existing
        /// credit handles or conflicting/missing params are rejected before the
        /// mirrored handshake. Builder choices are not overwritten.
        ///
        /// Source credit above a destination maximum fails locally instead of
        /// increasing its receive budget or silently clamping the source fact.
        /// This preserves validated pre-HEADERS credit, not WINDOW_UPDATE timing
        /// or steady-state replenishment. A source that commits nonempty DATA
        /// before its first peer HEADERS can report ambiguous credit and fail the
        /// paired connection. The eager connection is dedicated, not pooled.
        pub fn mirror_initial_h2_credit(mut self, limits: Option<H2InitialCreditLimits>) -> Self {
            self.mirror_initial_h2_credit = limits;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Which trailer fields the relay forwards although their definitions do not allow
        /// them in trailers. Defaults to [`ForbiddenTrailers::AllowAll`]: a relay forwards
        /// trailers as received, except fields that frame or route the message.
        pub fn forbidden_trailers(mut self, forbidden_trailers: ForbiddenTrailers) -> Self {
            self.forbidden_trailers = forbidden_trailers;
            self
        }
    }
}

impl<Ingress, Egress, M, P> Service<BridgeIo<Ingress, Egress>> for HttpMitmRelay<M, P>
where
    Ingress: Io + Unpin + ExtensionsRef,
    Egress: Io + Unpin + ExtensionsRef,
    (
        RemoveRequestHeaderLayer,
        M,
        RemoveResponseHeaderLayer,
        ValidateRequestHeaderLayer<Option<BoundAuthority<P>>>,
    ): Layer<
            HttpClientService<Body>,
            Service: Service<Request, Output = Response, Error: Into<BoxError>> + Clone,
        > + Clone,
    M: Send + Sync + 'static + Clone,
    P: Matcher<Request> + Clone,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(
        &self,
        BridgeIo(ingress_stream, egress_stream): BridgeIo<Ingress, Egress>,
    ) -> Result<Self::Output, Self::Error> {
        let token = CancellationToken::new();
        let request_guard = self.exec.guard().cloned();
        let (egress_health, egress_health_rx) = watch::channel(None);
        let egress_health = Arc::new(egress_health);

        tracing::debug!("HTTP MITM Relay: start");

        // Initial SETTINGS are selected before either native leg writes its frame.
        // Mandatory downstream bytes cannot depend on a server SETTINGS response.
        let deadline = Instant::now() + self.eager_peer_settings_timeout;
        let egress_is_h2 = egress_stream
            .extensions()
            .get_ref::<TargetHttpVersion>()
            .is_some_and(|target| target.0 == Version::HTTP_2);
        let (ingress_stream, downstream_settings) = if egress_is_h2 {
            let limits = egress_stream
                .extensions()
                .get_ref::<H2SettingsLimits>()
                .copied()
                .unwrap_or_default();
            tokio::time::timeout_at(
                deadline,
                inspect_client_initial_settings(ingress_stream, limits),
            )
            .await
            .map_err(|_elapsed| {
                BoxError::from_static_str("downstream initial H2 SETTINGS deadline elapsed")
            })??
        } else {
            (
                Rewind::new_buffered(ingress_stream, Default::default()),
                None,
            )
        };
        // The inspector determines the actual ingress protocol before any
        // native lease is installed. H1 and the ordinary relay path keep their
        // existing configuration and allocate no initial-credit cells.
        let initial_credit_guard = if let Some(limits) = self
            .mirror_initial_h2_credit
            .filter(|_| downstream_settings.is_some())
        {
            let downstream = ingress_stream.extensions();
            let upstream = egress_stream.extensions();
            let ingress = downstream.get_ref::<H2ServerContextParams>();
            let egress = upstream.get_ref::<H2ClientContextParams>();
            if !ingress.is_some_and(|params| {
                params.initial_connection_window_size == Some(DEFAULT_INITIAL_WINDOW_SIZE)
                    && params.adaptive_window == Some(false)
            }) || !egress.is_some_and(|params| {
                params.init_connection_window_size == Some(DEFAULT_INITIAL_WINDOW_SIZE)
                    && params.adaptive_window == Some(false)
            }) {
                return Err(BoxError::from_static_str(
                    "initial H2 credit mirroring requires explicit 65535/non-adaptive IO params",
                ));
            }
            if downstream.contains::<PeerInitialCredit>()
                || downstream.contains::<ReceiveInitialCredit>()
                || upstream.contains::<PeerInitialCredit>()
                || upstream.contains::<ReceiveInitialCredit>()
            {
                return Err(BoxError::from_static_str(
                    "initial H2 credit mirroring conflicts with existing native handles",
                ));
            }
            let downstream_credit = PeerInitialCredit::new();
            let upstream_credit = PeerInitialCredit::new();
            let ingress_target = upstream_credit.try_receive_target(limits.ingress)?;
            let egress_target = downstream_credit.try_receive_target(limits.egress)?;
            downstream.insert(downstream_credit);
            downstream.insert(ingress_target);
            upstream.insert(upstream_credit);
            upstream.insert(egress_target);
            // The eager client driver is spawned before ingress handshakes.
            // Cancel only this opt-in pair on every early return or future drop.
            Some(token.clone().drop_guard())
        } else {
            None
        };
        if let Some(settings) = downstream_settings {
            // The relay has no server-push forwarding implementation. Omission
            // means enabled by default, which cannot be silently advertised either.
            if settings.config.enable_push.unwrap_or(1) != 0 {
                return Err(BoxError::from_static_str(
                    "H2 relay cannot preserve enabled server push",
                ));
            }
            let mut params = egress_stream
                .extensions()
                .get_ref::<H2ClientContextParams>()
                .cloned()
                .unwrap_or_default();
            if let Some(explicit) = &params.initial_settings
                && explicit.to_literal()? != settings
            {
                return Err(BoxError::from_static_str(
                    "explicit egress H2 SETTINGS conflict with ingress",
                ));
            }
            params.initial_settings = Some(Arc::new(settings));
            egress_stream.extensions().insert(params);
        }

        let relay_state = if egress_is_h2 {
            let exec = request_guard
                .clone()
                .map_or_else(Executor::default, Executor::graceful);
            let (conn, peer_handle) = tokio::time::timeout_at(deadline, async {
                if initial_credit_guard.is_some() {
                    http2_eager_handshake::<_, Body>(
                        GracefulIo::new(Box::pin(token.clone().cancelled_owned()), egress_stream),
                        exec,
                    )
                    .await
                } else {
                    http2_eager_handshake::<_, Body>(egress_stream, exec).await
                }
            })
            .await
            .map_err(|_elapsed| {
                BoxError::from_static_str("upstream H2 handshake deadline elapsed")
            })??;
            let peer = tokio::time::timeout_at(deadline, peer_handle.await_settings())
                .await
                .map_err(|_elapsed| {
                    BoxError::from_static_str("upstream initial H2 SETTINGS deadline elapsed")
                })?
                .ok_or_else(|| {
                    BoxError::from_static_str("upstream closed before initial H2 SETTINGS")
                })?;
            let settings = peer.0.to_literal()?;
            if settings.config.enable_push.is_some() {
                return Err(BoxError::from_static_str(
                    "H2 server must not advertise SETTINGS_ENABLE_PUSH",
                ));
            }
            let limits = ingress_stream
                .extensions()
                .get_ref::<H2SettingsLimits>()
                .copied()
                .unwrap_or_default();
            limits.validate(&settings)?;
            let mut params = ingress_stream
                .extensions()
                .get_ref::<H2ServerContextParams>()
                .cloned()
                .unwrap_or_default();
            if let Some(explicit) = &params.initial_settings
                && explicit.to_literal()? != settings
            {
                return Err(BoxError::from_static_str(
                    "explicit ingress H2 SETTINGS conflict with upstream",
                ));
            }
            params.initial_settings = Some(Arc::new(settings));
            ingress_stream.extensions().insert(params);
            let health = egress_connection_health(&conn);
            egress_health.send_replace(Some(health.clone()));
            let client = (
                RemoveRequestHeaderLayer::hop_by_hop(),
                self.middleware.clone(),
                RemoveResponseHeaderLayer::hop_by_hop(),
                ValidateRequestHeaderLayer::custom(self.authority.clone()),
            )
                .layer(conn);
            Arc::new(Mutex::new(RelayState::Http2 { client, health }))
        } else {
            Arc::new(Mutex::new(RelayState::new(
                egress_stream,
                (
                    RemoveRequestHeaderLayer::hop_by_hop(),
                    self.middleware.clone(),
                    RemoveResponseHeaderLayer::hop_by_hop(),
                    ValidateRequestHeaderLayer::custom(self.authority.clone()),
                ),
            )))
        };

        let forbidden_trailers = self.forbidden_trailers.clone();
        let authority = self.authority.clone();
        let result = self
            .http_server
            .serve_with_graceful_shutdown(
                GracefulIo::new(token.clone().cancelled_owned(), ingress_stream),
                service_fn(move |req: Request| {
                    // Inherited by the forwarded request and the upstream's response.
                    req.extensions().insert(forbidden_trailers.clone());
                    let relay_state = relay_state.clone();
                    let authority = authority.clone();
                    let close_ingress = token.clone();
                    let guard = request_guard.clone();
                    let egress_health = egress_health.clone();
                    async move {
                        let req = match authority.validate(req).await {
                            Ok(req) => req,
                            Err(response) => return Ok(response),
                        };
                        let version = req.version();
                        let resp = handle_relay_request(
                            &relay_state,
                            req,
                            guard,
                            close_ingress,
                            &egress_health,
                        )
                        .await;
                        // Hop sanitation has already consumed received framing headers.
                        // Use decoder metadata, while respecting framing originated by middleware.
                        if matches!(version, Version::HTTP_10 | Version::HTTP_11)
                            && resp.extensions().get_ref::<OriginalResponseBodyFraming>()
                                == Some(&OriginalResponseBodyFraming::CloseDelimited)
                            && ![
                                header::CONTENT_LENGTH,
                                header::TRANSFER_ENCODING,
                                header::TRAILER,
                            ]
                            .iter()
                            .any(|name| resp.headers().contains_key(name))
                        {
                            resp.extensions().insert(CloseDelimitedResponse);
                        }
                        Ok(resp)
                    }
                }),
                egress_h2_gone(egress_health_rx),
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
            version => Err(
                BoxError::from_static_str("unsupported request version for MITM relay")
                    .context_debug_field("version", version),
            ),
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
        health: Arc<ConnectionHealthWatcher>,
    },
    Closed,
}

/// Egress h2 connection health, published once that connection exists:
/// before serving ingress (eager) or on the first request (lazy).
type EgressHealth = watch::Sender<Option<Arc<ConnectionHealthWatcher>>>;

fn egress_connection_health(conn: &HttpClientService<Body>) -> Arc<ConnectionHealthWatcher> {
    conn.extensions()
        .get_arc_or_insert(|| Arc::new(ConnectionHealthWatcher::default()))
}

/// Resolves once the egress h2 connection can no longer take requests
/// (EOF, GOAWAY, connection error), so ingress can be told with a
/// graceful GOAWAY instead of finding out on its next request.
async fn egress_h2_gone(mut egress_health: watch::Receiver<Option<Arc<ConnectionHealthWatcher>>>) {
    let health = match egress_health.wait_for(Option::is_some).await {
        Ok(health) => health.clone(),
        Err(_) => None,
    };
    let Some(health) = health else {
        // never an h2 egress: nothing to follow
        return std::future::pending().await;
    };
    let mut changed = health.watch();
    while health.health() != ConnectionHealth::Broken {
        if changed.changed().await.is_none() {
            break;
        }
    }
    tracing::debug!("egress h2 connection is gone: gracefully shut down ingress");
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
    egress_health: &EgressHealth,
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
            // on error the ingress is already cancelled
            resp.unwrap_or_else(|_| DefaultErrorResponse::response_for_version(version, false))
        }
        RelayMode::Http2 => {
            // Acquire-release: only briefly grab the state lock to
            // ensure the egress h2 client is connected, then drop
            // it. The actual upstream serve must NOT hold the lock
            // (see `serve_http2_request` rationale).
            let client_and_req = {
                let mut state = relay_state.lock().await;
                relay_connect_http2_if_needed(
                    &mut *state,
                    req,
                    guard,
                    close_ingress.clone(),
                    egress_health,
                )
                .await
            };

            match client_and_req {
                Ok((client, health, req)) => {
                    let resp =
                        serve_http2_request(&client, &health, req, &method, &uri, version).await;
                    tracing::trace!(
                        http.request.method = %method,
                        url.full = %uri,
                        ?version,
                        http.response.status_code = resp.status().as_u16(),
                        "received response from MITM relay egress"
                    );
                    resp
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
                Ok(mut resp) => {
                    if resp.extensions().contains::<ConnectionClose>()
                        && !resp.extensions().contains::<OnUpgrade>()
                    {
                        tracing::debug!(
                            http.request.method = %method,
                            url.full = %uri,
                            http.version = %resp.version(),
                            "upstream closed fixed HTTP/1 MITM relay connection"
                        );
                        *state = RelayState::Closed;
                        if resp.version() == Version::HTTP_11 {
                            resp.headers_mut()
                                .insert(header::CONNECTION, HeaderValue::from_static("close"));
                        }
                    }
                    Ok(resp)
                }
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
        RelayState::Closed => Ok(DefaultErrorResponse::response_for_version(version, false)),
        RelayState::Http2 { .. } | RelayState::Uninitialized { .. } => {
            *state = RelayState::Closed;
            Ok(
                DefaultErrorResponse::cancel_ingress_and_return_best_effort_response(
                    version,
                    &close_ingress,
                ),
            )
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
    egress_health: &EgressHealth,
) -> Result<(Middleware::Service, Arc<ConnectionHealthWatcher>, Request), Response>
where
    Egress: Io + Unpin + ExtensionsRef,
    Middleware: Layer<
            HttpClientService<Body>,
            Service: Service<Request, Output = Response, Error: Into<BoxError>> + Clone,
        > + Clone,
{
    match state {
        RelayState::Http2 { client, health } => Ok((client.clone(), health.clone(), req)),
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
            if let RelayState::Http2 { client, health } = state {
                egress_health.send_replace(Some(health.clone()));
                Ok((client.clone(), health.clone(), req))
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
            match RelayMode::try_from(version) {
                Ok(RelayMode::Http1) => {
                    let client = middleware.layer(conn);
                    *state = RelayState::Http1 { client };
                    Ok(input)
                }
                Ok(RelayMode::Http2) => {
                    let health = egress_connection_health(&conn);
                    let client = middleware.layer(conn);
                    *state = RelayState::Http2 { client, health };
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

async fn serve_http2_request<Client>(
    client: &Client,
    health: &ConnectionHealthWatcher,
    req: Request,
    method: &Method,
    uri: &Uri,
    version: Version,
) -> Response
where
    Client: Service<Request, Output = Response, Error: Into<BoxError>>,
{
    // No relay state lock across the upstream serve: h2 streams share
    // one `RelayState`, holding it would serialise all of them.
    //
    // Egress failures never cut the ingress connection: other ingress
    // streams may still be finishing on the same egress connection (e.g.
    // after an upstream graceful GOAWAY). Once egress is gone for good,
    // `egress_h2_gone` winds ingress down with a graceful GOAWAY.
    //
    // Retry safety is judged over every egress attempt middleware made
    // for this request (redirects, retries), never the final error alone:
    // an earlier hop may have reached the origin.
    let attempts = req
        .extensions()
        .insert_arc(Arc::new(SendAttempts::default()));
    let result = client.serve(req).await.map_err(Into::into);
    if attempts.none_processed() {
        // even when middleware already turned the failure into a response
        tracing::debug!(
            http.request.method = %method,
            url.full = %uri,
            ?version,
            egress.broken = health.health() == ConnectionHealth::Broken,
            "MITM relay request never processed by egress: refuse it (retry safe)"
        );
        return DefaultErrorResponse::response_for_version(version, true);
    }
    match result {
        Ok(resp) => resp,
        Err(err) => {
            tracing::debug!(
                http.request.method = %method,
                url.full = %uri,
                ?version,
                egress.broken = health.health() == ConnectionHealth::Broken,
                "upstream MITM relay request failed: {err}"
            );
            DefaultErrorResponse::response_for_version(version, false)
        }
    }
}
