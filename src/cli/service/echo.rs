//! Echo '[`Service`] that echos the [`http`] [`Request`] and [`tls`] client config.
//!
//! [`Service`]: crate::service::Service
//! [`http`]: crate::http
//! [`Request`]: crate::http::Request
//! [`tls`]: crate::tls

use crate::{
    cli::{ForwardKind, TlsServerCertKeyPair},
    error::{BoxError, ErrorContext, OpaqueError},
    http::{
        dep::http_body_util::BodyExt,
        headers::{CFConnectingIp, ClientIp, TrueClientIp, XClientIp, XRealIp},
        layer::{
            forwarded::GetForwardedHeadersLayer, required_header::AddRequiredResponseHeadersLayer,
            trace::TraceLayer,
        },
        response::Json,
        server::HttpServer,
        IntoResponse, Request, RequestContext, Response,
    },
    net::{
        forwarded::Forwarded,
        stream::{layer::http::BodyLimitLayer, SocketInfo},
    },
    proxy::pp::server::HaProxyLayer,
    rt::Executor,
    service::{
        layer::{
            limit::policy::ConcurrentPolicy, ConsumeErrLayer, Identity, LimitLayer, Stack,
            TimeoutLayer,
        },
        Context, Layer, Service, ServiceBuilder,
    },
    tls::{
        client::ClientHello,
        rustls::server::{TlsAcceptorLayer, TlsClientConfigHandler},
    },
    ua::{UserAgent, UserAgentClassifierLayer},
    utils::combinators::Either7,
};
use serde_json::json;
use std::{convert::Infallible, time::Duration};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
/// Builder that can be used to run your own echo [`Service`],
/// echo'ing back information about that request and its underlying transport / presentation layers.
pub struct EchoServiceBuilder<H> {
    concurrent_limit: usize,
    timeout: Duration,
    forward: Option<ForwardKind>,
    tls_server_config: Option<TlsServerCertKeyPair>,
    http_service_builder: ServiceBuilder<H>,
}

impl Default for EchoServiceBuilder<Identity> {
    fn default() -> Self {
        Self {
            concurrent_limit: 0,
            timeout: Duration::ZERO,
            forward: None,
            tls_server_config: None,
            http_service_builder: ServiceBuilder::new(),
        }
    }
}

impl EchoServiceBuilder<Identity> {
    /// Create a new [`EchoServiceBuilder`].
    pub fn new() -> Self {
        Self::default()
    }
}

impl<H> EchoServiceBuilder<H> {
    /// the number of concurrent connections to allow
    ///
    /// (0 = no limit)
    pub fn concurrent(mut self, limit: usize) -> Self {
        self.concurrent_limit = limit;
        self
    }

    /// the timeout in seconds for each connection
    ///
    /// (0 = no timeout)
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// enable support for one of the following "forward" headers or protocols
    ///
    /// Supported headers:
    ///
    /// Forwarded ("for="), X-Forwarded-For
    ///
    /// X-Client-IP Client-IP, X-Real-IP
    ///
    /// CF-Connecting-IP, True-Client-IP
    ///
    /// Or using HaProxy protocol.
    pub fn forward(self, kind: ForwardKind) -> Self {
        self.maybe_forward(Some(kind))
    }

    /// maybe enable support for one of the following "forward" headers or protocols.
    ///
    /// See [`Self::forward`] for more information.
    pub fn maybe_forward(mut self, maybe_kind: Option<ForwardKind>) -> Self {
        self.forward = maybe_kind;
        self
    }

    /// define a tls server cert config to be used for tls terminaton
    /// by the echo service.
    pub fn tls_server_config(mut self, cfg: TlsServerCertKeyPair) -> Self {
        self.tls_server_config = Some(cfg);
        self
    }

    /// maybe define a tls server cert config to be used for tls terminaton
    /// by the echo service.
    pub fn maybe_tls_server_config(mut self, cfg: Option<TlsServerCertKeyPair>) -> Self {
        self.tls_server_config = cfg;
        self
    }

    /// add a custom http layer which will be applied to the existing http layers
    pub fn http_layer<H2>(self, layer: H2) -> EchoServiceBuilder<Stack<H2, H>> {
        EchoServiceBuilder {
            concurrent_limit: self.concurrent_limit,
            timeout: self.timeout,
            forward: self.forward,
            tls_server_config: self.tls_server_config,
            http_service_builder: self.http_service_builder.layer(layer),
        }
    }
}

impl<H> EchoServiceBuilder<H>
where
    H: Layer<EchoService>,
    H::Service: Service<(), Request, Response = Response, Error = BoxError>,
{
    /// build a tcp service ready to echo http traffic back
    pub fn build(
        mut self,
        executor: Executor,
    ) -> Result<impl Service<(), TcpStream, Response = (), Error = Infallible>, BoxError> {
        let (tcp_forwarded_layer, http_forwarded_layer) = match &self.forward {
            None => (None, None),
            Some(ForwardKind::Forwarded) => (
                None,
                Some(Either7::A(GetForwardedHeadersLayer::forwarded())),
            ),
            Some(ForwardKind::XForwardedFor) => (
                None,
                Some(Either7::B(GetForwardedHeadersLayer::x_forwarded_for())),
            ),
            Some(ForwardKind::XClientIp) => (
                None,
                Some(Either7::C(GetForwardedHeadersLayer::<XClientIp>::new())),
            ),
            Some(ForwardKind::ClientIp) => (
                None,
                Some(Either7::D(GetForwardedHeadersLayer::<ClientIp>::new())),
            ),
            Some(ForwardKind::XRealIp) => (
                None,
                Some(Either7::E(GetForwardedHeadersLayer::<XRealIp>::new())),
            ),
            Some(ForwardKind::CFConnectingIp) => (
                None,
                Some(Either7::F(GetForwardedHeadersLayer::<CFConnectingIp>::new())),
            ),
            Some(ForwardKind::TrueClientIp) => (
                None,
                Some(Either7::G(GetForwardedHeadersLayer::<TrueClientIp>::new())),
            ),
            Some(ForwardKind::HaProxy) => (Some(HaProxyLayer::default()), None),
        };

        let tls_server_cfg = match self.tls_server_config.take() {
            None => None,
            Some(cfg) => Some(
                cfg.into_server_config()
                    .map_err(OpaqueError::from_boxed)
                    .context("build server config from env tls key/cert pair")?,
            ),
        };

        let tcp_service_builder = ServiceBuilder::new()
            .layer(ConsumeErrLayer::trace(tracing::Level::DEBUG))
            .layer(
                (self.concurrent_limit > 0)
                    .then(|| LimitLayer::new(ConcurrentPolicy::max(self.concurrent_limit))),
            )
            .layer((!self.timeout.is_zero()).then(|| TimeoutLayer::new(self.timeout)))
            .layer(tcp_forwarded_layer)
            // Limit the body size to 1MB for requests
            .layer(BodyLimitLayer::request_only(1024 * 1024))
            .layer(tls_server_cfg.map(|cfg| {
                TlsAcceptorLayer::with_client_config_handler(
                    cfg,
                    TlsClientConfigHandler::default().store_client_hello(),
                )
            }));

        let http_service = ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(AddRequiredResponseHeadersLayer::default())
            .layer(UserAgentClassifierLayer::new())
            .layer(ConsumeErrLayer::default())
            .layer(http_forwarded_layer)
            .service(self.http_service_builder.service(EchoService));

        Ok(tcp_service_builder.service(HttpServer::auto(executor).service(http_service)))
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// The inner echo-service used by the [`EchoServiceBuilder`].
pub struct EchoService;

impl Service<(), Request> for EchoService {
    type Response = Response;
    type Error = BoxError;

    async fn serve(
        &self,
        mut ctx: Context<()>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let user_agent_info = ctx
            .get()
            .map(|ua: &UserAgent| {
                json!({
                    "user_agent": ua.header_str().to_owned(),
                    "kind": ua.info().map(|info| info.kind.to_string()),
                    "version": ua.info().and_then(|info| info.version),
                    "platform": ua.platform().map(|v| v.to_string()),
                })
            })
            .unwrap_or_default();

        let request_context =
            ctx.get_or_try_insert_with_ctx::<RequestContext, _>(|ctx| (ctx, &req).try_into())?;
        let authority = request_context.authority.to_string();
        let scheme = request_context.protocol.to_string();

        // TODO: get in correct order
        // TODO: get in correct case
        // TODO: get also pseudo headers (or separate?!)

        let headers: Vec<_> = req
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    value.to_str().map(|v| v.to_owned()).unwrap_or_default(),
                )
            })
            .collect();

        let (parts, body) = req.into_parts();

        let body = body.collect().await.unwrap().to_bytes();
        let body = hex::encode(body.as_ref());

        let tls_client_hello = ctx.get::<ClientHello>().map(|hello| {
            json!({
                "server_name": hello.ext_server_name().clone(),
                "signature_schemes": hello
                    .ext_signature_algorithms()
                    .map(|slice| slice.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
                "alpn": hello
                    .ext_alpn()
                    .map(|slice| slice.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
                "cipher_suites": hello
                    .cipher_suites().iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            })
        });

        Ok(Json(json!({
            "ua": user_agent_info,
            "http": {
                "version": format!("{:?}", parts.version),
                "scheme": scheme,
                "method": format!("{:?}", parts.method),
                "authority": authority,
                "path": parts.uri.path().to_owned(),
                "query": parts.uri.query().map(str::to_owned),
                "headers": headers,
                "payload": body,
            },
            "tls": tls_client_hello,
            "socket_addr": ctx.get::<Forwarded>()
                .and_then(|f|
                        f.client_socket_addr().map(|addr| addr.to_string())
                            .or_else(|| f.client_ip().map(|ip| ip.to_string()))
                ).or_else(|| ctx.get::<SocketInfo>().map(|v| v.peer_addr().to_string())),
        }))
        .into_response())
    }
}
