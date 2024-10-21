//! Echo '[`Service`] that echos the [`http`] [`Request`] and [`tls`] client config.
//!
//! [`Service`]: crate::Service
//! [`http`]: crate::http
//! [`Request`]: crate::http::Request
//! [`tls`]: crate::tls

use crate::{
    cli::ForwardKind,
    combinators::Either7,
    error::BoxError,
    http::{
        dep::http_body_util::BodyExt,
        headers::{CFConnectingIp, ClientIp, TrueClientIp, XClientIp, XRealIp},
        layer::{
            forwarded::GetForwardedHeadersLayer,
            required_header::AddRequiredResponseHeadersLayer,
            trace::TraceLayer,
            ua::{UserAgent, UserAgentClassifierLayer},
        },
        response::Json,
        server::HttpServer,
        IntoResponse, Request, Response,
    },
    layer::{limit::policy::ConcurrentPolicy, ConsumeErrLayer, LimitLayer, TimeoutLayer},
    net::forwarded::Forwarded,
    net::http::RequestContext,
    net::stream::{layer::http::BodyLimitLayer, SocketInfo},
    proxy::haproxy::server::HaProxyLayer,
    rt::Executor,
    Context, Layer, Service,
};
use rama_core::{combinators::Either3, error::OpaqueError};
use serde_json::json;
use std::{convert::Infallible, time::Duration};
use tokio::net::TcpStream;

#[cfg(any(feature = "rustls", feature = "boring"))]
use crate::{
    http::Version,
    net::tls::server::ServerConfig,
    tls::std::server::TlsAcceptorLayer,
    tls::types::{client::ClientHelloExtension, SecureTransport},
};

#[derive(Debug, Clone)]
/// Builder that can be used to run your own echo [`Service`],
/// echo'ing back information about that request and its underlying transport / presentation layers.
pub struct EchoServiceBuilder<H> {
    concurrent_limit: usize,
    timeout: Duration,
    forward: Option<ForwardKind>,

    #[cfg(any(feature = "rustls", feature = "boring"))]
    tls_server_config: Option<ServerConfig>,

    http_version: Option<Version>,

    http_service_builder: H,
}

impl Default for EchoServiceBuilder<()> {
    fn default() -> Self {
        Self {
            concurrent_limit: 0,
            timeout: Duration::ZERO,
            forward: None,

            #[cfg(any(feature = "rustls", feature = "boring"))]
            tls_server_config: None,

            http_version: None,

            http_service_builder: (),
        }
    }
}

impl EchoServiceBuilder<()> {
    /// Create a new [`EchoServiceBuilder`].
    pub fn new() -> Self {
        Self::default()
    }
}

impl<H> EchoServiceBuilder<H> {
    /// set the number of concurrent connections to allow
    ///
    /// (0 = no limit)
    pub fn concurrent(mut self, limit: usize) -> Self {
        self.concurrent_limit = limit;
        self
    }

    /// set the number of concurrent connections to allow
    ///
    /// (0 = no limit)
    pub fn set_concurrent(&mut self, limit: usize) -> &mut Self {
        self.concurrent_limit = limit;
        self
    }

    /// set the timeout in seconds for each connection
    ///
    /// (0 = no timeout)
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// set the timeout in seconds for each connection
    ///
    /// (0 = no timeout)
    pub fn set_timeout(&mut self, timeout: Duration) -> &mut Self {
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

    /// enable support for one of the following "forward" headers or protocols
    ///
    /// Same as [`Self::forward`] but without consuming `self`.
    pub fn set_forward(&mut self, kind: ForwardKind) -> &mut Self {
        self.forward = Some(kind);
        self
    }

    /// maybe enable support for one of the following "forward" headers or protocols.
    ///
    /// See [`Self::forward`] for more information.
    pub fn maybe_forward(mut self, maybe_kind: Option<ForwardKind>) -> Self {
        self.forward = maybe_kind;
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// define a tls server cert config to be used for tls terminaton
    /// by the echo service.
    pub fn tls_server_config(mut self, cfg: ServerConfig) -> Self {
        self.tls_server_config = Some(cfg);
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// define a tls server cert config to be used for tls terminaton
    /// by the echo service.
    pub fn set_tls_server_config(&mut self, cfg: ServerConfig) -> &mut Self {
        self.tls_server_config = Some(cfg);
        self
    }

    #[cfg(any(feature = "rustls", feature = "boring"))]
    /// maybe define a tls server cert config to be used for tls terminaton
    /// by the echo service.
    pub fn maybe_tls_server_config(mut self, cfg: Option<ServerConfig>) -> Self {
        self.tls_server_config = cfg;
        self
    }

    /// set the http version to use for the http server (auto by default)
    pub fn http_version(mut self, version: Version) -> Self {
        self.http_version = Some(version);
        self
    }

    /// maybe set the http version to use for the http server (auto by default)
    pub fn maybe_http_version(mut self, version: Option<Version>) -> Self {
        self.http_version = version;
        self
    }

    /// set the http version to use for the http server (auto by default)
    pub fn set_http_version(&mut self, version: Version) -> &mut Self {
        self.http_version = Some(version);
        self
    }

    /// add a custom http layer which will be applied to the existing http layers
    pub fn http_layer<H2>(self, layer: H2) -> EchoServiceBuilder<(H, H2)> {
        EchoServiceBuilder {
            concurrent_limit: self.concurrent_limit,
            timeout: self.timeout,
            forward: self.forward,

            #[cfg(any(feature = "rustls", feature = "boring"))]
            tls_server_config: self.tls_server_config,

            http_version: self.http_version,

            http_service_builder: (self.http_service_builder, layer),
        }
    }
}

impl<H> EchoServiceBuilder<H>
where
    H: Layer<EchoService, Service: Service<(), Request, Response = Response, Error = BoxError>>,
{
    #[allow(unused_mut)]
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

        #[cfg(any(feature = "rustls", feature = "boring"))]
        let tls_acceptor_data = match self.tls_server_config {
            None => None,
            Some(cfg) => Some(cfg.try_into()?),
        };

        let tcp_service_builder = (
            ConsumeErrLayer::trace(tracing::Level::DEBUG),
            (self.concurrent_limit > 0)
                .then(|| LimitLayer::new(ConcurrentPolicy::max(self.concurrent_limit))),
            (!self.timeout.is_zero()).then(|| TimeoutLayer::new(self.timeout)),
            tcp_forwarded_layer,
            // Limit the body size to 1MB for requests
            BodyLimitLayer::request_only(1024 * 1024),
            #[cfg(any(feature = "rustls", feature = "boring"))]
            tls_acceptor_data.map(|data| TlsAcceptorLayer::new(data).with_store_client_hello(true)),
        );

        let http_service = (
            TraceLayer::new_for_http(),
            AddRequiredResponseHeadersLayer::default(),
            UserAgentClassifierLayer::new(),
            ConsumeErrLayer::default(),
            http_forwarded_layer,
        )
            .layer(self.http_service_builder.layer(EchoService));

        let http_transport_service = match self.http_version {
            Some(Version::HTTP_2) => Either3::A(HttpServer::h2(executor).service(http_service)),
            Some(Version::HTTP_11 | Version::HTTP_10 | Version::HTTP_09) => {
                Either3::B(HttpServer::http1().service(http_service))
            }
            Some(_) => {
                return Err(OpaqueError::from_display("unsupported http version").into_boxed())
            }
            None => Either3::C(HttpServer::auto(executor).service(http_service)),
        };

        Ok(tcp_service_builder.layer(http_transport_service))
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

        #[cfg(any(feature = "rustls", feature = "boring"))]
        let tls_client_hello = ctx
            .get::<SecureTransport>()
            .and_then(|st| st.client_hello())
            .map(|hello| {
                json!({
                    "cipher_suites": hello
                    .cipher_suites().iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                    "compression_algorithms": hello
                    .compression_algorithms().iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                    "extensions": hello.extensions().iter().map(|extension| match extension {
                        ClientHelloExtension::ServerName(domain) => json!({
                            "id": extension.id().to_string(),
                            "data": domain,
                        }),
                        ClientHelloExtension::SignatureAlgorithms(v) => json!({
                            "id": extension.id().to_string(),
                            "data": v.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                        }),
                        ClientHelloExtension::SupportedVersions(v) => json!({
                            "id": extension.id().to_string(),
                            "data": v.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                        }),
                        ClientHelloExtension::ApplicationLayerProtocolNegotiation(v) => json!({
                            "id": extension.id().to_string(),
                            "data": v.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                        }),
                        ClientHelloExtension::SupportedGroups(v) => json!({
                            "id": extension.id().to_string(),
                            "data": v.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                        }),
                        ClientHelloExtension::ECPointFormats(v) => json!({
                            "id": extension.id().to_string(),
                            "data": v.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                        }),
                        ClientHelloExtension::Opaque { id, data } => json!({
                            "id": id.to_string(),
                            "data": format!("0x{}", hex::encode(data)),
                        }),
                    }).collect::<Vec<_>>(),
                })
            });

        #[cfg(not(any(feature = "rustls", feature = "boring")))]
        let tls_client_hello: Option<()> = None;

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
