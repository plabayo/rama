//! IP '[`Service`] that echos the client IP either over http or directly over tcp.
//!
//! [`Service`]: crate::Service

use crate::{
    Context, Layer, Service,
    cli::ForwardKind,
    combinators::Either7,
    error::{BoxError, OpaqueError},
    http::{
        Request, Response, StatusCode,
        headers::forwarded::{CFConnectingIp, ClientIp, TrueClientIp, XClientIp, XRealIp},
        layer::{
            forwarded::GetForwardedHeaderLayer, required_header::AddRequiredResponseHeadersLayer,
            trace::TraceLayer, ua::UserAgentClassifierLayer,
        },
        server::HttpServer,
        service::web::response::IntoResponse,
    },
    layer::{ConsumeErrLayer, LimitLayer, TimeoutLayer, limit::policy::ConcurrentPolicy},
    net::forwarded::Forwarded,
    net::http::server::HttpPeekRouter,
    net::stream::{SocketInfo, layer::http::BodyLimitLayer},
    proxy::haproxy::server::HaProxyLayer,
    rt::Executor,
    stream::Stream,
    telemetry::tracing,
};

#[cfg(all(feature = "rustls", not(feature = "boring")))]
use crate::tls::rustls::server::{TlsAcceptorData, TlsAcceptorLayer};

#[cfg(feature = "boring")]
use crate::{
    net::tls::server::ServerConfig,
    tls::boring::server::{TlsAcceptorData, TlsAcceptorLayer},
};

#[cfg(feature = "boring")]
type TlsConfig = ServerConfig;

#[cfg(all(feature = "rustls", not(feature = "boring")))]
type TlsConfig = TlsAcceptorData;

#[cfg(any(feature = "rustls", feature = "boring"))]
use rama_core::{combinators::Either, layer::MapRequestLayer};

use std::{convert::Infallible, marker::PhantomData, time::Duration};
use tokio::{io::AsyncWriteExt, net::TcpStream};

#[derive(Debug, Clone)]
/// Builder that can be used to run your own ip [`Service`],
/// echo'ing back the client IP over http or tcp.
pub struct IpServiceBuilder<M> {
    #[cfg(any(feature = "rustls", feature = "boring"))]
    tls_server_config: Option<TlsConfig>,
    concurrent_limit: usize,
    timeout: Duration,
    peek_timeout: Duration,
    forward: Option<ForwardKind>,
    _mode: PhantomData<fn(M)>,
}

impl Default for IpServiceBuilder<mode::Auto> {
    fn default() -> Self {
        Self {
            #[cfg(any(feature = "rustls", feature = "boring"))]
            tls_server_config: None,
            concurrent_limit: 0,
            timeout: Duration::ZERO,
            peek_timeout: Duration::ZERO,
            forward: None,
            _mode: PhantomData,
        }
    }
}

impl IpServiceBuilder<mode::Auto> {
    /// Create a new [`IpServiceBuilder`], echoing the IP back over HTTP.
    #[must_use]
    pub fn auto() -> Self {
        Self::default()
    }
}

impl IpServiceBuilder<mode::Http> {
    /// Create a new [`IpServiceBuilder`], echoing the IP back over L4.
    #[must_use]
    pub fn http() -> Self {
        Self {
            #[cfg(any(feature = "rustls", feature = "boring"))]
            tls_server_config: None,
            concurrent_limit: 0,
            timeout: Duration::ZERO,
            peek_timeout: Duration::ZERO,
            forward: None,
            _mode: PhantomData,
        }
    }
}

impl IpServiceBuilder<mode::Transport> {
    /// Create a new [`IpServiceBuilder`], echoing the IP back over L4.
    #[must_use]
    pub fn tcp() -> Self {
        Self {
            #[cfg(any(feature = "rustls", feature = "boring"))]
            tls_server_config: None,
            concurrent_limit: 0,
            timeout: Duration::ZERO,
            peek_timeout: Duration::ZERO,
            forward: None,
            _mode: PhantomData,
        }
    }
}

impl<M> IpServiceBuilder<M> {
    crate::utils::macros::generate_set_and_with! {
        /// set the number of concurrent connections to allow
        #[must_use]
        pub fn concurrent(mut self, limit: usize) -> Self {
            self.concurrent_limit = limit;
            self
        }
    }

    crate::utils::macros::generate_set_and_with! {
        /// set the timeout in seconds for each connection
        #[must_use]
        pub fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }
    }

    crate::utils::macros::generate_set_and_with! {
        /// maybe enable support for one of the following "forward" headers or protocols
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
        #[must_use]
        pub fn forward(mut self, maybe_kind: Option<ForwardKind>) -> Self {
            self.forward = maybe_kind;
            self
        }
    }

    crate::utils::macros::generate_set_and_with! {
        #[cfg(any(feature = "rustls", feature = "boring"))]
        /// define a tls server cert config to be used for tls terminaton
        /// by the IP service.
        pub fn tls_server_config(mut self, cfg: Option<TlsConfig>) -> Self {
            self.tls_server_config = cfg;
            self
        }
    }
}

impl IpServiceBuilder<mode::Http> {
    #[allow(unused_mut)]
    #[inline]
    /// build a tcp service ready to echo the client IP back
    pub fn build(
        mut self,
        executor: Executor,
    ) -> Result<impl Service<TcpStream, Response = (), Error = Infallible>, BoxError> {
        #[cfg(all(feature = "rustls", not(feature = "boring")))]
        let tls_cfg = self.tls_server_config.take();

        #[cfg(feature = "boring")]
        let tls_cfg: Option<TlsAcceptorData> = match self.tls_server_config.take() {
            Some(cfg) => Some(cfg.try_into()?),
            None => None,
        };

        #[cfg(any(feature = "rustls", feature = "boring"))]
        match tls_cfg {
            Some(tls_cfg) => Ok((
                ConsumeErrLayer::trace(tracing::Level::DEBUG),
                TlsAcceptorLayer::new(tls_cfg),
            )
                .into_layer(self.build_http(executor)?)
                .boxed()),
            None => Ok(self.build_http(executor)?.boxed()),
        }

        #[cfg(not(any(feature = "rustls", feature = "boring")))]
        self.build_http(executor)
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// The inner http ip-service used by the [`IpServiceBuilder`].
struct HttpIpService;

impl Service<Request> for HttpIpService {
    type Response = Response;
    type Error = BoxError;

    async fn serve(&self, ctx: Context, _req: Request) -> Result<Self::Response, Self::Error> {
        let peer_ip = ctx
            .get::<Forwarded>()
            .and_then(|f| f.client_ip())
            .or_else(|| ctx.get::<SocketInfo>().map(|s| s.peer_addr().ip()));

        Ok(match peer_ip {
            Some(ip) => ip.to_string().into_response(),
            None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        })
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// The inner tcp echo-service used by the [`IpServiceBuilder`].
struct TcpIpService;

impl<Input> Service<Input> for TcpIpService
where
    Input: Stream + Unpin,
{
    type Response = ();
    type Error = BoxError;

    async fn serve(&self, ctx: Context, stream: Input) -> Result<Self::Response, Self::Error> {
        tracing::info!("connection received");
        let peer_ip = ctx
            .get::<Forwarded>()
            .and_then(|f| f.client_ip())
            .or_else(|| ctx.get::<SocketInfo>().map(|s| s.peer_addr().ip()));
        let Some(peer_ip) = peer_ip else {
            tracing::error!("missing peer information");
            return Ok(());
        };

        let mut stream = std::pin::pin!(stream);

        match peer_ip {
            std::net::IpAddr::V4(ip) => {
                if let Err(err) = stream.write_all(&ip.octets()).await {
                    tracing::error!("error writing IPv4 of peer to peer: {}", err);
                }
            }
            std::net::IpAddr::V6(ip) => {
                if let Err(err) = stream.write_all(&ip.octets()).await {
                    tracing::error!("error writing IPv6 of peer to peer: {}", err);
                }
            }
        };

        Ok(())
    }
}

impl IpServiceBuilder<mode::Transport> {
    #[allow(unused_mut)]
    #[inline]
    /// build a tcp service ready to echo client IP back
    pub fn build(
        mut self,
    ) -> Result<impl Service<TcpStream, Response = (), Error = Infallible>, BoxError> {
        #[cfg(all(feature = "rustls", not(feature = "boring")))]
        let tls_cfg = self.tls_server_config.take();

        #[cfg(feature = "boring")]
        let tls_cfg: Option<TlsAcceptorData> = match self.tls_server_config.take() {
            Some(cfg) => Some(cfg.try_into()?),
            None => None,
        };

        #[cfg(any(feature = "rustls", feature = "boring"))]
        match tls_cfg {
            Some(tls_cfg) => Ok((
                ConsumeErrLayer::trace(tracing::Level::DEBUG),
                TlsAcceptorLayer::new(tls_cfg),
            )
                .into_layer(self.build_tcp()?)
                .boxed()),
            None => Ok(self.build_tcp()?.boxed()),
        }

        #[cfg(not(any(feature = "rustls", feature = "boring")))]
        self.build_tcp()
    }
}

impl<M> IpServiceBuilder<M> {
    fn build_tcp<S: Stream + Unpin + Send + Sync + 'static>(
        self,
    ) -> Result<impl Service<S, Response = (), Error = Infallible>, BoxError> {
        let tcp_forwarded_layer = match &self.forward {
            None => None,
            Some(ForwardKind::HaProxy) => Some(HaProxyLayer::default()),
            Some(other) => {
                return Err(OpaqueError::from_display(format!(
                    "invalid forward kind for Transport mode: {other:?}"
                ))
                .into());
            }
        };

        let tcp_service_builder = (
            ConsumeErrLayer::trace(tracing::Level::DEBUG),
            (self.concurrent_limit > 0)
                .then(|| LimitLayer::new(ConcurrentPolicy::max(self.concurrent_limit))),
            (!self.timeout.is_zero()).then(|| TimeoutLayer::new(self.timeout)),
            tcp_forwarded_layer,
        );

        Ok(tcp_service_builder.into_layer(TcpIpService))
    }

    fn build_http<S: Stream + Unpin + Send + Sync + 'static>(
        self,
        executor: Executor,
    ) -> Result<impl Service<S, Response = (), Error = Infallible>, BoxError> {
        let (tcp_forwarded_layer, http_forwarded_layer) = match &self.forward {
            None => (None, None),
            Some(ForwardKind::Forwarded) => {
                (None, Some(Either7::A(GetForwardedHeaderLayer::forwarded())))
            }
            Some(ForwardKind::XForwardedFor) => (
                None,
                Some(Either7::B(GetForwardedHeaderLayer::x_forwarded_for())),
            ),
            Some(ForwardKind::XClientIp) => (
                None,
                Some(Either7::C(GetForwardedHeaderLayer::<XClientIp>::new())),
            ),
            Some(ForwardKind::ClientIp) => (
                None,
                Some(Either7::D(GetForwardedHeaderLayer::<ClientIp>::new())),
            ),
            Some(ForwardKind::XRealIp) => (
                None,
                Some(Either7::E(GetForwardedHeaderLayer::<XRealIp>::new())),
            ),
            Some(ForwardKind::CFConnectingIp) => (
                None,
                Some(Either7::F(GetForwardedHeaderLayer::<CFConnectingIp>::new())),
            ),
            Some(ForwardKind::TrueClientIp) => (
                None,
                Some(Either7::G(GetForwardedHeaderLayer::<TrueClientIp>::new())),
            ),
            Some(ForwardKind::HaProxy) => (Some(HaProxyLayer::default()), None),
        };

        let tcp_service_builder = (
            ConsumeErrLayer::trace(tracing::Level::DEBUG),
            (self.concurrent_limit > 0)
                .then(|| LimitLayer::new(ConcurrentPolicy::max(self.concurrent_limit))),
            (!self.timeout.is_zero()).then(|| TimeoutLayer::new(self.timeout)),
            tcp_forwarded_layer,
            // Limit the body size to 1MB for requests
            BodyLimitLayer::request_only(1024 * 1024),
        );

        let http_service = (
            TraceLayer::new_for_http(),
            AddRequiredResponseHeadersLayer::default(),
            UserAgentClassifierLayer::new(),
            ConsumeErrLayer::default(),
            http_forwarded_layer,
        )
            .into_layer(HttpIpService);

        // TODO: enable TLS once we make use of our remote ACME provider
        // TlsPeekRouter::new(TlsAcceptorLayer::new(TlsAcceptorDataBuilder::new(cert_chain, key_der)))

        Ok(tcp_service_builder.into_layer(HttpServer::auto(executor).service(http_service)))
    }
}

impl IpServiceBuilder<mode::Auto> {
    crate::utils::macros::generate_set_and_with! {
        /// Set the peek window to timeout on (to wait for http traffic)
        pub fn peek_timeout(mut self, peek_timeout: Duration) -> Self {
            self.peek_timeout = peek_timeout;
            self
        }
    }

    /// build a tcp service ready to echo client IP back
    #[allow(unused_mut)]
    pub fn build(
        mut self,
        executor: Executor,
    ) -> Result<impl Service<TcpStream, Response = (), Error = Infallible>, BoxError> {
        #[cfg(all(feature = "rustls", not(feature = "boring")))]
        let tls_cfg = self.tls_server_config.take();

        #[cfg(feature = "boring")]
        let tls_cfg: Option<TlsAcceptorData> = match self.tls_server_config.take() {
            Some(cfg) => Some(cfg.try_into()?),
            None => None,
        };

        let svc_http = self.clone().build_http(executor)?;
        let peek_timeout = self.peek_timeout;
        let svc_tcp = self.build_tcp()?;

        let router = HttpPeekRouter::new(svc_http)
            .with_fallback(svc_tcp)
            .maybe_with_peek_timeout((!peek_timeout.is_zero()).then_some(peek_timeout));

        #[cfg(any(feature = "rustls", feature = "boring"))]
        {
            Ok((
                ConsumeErrLayer::trace(tracing::Level::DEBUG),
                match tls_cfg {
                    Some(tls_cfg) => Either::A((
                        TlsAcceptorLayer::new(tls_cfg),
                        MapRequestLayer::new(Either::A),
                    )),
                    None => Either::B(MapRequestLayer::new(Either::B)),
                },
            )
                .into_layer(router))
        }

        #[cfg(not(any(feature = "rustls", feature = "boring")))]
        {
            Ok(ConsumeErrLayer::trace(tracing::Level::DEBUG).into_layer(router))
        }
    }
}

pub mod mode {
    //! operation modes of the ip service

    #[derive(Debug, Clone)]
    #[non_exhaustive]
    /// Default mode of the Ip service, echo'ng the info back over http
    pub struct Http;

    #[derive(Debug, Clone)]
    #[non_exhaustive]
    /// Alternative mode of the Ip service, echo'ng the ip info over tcp
    pub struct Transport;

    #[derive(Debug, Clone)]
    #[non_exhaustive]
    /// Default mode of the Ip service, echo'ng the IP over
    /// http if that was detected, otherwise over tcp directly.
    pub struct Auto;
}
