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
    },
    layer::{ConsumeErrLayer, LimitLayer, TimeoutLayer, limit::policy::ConcurrentPolicy},
    net::forwarded::Forwarded,
    net::stream::{SocketInfo, Stream, layer::http::BodyLimitLayer},
    proxy::haproxy::server::HaProxyLayer,
    rt::Executor,
    telemetry::tracing,
};
use rama_http::service::web::response::IntoResponse;
use std::{convert::Infallible, marker::PhantomData, time::Duration};
use tokio::{io::AsyncWriteExt, net::TcpStream};

#[derive(Debug, Clone)]
/// Builder that can be used to run your own ip [`Service`],
/// echo'ing back the client IP over http or tcp.
pub struct IpServiceBuilder<M> {
    concurrent_limit: usize,
    timeout: Duration,
    forward: Option<ForwardKind>,
    _mode: PhantomData<fn(M)>,
}

impl Default for IpServiceBuilder<mode::Http> {
    fn default() -> Self {
        Self {
            concurrent_limit: 0,
            timeout: Duration::ZERO,
            forward: None,
            _mode: PhantomData,
        }
    }
}

impl IpServiceBuilder<mode::Http> {
    /// Create a new [`IpServiceBuilder`], echoing the IP back over HTTP.
    #[must_use]
    pub fn http() -> Self {
        Self::default()
    }
}

impl IpServiceBuilder<mode::Transport> {
    /// Create a new [`IpServiceBuilder`], echoing the IP back over L4.
    #[must_use]
    pub fn tcp() -> Self {
        Self {
            concurrent_limit: 0,
            timeout: Duration::ZERO,
            forward: None,
            _mode: PhantomData,
        }
    }
}

impl<M> IpServiceBuilder<M> {
    /// set the number of concurrent connections to allow
    ///
    /// (0 = no limit)
    #[must_use]
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
    #[must_use]
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
    #[must_use]
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
    #[must_use]
    pub fn maybe_forward(mut self, maybe_kind: Option<ForwardKind>) -> Self {
        self.forward = maybe_kind;
        self
    }
}

impl IpServiceBuilder<mode::Http> {
    /// build a tcp service ready to echo http traffic back
    pub fn build(
        self,
        executor: Executor,
    ) -> Result<impl Service<(), TcpStream, Response = (), Error = Infallible>, BoxError> {
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

        // TODO: support opt-in TLS)

        let http_service = (
            TraceLayer::new_for_http(),
            AddRequiredResponseHeadersLayer::default(),
            UserAgentClassifierLayer::new(),
            ConsumeErrLayer::default(),
            http_forwarded_layer,
        )
            .into_layer(HttpEchoService);

        Ok(tcp_service_builder.into_layer(HttpServer::auto(executor).service(http_service)))
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// The inner http echo-service used by the [`IpServiceBuilder`].
pub struct HttpEchoService;

impl Service<(), Request> for HttpEchoService {
    type Response = Response;
    type Error = BoxError;

    async fn serve(&self, ctx: Context<()>, _req: Request) -> Result<Self::Response, Self::Error> {
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
pub struct TcpEchoService;

impl<Input> Service<(), Input> for TcpEchoService
where
    Input: Stream + Unpin,
{
    type Response = ();
    type Error = BoxError;

    async fn serve(&self, ctx: Context<()>, stream: Input) -> Result<Self::Response, Self::Error> {
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
    /// build a tcp service ready to echo http traffic back
    pub fn build(
        self,
    ) -> Result<impl Service<(), TcpStream, Response = (), Error = Infallible>, BoxError> {
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

        Ok(tcp_service_builder.into_layer(TcpEchoService))
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
}
