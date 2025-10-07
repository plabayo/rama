//! IP '[`Service`] that echos the client IP either over http or directly over tcp.
//!
//! [`Service`]: crate::Service

use crate::{
    Layer, Service,
    cli::ForwardKind,
    combinators::Either7,
    error::{BoxError, OpaqueError},
    extensions::{ExtensionsMut, ExtensionsRef},
    http::{
        Request, Response, StatusCode,
        headers::forwarded::{CFConnectingIp, ClientIp, TrueClientIp, XClientIp, XRealIp},
        headers::{Accept, HeaderMapExt},
        layer::{
            forwarded::GetForwardedHeaderLayer, required_header::AddRequiredResponseHeadersLayer,
            trace::TraceLayer,
        },
        mime,
        server::HttpServer,
        service::web::response::{Html, IntoResponse, Json, Redirect},
    },
    layer::{ConsumeErrLayer, LimitLayer, TimeoutLayer, limit::policy::ConcurrentPolicy},
    net::forwarded::Forwarded,
    net::stream::{SocketInfo, layer::http::BodyLimitLayer},
    proxy::haproxy::server::HaProxyLayer,
    rt::Executor,
    stream::Stream,
    tcp::TcpStream,
    telemetry::tracing,
};

#[cfg(all(feature = "rustls", not(feature = "boring")))]
use crate::tls::rustls::server::{TlsAcceptorData, TlsAcceptorLayer};

#[cfg(any(feature = "rustls", feature = "boring"))]
use crate::http::{headers::StrictTransportSecurity, layer::set_header::SetResponseHeaderLayer};

#[cfg(feature = "boring")]
use crate::{
    net::tls::server::ServerConfig,
    tls::boring::server::{TlsAcceptorData, TlsAcceptorLayer},
};

#[cfg(feature = "boring")]
type TlsConfig = ServerConfig;

#[cfg(all(feature = "rustls", not(feature = "boring")))]
type TlsConfig = TlsAcceptorData;

use std::{convert::Infallible, marker::PhantomData, net::IpAddr, time::Duration};
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone)]
/// Builder that can be used to run your own ip [`Service`],
/// echo'ing back the client IP over http or tcp.
pub struct IpServiceBuilder<M> {
    #[cfg(any(feature = "rustls", feature = "boring"))]
    tls_server_config: Option<TlsConfig>,
    concurrent_limit: usize,
    timeout: Duration,
    forward: Option<ForwardKind>,
    _mode: PhantomData<fn(M)>,
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
        {
            let maybe_tls_acceptor_layer = tls_cfg.map(TlsAcceptorLayer::new);
            self.build_http(executor, maybe_tls_acceptor_layer)
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

    async fn serve(&self, req: Request) -> Result<Self::Response, Self::Error> {
        let norm_req_path = req.uri().path().trim_matches('/');
        if !norm_req_path.is_empty() {
            tracing::debug!("unexpected request path '{norm_req_path}', redirect to root");
            return Ok(Redirect::permanent("/").into_response());
        }

        let peer_ip = req
            .extensions()
            .get::<Forwarded>()
            .and_then(|f| f.client_ip())
            .or_else(|| {
                req.extensions()
                    .get::<SocketInfo>()
                    .map(|s| s.peer_addr().ip())
            });

        Ok(match peer_ip {
            Some(ip) => match HttpBodyContentFormat::derive_from_req(&req) {
                HttpBodyContentFormat::Txt => ip.to_string().into_response(),
                HttpBodyContentFormat::Html => format_html_page(ip).into_response(),
                HttpBodyContentFormat::Json => Json(serde_json::json!({
                    "ip": ip,
                }))
                .into_response(),
            },
            None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum HttpBodyContentFormat {
    #[default]
    Txt,
    Html,
    Json,
}

impl HttpBodyContentFormat {
    fn derive_from_req(req: &Request) -> Self {
        let Some(accept) = req.headers().typed_get::<Accept>() else {
            return Self::default();
        };
        accept
            .iter()
            .find_map(|qv| {
                let r#type = qv.value.subtype();
                if r#type == mime::JSON {
                    Some(Self::Json)
                } else if r#type == mime::HTML {
                    Some(Self::Html)
                } else if r#type == mime::TEXT {
                    Some(Self::Txt)
                } else {
                    None
                }
            })
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// The inner tcp echo-service used by the [`IpServiceBuilder`].
struct TcpIpService;

impl<Input> Service<Input> for TcpIpService
where
    Input: Stream + Unpin + ExtensionsRef,
{
    type Response = ();
    type Error = BoxError;

    async fn serve(&self, stream: Input) -> Result<Self::Response, Self::Error> {
        tracing::info!("connection received");
        let peer_ip = stream
            .extensions()
            .get::<Forwarded>()
            .and_then(|f| f.client_ip())
            .or_else(|| {
                stream
                    .extensions()
                    .get::<SocketInfo>()
                    .map(|s| s.peer_addr().ip())
            });
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
        {
            let maybe_tls_acceptor_layer = tls_cfg.map(TlsAcceptorLayer::new);
            self.build_tcp(maybe_tls_acceptor_layer)
        }

        #[cfg(not(any(feature = "rustls", feature = "boring")))]
        self.build_tcp()
    }
}

impl<M> IpServiceBuilder<M> {
    fn build_tcp<S: Stream + ExtensionsMut + Unpin + Send + Sync + 'static>(
        self,
        #[cfg(any(feature = "rustls", feature = "boring"))] maybe_tls_accept_layer: Option<
            TlsAcceptorLayer,
        >,
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
            #[cfg(any(feature = "rustls", feature = "boring"))]
            maybe_tls_accept_layer,
        );

        Ok(tcp_service_builder.into_layer(TcpIpService))
    }

    fn build_http<S: Stream + Unpin + Send + Sync + ExtensionsMut + 'static>(
        self,
        executor: Executor,
        #[cfg(any(feature = "rustls", feature = "boring"))] maybe_tls_accept_layer: Option<
            TlsAcceptorLayer,
        >,
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

        #[cfg(any(feature = "rustls", feature = "boring"))]
        let hsts_layer = maybe_tls_accept_layer.is_some().then(|| {
            SetResponseHeaderLayer::if_not_present_typed(
                StrictTransportSecurity::excluding_subdomains(Duration::from_secs(31536000)),
            )
        });

        let tcp_service_builder = (
            ConsumeErrLayer::trace(tracing::Level::DEBUG),
            (self.concurrent_limit > 0)
                .then(|| LimitLayer::new(ConcurrentPolicy::max(self.concurrent_limit))),
            (!self.timeout.is_zero()).then(|| TimeoutLayer::new(self.timeout)),
            tcp_forwarded_layer,
            // Limit the body size to 1MB for requests
            BodyLimitLayer::request_only(1024 * 1024),
            #[cfg(any(feature = "rustls", feature = "boring"))]
            maybe_tls_accept_layer,
        );

        let http_service = (
            TraceLayer::new_for_http(),
            AddRequiredResponseHeadersLayer::default(),
            ConsumeErrLayer::default(),
            #[cfg(any(feature = "rustls", feature = "boring"))]
            hsts_layer,
            http_forwarded_layer,
        )
            .into_layer(HttpIpService);

        Ok(tcp_service_builder.into_layer(HttpServer::auto(executor).service(http_service)))
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

fn format_html_page(ip: IpAddr) -> Html<String> {
    Html(format!(
        r##"<!doctype html> <html lang="en"> <head> <meta charset="utf-8" /> <meta name="viewport" content="width=device-width,initial-scale=1" /> <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='0.9em' font-size='90'>🦙</text></svg>" /> <title>Rama IP</title> <style> *, *::before, *::after {{ box-sizing: border-box; }} :root{{ --bg:#000; --panel:#0f0f0f; --green:#45d23a; --muted:#bfbfbf; }} html,body{{height:100%;margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,"Helvetica Neue",Arial;}} body{{ background:var(--bg); color:var(--muted); display:flex; align-items:center; justify-content:center; padding:2.8rem; }} .card{{ text-align:center; }} .logo{{ display:flex; align-items:center; justify-content:center; gap:0.8rem; margin-bottom:1.1rem; }} .logo, .logo a, .logo a:hover {{ color:var(--green); font-weight:700; font-size:2rem; letter-spacing:0.4rem; }} .logo a {{ text-decoration: none; }} .logo a:hover {{ text-decoration: underline; }} .subtitle{{ font-size:1.1rem; margin:0.3rem 0 2rem 0; color:var(--muted); }} .panel{{ background:linear-gradient(180deg,#0b0b0b 0%, #111 100%); border-radius:0.8rem; padding:2rem; box-shadow:0 0.3rem 2rem rgba(0,0,0,0.7), inset 0 0.05rem 0 rgba(255,255,255,0.02); border:0.1rem solid rgba(69,210,58,0.06); }} .ip{{ background:transparent; border-radius:0.6rem; padding:1rem 1.1rem; font-family: ui-monospace,SFMono-Regular,Menlo,monospace; font-size:1.1rem; color:#fff139; margin:0.6rem auto 1.1rem auto; word-break:break-all; border:0.05rem solid rgba(69,210,58,0.12); }} .muted{{ color:var(--muted); font-size:1rem; margin-bottom:0.9rem; }} .controls{{display:flex;gap:0.8rem;justify-content:center;flex-wrap:wrap;}} button{{ background:transparent; color:var(--green); padding:0.8rem 1.1rem; border-radius:0.6rem; font-weight:700; border:0.1rem solid rgba(69,210,58,0.9); cursor:pointer; }} button.primary{{ background:var(--green); color:#032; box-shadow:0 0.4rem 1.2rem rgba(69,210,58,0.08); }} .note{{font-size:0.95rem;color:#9aa; margin-top:1rem;}} .small{{font-size:0.9rem;color:#808080;margin-top:0.7rem}} </style> </head> <body> <div class="card"> <div class="logo"> <div>🦙</div> <div><a href="https://ramaproxy.org">ラマ</a></div> </div> <div class="panel" role="region" aria-label="ip panel"> <div class="muted">Your public ip</div><div id="ip" class="ip"> <code>{ip}</code> </div> <div class="controls"> <button id="copyBtn" class="primary" title="Copy ip to clipboard">📋 Copy IP</button></div> </div> <script> (async function(){{ const ipEl = document.getElementById('ip'); const copyBtn = document.getElementById('copyBtn'); copyBtn.addEventListener('click', async ()=>{{ const txt = ipEl.textContent.trim(); try{{ await navigator.clipboard.writeText(txt); copyBtn.textContent = 'Copied'; setTimeout(()=> copyBtn.textContent = 'Copy IP', 1400); }}catch(e){{ const ta = document.createElement('textarea'); ta.value = txt; document.body.appendChild(ta); ta.select(); try{{ document.execCommand('copy'); copyBtn.textContent = 'Copied'; }} catch(e){{ alert('Copy failed. Select and copy manually.'); }} ta.remove(); setTimeout(()=> copyBtn.textContent = 'Copy IP', 1400); }} }}); }})(); </script> </body> </html>"##,
    ))
}
