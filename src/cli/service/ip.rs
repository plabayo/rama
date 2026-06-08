//! IP '[`Service`] that echos the client IP either over http or directly over tcp.
//!
//! [`Service`]: crate::Service

#![expect(
    clippy::allow_attributes,
    reason = "feature-gated `mut self` consumed by some cfg branches but not others — `#[allow(unused_mut)]` would warn unfulfilled in the cfg arm where it IS used"
)]

use crate::{
    Layer, Service,
    cli::ForwardKind,
    combinators::Either,
    combinators::Either7,
    error::BoxError,
    error::{ErrorExt as _, extra::OpaqueError},
    extensions::ExtensionsRef,
    http::{
        Request, Response, StatusCode,
        headers::exotic::XClacksOverhead,
        headers::forwarded::{CFConnectingIp, ClientIp, TrueClientIp, XClientIp, XRealIp},
        headers::{Accept, HeaderMapExt},
        layer::{
            forwarded::GetForwardedHeaderLayer, required_header::AddRequiredResponseHeadersLayer,
            set_header::SetResponseHeaderLayer, trace::TraceLayer,
        },
        mime,
        server::HttpServer,
        service::web::response::{Css, IntoResponse, Json, Redirect, Script},
    },
    io::Io,
    layer::limit::policy::UnlimitedPolicy,
    layer::{ConsumeErrLayer, LimitLayer, TimeoutLayer, limit::policy::ConcurrentPolicy},
    net::forwarded::Forwarded,
    net::stream::{SocketInfo, layer::http::BodyLimitLayer},
    proxy::haproxy::server::HaProxyLayer,
    rt::Executor,
    tcp::TcpStream,
    telemetry::tracing,
};

#[cfg(all(feature = "rustls", not(feature = "boring")))]
use crate::tls::rustls::server::{TlsAcceptorData, TlsAcceptorLayer};

#[cfg(any(feature = "rustls", feature = "boring"))]
use crate::http::headers::StrictTransportSecurity;

#[cfg(feature = "boring")]
use crate::{
    net::tls::server::ServerConfig,
    tls::boring::server::{TlsAcceptorData, TlsAcceptorLayer},
};

#[cfg(feature = "boring")]
type TlsConfig = ServerConfig;

#[cfg(all(feature = "rustls", not(feature = "boring")))]
type TlsConfig = TlsAcceptorData;

use std::{convert::Infallible, marker::PhantomData, net::IpAddr, sync::Arc, time::Duration};
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
    ) -> Result<impl Service<TcpStream, Output = (), Error = Infallible>, BoxError> {
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
/// The inner http ip-service used by the [`IpServiceBuilder`]. Mounted at
/// `/` by the surrounding [`crate::http::service::web::Router`] in
/// [`IpServiceBuilder::build_http`]; the asset sidecars are sibling
/// routes on the same router.
struct HttpIpService;

impl Service<Request> for HttpIpService {
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        let peer_ip = req
            .extensions()
            .get_ref::<Forwarded>()
            .and_then(|f| f.client_ip())
            .or_else(|| {
                req.extensions()
                    .get_ref::<SocketInfo>()
                    .map(|s| s.peer_addr().ip_addr)
            });

        Ok(match peer_ip {
            Some(ip) => match HttpBodyContentFormat::derive_from_req(&req) {
                HttpBodyContentFormat::Txt => ip.to_string().into_response(),
                HttpBodyContentFormat::Html => render_html_page(ip).into_response(),
                HttpBodyContentFormat::Json => Json(serde_json::json!({
                    "ip": ip,
                }))
                .into_response(),
            },
            None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        })
    }
}

/// Sidecar stylesheet for the HTML page. Served as a separate route so
/// the defence-in-depth CSP can keep `style-src 'self'` (blocking
/// inline `<style>`) without breaking the page.
const IP_STYLE_CSS: &str = include_str!("ip.css");

/// Sidecar clipboard-copy script. Served separately for the same
/// reason as [`IP_STYLE_CSS`] (`script-src 'self'`).
const IP_SCRIPT_JS: &str = include_str!("ip.js");

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
            .0
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
    Input: Io + Unpin + ExtensionsRef,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, stream: Input) -> Result<Self::Output, Self::Error> {
        tracing::info!("connection received");
        let peer_ip = stream
            .extensions()
            .get_ref::<Forwarded>()
            .and_then(|f| f.client_ip())
            .or_else(|| {
                stream
                    .extensions()
                    .get_ref::<SocketInfo>()
                    .map(|s| s.peer_addr().ip_addr)
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
    ) -> Result<impl Service<TcpStream, Output = (), Error = Infallible>, BoxError> {
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
    fn build_tcp<S: Io + ExtensionsRef + Unpin + Sync>(
        self,
        #[cfg(any(feature = "rustls", feature = "boring"))] maybe_tls_accept_layer: Option<
            TlsAcceptorLayer,
        >,
    ) -> Result<impl Service<S, Output = (), Error = Infallible>, BoxError> {
        let tcp_forwarded_layer = match &self.forward {
            None => None,
            Some(ForwardKind::HaProxy) => Some(HaProxyLayer::default()),
            Some(other) => {
                return Err(OpaqueError::from_static_str(
                    "invalid forward kind for Transport mode",
                )
                .with_context_debug_field("kind", || other.clone()));
            }
        };

        let tcp_service_builder = (
            ConsumeErrLayer::trace_as(tracing::Level::DEBUG),
            LimitLayer::new(if self.concurrent_limit > 0 {
                Either::A(ConcurrentPolicy::max(self.concurrent_limit))
            } else {
                Either::B(UnlimitedPolicy::new())
            }),
            if !self.timeout.is_zero() {
                TimeoutLayer::new(self.timeout)
            } else {
                TimeoutLayer::never()
            },
            tcp_forwarded_layer,
            #[cfg(any(feature = "rustls", feature = "boring"))]
            maybe_tls_accept_layer,
        );

        Ok(tcp_service_builder.into_layer(TcpIpService))
    }

    fn build_http<S: Io + Unpin + Sync + ExtensionsRef>(
        self,
        executor: Executor,
        #[cfg(any(feature = "rustls", feature = "boring"))] maybe_tls_accept_layer: Option<
            TlsAcceptorLayer,
        >,
    ) -> Result<impl Service<S, Output = (), Error = Infallible>, BoxError> {
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
                StrictTransportSecurity::excluding_subdomains_for_max_seconds(31536000),
            )
        });

        let tcp_service_builder = (
            ConsumeErrLayer::trace_as(tracing::Level::DEBUG),
            (self.concurrent_limit > 0)
                .then(|| LimitLayer::new(ConcurrentPolicy::max(self.concurrent_limit))),
            (!self.timeout.is_zero()).then(|| TimeoutLayer::new(self.timeout)),
            tcp_forwarded_layer,
            // Limit the body size to 1MB for requests
            BodyLimitLayer::request_only(1024 * 1024),
            #[cfg(any(feature = "rustls", feature = "boring"))]
            maybe_tls_accept_layer,
        );

        // Defence-in-depth response headers for the HTML page (txt/json
        // responses also get them — they're benign there and means
        // any future widening of HTML emission is already covered).
        // The page loads `/style/ip.css` and `/script/ip.js` from the
        // same origin, no inline scripts/styles, no external requests:
        // the strict-self baseline (banner image whitelisted in the
        // shared helper) covers it.
        let (csp_layer, nosniff_layer, referrer_layer, frame_layer) =
            crate::cli::service::http_security::defence_in_depth_layer(
                crate::cli::service::http_security::rama_html_csp(),
            );

        // Route the IP echo + its asset sidecars through a Router so we
        // get clean method-aware matching (anything outside the three
        // known routes redirects to `/`).
        let router = crate::http::service::web::Router::new()
            .with_get("/", HttpIpService)
            .with_get("/style/ip.css", Css(IP_STYLE_CSS))
            .with_get("/script/ip.js", Script(IP_SCRIPT_JS))
            .with_not_found(async || Redirect::permanent("/"));

        let http_service = (
            TraceLayer::new_for_http(),
            SetResponseHeaderLayer::<XClacksOverhead>::if_not_present_default_typed(),
            AddRequiredResponseHeadersLayer::default(),
            csp_layer,
            nosniff_layer,
            referrer_layer,
            frame_layer,
            ConsumeErrLayer::default(),
            #[cfg(any(feature = "rustls", feature = "boring"))]
            hsts_layer,
            http_forwarded_layer,
        )
            .into_layer(router);

        // Wrap in `Arc` because `Router` is not `Clone` and
        // `HttpServer::service` requires a cloneable inner service so it
        // can hand a copy to each connection's task.
        let http_service = Arc::new(http_service);
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

fn render_html_page(ip: IpAddr) -> impl crate::http::protocols::html::IntoHtml + IntoResponse {
    use crate::http::protocols::html::*;
    html!(
        lang = "en",
        head!(
            meta!(charset = "utf-8"),
            meta!(
                name = "viewport",
                content = "width=device-width,initial-scale=1"
            ),
            link!(
                rel = "icon",
                href = PreEscaped(
                    "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>\
                     <text y='0.9em' font-size='90'>🦙</text></svg>"
                ),
            ),
            title!("Rama IP"),
            link!(
                rel = "stylesheet",
                r#type = "text/css",
                href = "/style/ip.css"
            ),
        ),
        body!(div!(
            class = "card",
            div!(
                class = "logo",
                div!("🦙"),
                div!(a!(href = "https://ramaproxy.org", "ラマ")),
            ),
            div!(
                class = "panel",
                role = "region",
                "aria-label" = "ip panel",
                div!(class = "muted", "Your public ip"),
                div!(id = "ip", class = "ip", code!(ip.to_string())),
                div!(
                    class = "controls",
                    button!(
                        id = "copyBtn",
                        class = "primary",
                        title = "Copy ip to clipboard",
                        "📋 Copy IP",
                    ),
                ),
            ),
            script!(src = "/script/ip.js"),
        )),
    )
}

#[cfg(test)]
mod render_html_page_tests {
    use super::*;
    use crate::http::protocols::html::IntoHtml as _;
    use std::net::Ipv4Addr;

    /// The IP value flows through `html!`'s escape pipeline, so even if a
    /// future `IpAddr::Display` impl produced HTML-special chars they would
    /// be neutralised. Verify the rendered page contains the expected IP
    /// inside `<code>…</code>` and that the page chrome is well-formed.
    #[test]
    fn render_html_page_embeds_ip_safely() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let out = render_html_page(ip).into_string();
        assert!(out.starts_with("<!DOCTYPE html><html lang=\"en\">"));
        assert!(out.contains("<title>Rama IP</title>"));
        assert!(out.contains(r#"<div id="ip" class="ip"><code>127.0.0.1</code></div>"#));
        // Copy button is wired by selector ID in the inline script.
        assert!(out.contains(r#"id="copyBtn""#));
    }

    /// The aria-label attribute uses the `"aria-label" = …` syntax (since
    /// `aria-label` is not a Rust ident). Pin the rendered output.
    #[test]
    fn render_html_page_emits_aria_label() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
        let out = render_html_page(ip).into_string();
        assert!(out.contains(r#"aria-label="ip panel""#));
    }

    /// Regression guard against the bug audited 2026-05-18: the IP page
    /// must reference its CSS and JS via `<link>` / `<script src>`
    /// because the surrounding service applies `style-src 'self'` and
    /// `script-src 'self'` — an inline `<style>` or `<script>` block
    /// would be blocked at the browser.
    #[test]
    fn render_html_page_uses_external_assets() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let out = render_html_page(ip).into_string();
        assert!(
            !out.contains("<style>") && !out.contains("<style "),
            "IP page must not embed inline <style>; CSP blocks it"
        );
        // The renderer is allowed to emit a self-closing `<script src=...>`,
        // but never an inline `<script>...JS...</script>` body.
        assert!(
            !out.contains("<script>"),
            "IP page must not embed inline <script>; CSP blocks it"
        );
        assert!(
            out.contains(r#"<link rel="stylesheet" type="text/css" href="/style/ip.css">"#),
            "IP page must link to /style/ip.css",
        );
        assert!(
            out.contains(r#"<script src="/script/ip.js">"#),
            "IP page must source /script/ip.js",
        );
    }
}
