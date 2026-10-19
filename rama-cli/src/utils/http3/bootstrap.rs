//! A TCP door for HTTP/3-only origins: browsers start over TCP, so it hands out `Alt-Svc`
//! and reloads them onto QUIC; nothing else is served over TCP.

use std::convert::Infallible;

use rama::{
    Layer as _, Service,
    error::{BoxError, ErrorContext as _},
    http::{
        HeaderValue, Request, Response, StatusCode,
        header::{REFRESH, SET_COOKIE},
        headers::{AltSvc, CacheControl, Connection, Cookie, HeaderMapExt as _},
        protocols::html::*,
        server::HttpServer,
        service::web::response::IntoResponse,
    },
    layer::ConsumeErrLayer,
    net::{address::SocketAddress, tls::ApplicationProtocol},
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing,
    tls::{boring::server::TlsAcceptorLayer, server::TlsServerConfig},
};

const STYLE_CSS: &str = include_str!("bootstrap.css");

/// Marks a browser that was already sent back once, so a client that keeps
/// using TCP gets an explanation instead of an endless reload.
const COOKIE_NAME: &str = "rama-h3-bootstrap";
const COOKIE_SET: &str = "rama-h3-bootstrap=1; Max-Age=60; Path=/; Secure; HttpOnly; SameSite=Lax";
const COOKIE_CLEAR: &str = "rama-h3-bootstrap=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax";

/// Answers every TCP request by advertising `alt_svc` and asking the browser to come back.
#[derive(Debug, Clone)]
pub(crate) struct Http3Bootstrap {
    alt_svc: AltSvc,
}

impl Http3Bootstrap {
    pub(crate) fn new(alt_svc: AltSvc) -> Self {
        Self { alt_svc }
    }

    fn respond(&self, request: &Request) -> Response {
        let retried = request
            .headers()
            .typed_get::<Cookie>()
            .is_some_and(|cookie| cookie.get(COOKIE_NAME).is_some());
        let mut response = if retried {
            page(
                "This browser did not switch to HTTP/3",
                (
                    p!("This origin is served over HTTP/3 (QUIC) only, and your browser kept connecting over TCP."),
                    p!("Your network may block UDP, or the browser may have HTTP/3 disabled. Reload to try again."),
                ),
                false,
            )
            .into_response()
        } else {
            page(
                "Switching to HTTP/3…",
                p!("This origin is served over HTTP/3 (QUIC) only. Your browser is being sent back over HTTP/3."),
                true,
            )
            .into_response()
        };
        *response.status_mut() = StatusCode::OK;
        let headers = response.headers_mut();
        headers.typed_insert(self.alt_svc.clone());
        headers.typed_insert(CacheControl::new().with_no_store());
        // The reload must open a new connection, the first one Alt-Svc can apply to.
        headers.typed_insert(Connection::close());
        if retried {
            headers.insert(SET_COOKIE, HeaderValue::from_static(COOKIE_CLEAR));
        } else {
            headers.insert(REFRESH, HeaderValue::from_static("1"));
            headers.insert(SET_COOKIE, HeaderValue::from_static(COOKIE_SET));
        }
        response
    }
}

impl Service<Request> for Http3Bootstrap {
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, request: Request) -> Result<Self::Output, Self::Error> {
        Ok(self.respond(&request))
    }
}

fn page(
    heading: &'static str,
    notice: impl IntoHtml,
    refresh: bool,
) -> impl IntoHtml + IntoResponse {
    html!(
        lang = "en",
        head!(
            meta!(charset = "UTF-8"),
            meta!(
                name = "viewport",
                content = "width=device-width, initial-scale=1.0"
            ),
            refresh.then(|| meta!("http-equiv" = "refresh", content = "1")),
            meta!(name = "robots", content = "none"),
            title!("ラマ | HTTP/3"),
            style!(PreEscaped(STYLE_CSS)),
        ),
        body!(main!(
            h1!(a!(href = "/", "ラマ"), " | ", heading),
            div!(class = "notice", notice),
            p!(
                class = "small",
                "Served by ",
                a!(href = "https://ramaproxy.org", "rama"),
                "."
            ),
        )),
    )
}

/// Serve the bootstrap door on `addr` with `tls`, over HTTP/1.1 so the connection can close.
pub(crate) async fn serve(
    exec: Executor,
    addr: SocketAddress,
    tls: TlsServerConfig,
    alt_svc: AltSvc,
) -> Result<(), BoxError> {
    let listener = TcpListener::build(exec.clone())
        .bind_address(addr)
        .await
        .context("bind HTTP/3 bootstrap TCP listener")?;
    let bound = listener
        .local_addr()
        .context("HTTP/3 bootstrap listener address")?;
    tracing::info!(
        network.local.address = %bound.ip(),
        network.local.port = bound.port(),
        "HTTP/3 bootstrap listening",
    );
    let service = (
        ConsumeErrLayer::trace_as(tracing::Level::DEBUG),
        // Only HTTP/1.1 can close the connection the reload must not reuse.
        TlsAcceptorLayer::new(tls.with_alpn([ApplicationProtocol::HTTP_11].into_iter().collect())),
    )
        .into_layer(HttpServer::new_http1(exec.clone()).service(Http3Bootstrap::new(alt_svc)));
    exec.into_spawn_task(listener.serve(service));
    Ok(())
}

#[cfg(test)]
mod tests {
    use rama::http::{
        Body,
        header::{CONNECTION, COOKIE},
    };

    use super::*;

    fn bootstrap() -> Http3Bootstrap {
        Http3Bootstrap::new(super::super::alt_svc(443).unwrap())
    }

    #[test]
    fn a_first_visit_advertises_h3_and_reloads_on_a_new_connection() {
        let response = bootstrap().respond(&Request::new(Body::empty()));
        let headers = response.headers();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(headers.typed_get::<AltSvc>().is_some());
        assert_eq!(headers.get(REFRESH).unwrap(), "1");
        assert_eq!(headers.get(SET_COOKIE).unwrap(), COOKIE_SET);
        assert_eq!(headers.get(CONNECTION).unwrap(), "close");
    }

    #[test]
    fn a_browser_that_returns_over_tcp_gets_no_further_reload() {
        let mut request = Request::new(Body::empty());
        request.headers_mut().insert(
            COOKIE,
            HeaderValue::from_static("other=1; rama-h3-bootstrap=1"),
        );
        let response = bootstrap().respond(&request);
        let headers = response.headers();
        assert!(headers.get(REFRESH).is_none());
        assert_eq!(headers.get(SET_COOKIE).unwrap(), COOKIE_CLEAR);
        assert!(headers.typed_get::<AltSvc>().is_some());
    }
}
