//! Built-in certificate-install portal for devices using the MITM proxy.

use rama::{
    Layer, Service,
    bytes::Bytes,
    http::{
        Body, Response, StatusCode,
        protocols::html::*,
        service::web::{
            Router,
            response::{Css, Html, IntoResponse},
        },
    },
    service::BoxService,
};
use std::{convert::Infallible, sync::Arc};

const RAMA_LOGO_SVG: &str = include_str!("../../../../../docs/img/rama_logo.svg");
const STYLE_CSS: &str = include_str!("portal.css");

#[derive(Clone)]
pub(super) struct PortalService {
    inner: BoxService<rama::http::Request, Response, Infallible>,
}

impl std::fmt::Debug for PortalService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalService").finish_non_exhaustive()
    }
}

impl Service<rama::http::Request> for PortalService {
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, request: rama::http::Request) -> Result<Response, Infallible> {
        self.inner.serve(request).await
    }
}

pub(super) fn service(ca_pem: Vec<u8>) -> PortalService {
    let ca_pem = Bytes::from(ca_pem);
    let pem_download = ca_pem.clone();
    let router = Router::new()
        .with_get("/", Html(render_index().into_string()))
        .with_get("/ca.pem", move || {
            std::future::ready(certificate_download(pem_download.clone()))
        })
        .with_get("/rama-proxy-ca.crt", move || {
            std::future::ready(certificate_download(ca_pem.clone()))
        })
        .with_get("/assets/style.css", Css(STYLE_CSS))
        .with_get("/assets/rama-logo.svg", logo);
    let router = rama::http::layer::error_handling::ErrorHandler::new(router);
    let csp = rama::cli::service::http_security::rama_html_csp();
    let inner =
        rama::cli::service::http_security::defence_in_depth_layer(csp).into_layer(Arc::new(router));
    PortalService {
        inner: BoxService::new(inner),
    }
}

fn certificate_download(ca_pem: Bytes) -> Response {
    Response::builder()
        .header("content-type", "application/x-x509-ca-cert")
        .header(
            "content-disposition",
            "attachment; filename=\"rama-proxy-ca.crt\"",
        )
        .header("cache-control", "no-store")
        .body(Body::from(ca_pem))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn logo() -> Response {
    Response::builder()
        .header("content-type", "image/svg+xml")
        .header("cache-control", "public, max-age=86400")
        .body(Body::from(RAMA_LOGO_SVG))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn render_index() -> impl IntoHtml {
    html!(
        lang = "en",
        head!(
            meta!(charset = "utf-8"),
            meta!(
                name = "viewport",
                content = "width=device-width,initial-scale=1"
            ),
            title!("Rama Proxy Inspector"),
            link!(
                rel = "icon",
                r#type = "image/svg+xml",
                href = "/assets/rama-logo.svg"
            ),
            link!(rel = "stylesheet", href = "/assets/style.css"),
        ),
        body!(main!(
            class = "portal",
            img!(
                class = "mark",
                src = "/assets/rama-logo.svg",
                alt = "Rama noodle logo"
            ),
            div!(
                class = "copy",
                p!(class = "eyebrow", "Rama CLI"),
                h1!("Rama Proxy Inspector"),
                p!(
                    class = "lead",
                    "This connection is intercepted by the Rama CLI Proxy Inspector."
                ),
                p!(
                    "Install and trust this session’s certificate authority on this device to inspect HTTPS traffic without certificate warnings."
                ),
                a!(
                    class = "install",
                    href = "/rama-proxy-ca.crt",
                    download = "rama-proxy-ca.crt",
                    "Install certificate"
                ),
                p!(
                    class = "note",
                    "The certificate is ephemeral and only valid while this proxy process is running."
                )
            )
        ))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::http::{Request, body::util::BodyExt as _};

    #[tokio::test]
    async fn portal_serves_install_page_and_certificate() {
        let service = service(b"test-ca".to_vec());
        assert_eq!(format!("{service:?}"), "PortalService { .. }");
        let page = service
            .serve(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(page.status(), StatusCode::OK);
        assert!(page.headers().contains_key("content-security-policy"));
        let page = page.into_body().collect().await.unwrap().to_bytes();
        let page = String::from_utf8(page.to_vec()).unwrap();
        assert!(page.contains("Rama Proxy Inspector"));
        assert!(page.contains("/rama-proxy-ca.crt"));

        let certificate = service
            .serve(
                Request::get("/rama-proxy-ca.crt")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            certificate.headers()["content-type"],
            "application/x-x509-ca-cert"
        );
        assert_eq!(
            certificate.into_body().collect().await.unwrap().to_bytes(),
            "test-ca"
        );

        let logo = service
            .serve(
                Request::get("/assets/rama-logo.svg")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logo.headers()["content-type"], "image/svg+xml");
        let logo = logo.into_body().collect().await.unwrap().to_bytes();
        assert!(logo.windows(b"<svg".len()).any(|window| window == b"<svg"));
    }
}
