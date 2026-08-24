//! Built-in certificate-install portal for devices using the MITM proxy.

use rama::{
    Layer, Service,
    bytes::Bytes,
    error::{BoxError, ErrorContext as _},
    http::{
        Body, Response, StatusCode,
        protocols::html::*,
        service::web::{
            Router,
            response::{Css, Html, IntoResponse},
        },
    },
    service::BoxService,
    telemetry::tracing,
    tls::boring::core::{sha::sha256, x509::X509},
};
use std::{convert::Infallible, fmt::Write as _, sync::Arc};

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
    let fingerprint = ca_sha256_fingerprint(&ca_pem).unwrap_or_else(|error| {
        tracing::error!(%error, "failed to compute MITM CA certificate fingerprint");
        "unavailable — do not trust this certificate".to_owned()
    });
    let ca_pem = Bytes::from(ca_pem);
    let pem_download = ca_pem.clone();
    let router = Router::new()
        .with_get("/", Html(render_index(&fingerprint).into_string()))
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

/// Return the SHA-256 fingerprint of the X.509 DER encoded by `ca_pem`.
///
/// This is shared by the install portal and the trusted-terminal message so
/// both surfaces present the exact same value.
pub(super) fn ca_sha256_fingerprint(ca_pem: &[u8]) -> Result<String, BoxError> {
    let certificate = X509::from_pem(ca_pem).context("parse MITM CA certificate PEM")?;
    let der = certificate
        .to_der()
        .context("encode MITM CA certificate as DER")?;
    let digest = sha256(&der);
    let mut fingerprint = String::with_capacity(digest.len() * 3 - 1);
    for (index, byte) in digest.iter().enumerate() {
        if index != 0 {
            fingerprint.push(':');
        }
        write!(&mut fingerprint, "{byte:02X}").context("format MITM CA fingerprint")?;
    }
    Ok(fingerprint)
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

fn render_index(fingerprint: &str) -> impl IntoHtml {
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
                    strong!("CA certificate SHA-256 fingerprint"),
                    br!(),
                    code!(fingerprint)
                ),
                p!(
                    class = "note",
                    "Before trusting the certificate, compare this fingerprint exactly with the SHA-256 CA fingerprint printed in the trusted terminal where you started the proxy. Do not install it if they differ."
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

    const TEST_CA_PEM: &[u8] = include_bytes!("../../../../../examples/assets/example.com.crt");
    const TEST_CA_SHA256: &str = "81:F7:86:9E:57:6C:0D:2F:56:60:2A:7E:A8:F2:51:0A:99:A1:39:21:E1:32:12:77:F3:77:30:CF:96:AA:AD:F3";

    #[test]
    fn ca_fingerprint_hashes_the_certificate_der() {
        assert_eq!(ca_sha256_fingerprint(TEST_CA_PEM).unwrap(), TEST_CA_SHA256);
        ca_sha256_fingerprint(b"not a PEM certificate").unwrap_err();
    }

    #[tokio::test]
    async fn portal_serves_install_page_and_certificate() {
        let service = service(TEST_CA_PEM.to_vec());
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
        assert!(page.contains("CA certificate SHA-256 fingerprint"));
        assert!(page.contains(TEST_CA_SHA256));
        assert!(page.contains("trusted terminal"));

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
            TEST_CA_PEM
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
