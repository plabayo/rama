use std::ops::Deref;

use super::FromRequestParts;
use crate::http::{dep::http::request::Parts, headers::extract::extract_host_from_headers};
use crate::service::Context;

/// Extractor that resolves the hostname of the request.
///
/// Hostname is resolved through the following, in order:
/// - `Forwarded` header
/// - `X-Forwarded-Host` header
/// - `Host` header
/// - request target / URI
///
/// Note that user agents can set `X-Forwarded-Host` and `Host` headers to arbitrary values so make
/// sure to validate them to avoid security issues.
#[derive(Debug, Clone)]
pub struct Host(pub String);

crate::__define_http_rejection! {
    #[status = BAD_REQUEST]
    #[body = "Failed to detect the Http host"]
    /// Rejection type used if the [`Host`] extractor is unable to
    /// determine the (http) Host.
    pub struct MissingHost;
}

impl<S> FromRequestParts<S> for Host
where
    S: Send + Sync + 'static,
{
    type Rejection = MissingHost;

    async fn from_request_parts(_ctx: &Context<S>, parts: &Parts) -> Result<Self, Self::Rejection> {
        if let Some(host) = extract_host_from_headers(&parts.headers) {
            return Ok(Host(host));
        }

        if let Some(host) = parts.uri.host() {
            return Ok(Host(host.to_owned()));
        }

        Err(MissingHost)
    }
}

impl Deref for Host {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::http::dep::http_body_util::BodyExt as _;
    use crate::http::header::X_FORWARDED_HOST;
    use crate::http::service::web::WebService;
    use crate::http::StatusCode;
    use crate::http::{Body, HeaderName, Request};
    use crate::service::Service;

    async fn test_host_from_request(host: &str, headers: Vec<(&HeaderName, &str)>) {
        let svc = WebService::default().get("/", |Host(host): Host| async move { host });

        let mut builder = Request::builder().method("GET").uri("http://example.com/");
        for (header, value) in headers {
            builder = builder.header(header, value);
        }
        let req = builder.body(Body::empty()).unwrap();

        let res = svc.serve(Context::default(), req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, host);
    }

    #[tokio::test]
    async fn host_header() {
        test_host_from_request(
            "some-domain:123",
            vec![(&http::header::HOST, "some-domain:123")],
        )
        .await;
    }

    #[tokio::test]
    async fn x_forwarded_host_header() {
        test_host_from_request(
            "some-domain:456",
            vec![(&X_FORWARDED_HOST, "some-domain:456")],
        )
        .await;
    }

    #[tokio::test]
    async fn x_forwarded_host_precedence_over_host_header() {
        test_host_from_request(
            "some-domain:456",
            vec![
                (&X_FORWARDED_HOST, "some-domain:456"),
                (&http::header::HOST, "some-domain:123"),
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn uri_host() {
        test_host_from_request("example.com", vec![]).await;
    }
}
