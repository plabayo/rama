use super::FromRequestParts;
use crate::http::dep::http::request::Parts;
use crate::http::RequestContext;
use crate::net::address;
use crate::service::Context;

/// Extractor that resolves the authority of the request.
///
/// Host, part authority, is resolved through the following, in order:
/// - `Forwarded` header
/// - `X-Forwarded-Host` header
/// - `Host` header
/// - request target / URI
///
/// TODO: update the above once we have forwarded better implemented!
///
/// Note that user agents can set `X-Forwarded-Host` and `Host` headers to arbitrary values so make
/// sure to validate them to avoid security issues.
#[derive(Debug, Clone)]
pub struct Authority(pub address::Authority);

impl_deref!(Authority: address::Authority);

crate::__define_http_rejection! {
    #[status = BAD_REQUEST]
    #[body = "Failed to detect the Http Authority"]
    /// Rejection type used if the [`Authority`] extractor is unable to
    /// determine the (http) Authority.
    pub struct MissingAuthority;
}

impl<S> FromRequestParts<S> for Authority
where
    S: Send + Sync + 'static,
{
    type Rejection = MissingAuthority;

    async fn from_request_parts(ctx: &Context<S>, parts: &Parts) -> Result<Self, Self::Rejection> {
        Ok(Authority(
            ctx.get::<RequestContext>()
                .map(|ctx| ctx.authority.clone())
                .unwrap_or_else(|| RequestContext::from((ctx, parts)).authority.clone())
                .ok_or(MissingAuthority)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::http::dep::http_body_util::BodyExt as _;
    use crate::http::header::X_FORWARDED_HOST;
    use crate::http::layer::forwarded::GetForwardedHeadersService;
    use crate::http::service::web::WebService;
    use crate::http::StatusCode;
    use crate::http::{Body, HeaderName, Request};
    use crate::service::Service;

    async fn test_authority_from_request(authority: &str, headers: Vec<(&HeaderName, &str)>) {
        let svc = GetForwardedHeadersService::x_forwarded_host(
            WebService::default().get("/", |Authority(authority): Authority| async move {
                authority.to_string()
            }),
        );

        let mut builder = Request::builder().method("GET").uri("http://example.com/");
        for (header, value) in headers {
            builder = builder.header(header, value);
        }
        let req = builder.body(Body::empty()).unwrap();

        let res = svc.serve(Context::default(), req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, authority);
    }

    #[tokio::test]
    async fn host_header() {
        test_authority_from_request(
            "some-domain:123",
            vec![(&http::header::HOST, "some-domain:123")],
        )
        .await;
    }

    #[tokio::test]
    async fn x_forwarded_host_header() {
        test_authority_from_request(
            "some-domain:456",
            vec![(&X_FORWARDED_HOST, "some-domain:456")],
        )
        .await;
    }

    #[tokio::test]
    async fn x_forwarded_host_precedence_over_host_header() {
        test_authority_from_request(
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
        test_authority_from_request("example.com:80", vec![]).await;
    }
}
