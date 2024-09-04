use super::FromRequestParts;
use crate::dep::http::request::Parts;
use crate::utils::macros::define_http_rejection;
use rama_core::Context;
use rama_net::address;
use rama_net::http::RequestContext;
use rama_utils::macros::impl_deref;

/// Extractor that resolves the authority of the request.
#[derive(Debug, Clone)]
pub struct Authority(pub address::Authority);

impl_deref!(Authority: address::Authority);

define_http_rejection! {
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
        Ok(Authority(match ctx.get::<RequestContext>() {
            Some(ctx) => ctx.authority.clone(),
            None => RequestContext::try_from((ctx, parts))
                .map_err(|_| MissingAuthority)?
                .authority
                .clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::dep::http_body_util::BodyExt as _;
    use crate::header::X_FORWARDED_HOST;
    use crate::layer::forwarded::GetForwardedHeadersService;
    use crate::service::web::WebService;
    use crate::StatusCode;
    use crate::{Body, HeaderName, Request};
    use rama_core::Service;

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
