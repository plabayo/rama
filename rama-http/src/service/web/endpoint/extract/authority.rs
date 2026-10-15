//! Module in function of the [`Authority`] extractor.

use super::{FromPartsStateRefPair, OptionalFromPartsStateRefPair};
use crate::utils::macros::define_http_rejection;
use rama_http_types::request::Parts;
use rama_net::address;
use rama_net::input_ext::AuthorityInputExt;
use rama_utils::macros::impl_deref;

/// Extractor that resolves the authority of the request.
#[derive(Debug, Clone)]
pub struct Authority(pub address::HostWithOptPort);

impl_deref!(Authority: address::HostWithOptPort);

define_http_rejection! {
    #[status = BAD_REQUEST]
    #[body = "Failed to detect the Http Authority"]
    /// Rejection type used if the [`Authority`] extractor is unable to
    /// determine the (http) Authority.
    pub struct MissingAuthority;
}

impl<State> FromPartsStateRefPair<State> for Authority
where
    State: Send + Sync,
{
    type Rejection = MissingAuthority;

    async fn from_parts_state_ref_pair(
        parts: &Parts,
        _state: &State,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.authority().ok_or(MissingAuthority)?))
    }
}

impl<State> OptionalFromPartsStateRefPair<State> for Authority
where
    State: Send + Sync,
{
    type Rejection = MissingAuthority;

    async fn from_parts_state_ref_pair(
        parts: &Parts,
        _state: &State,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.authority().map(Self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::header::X_FORWARDED_HOST;
    use crate::layer::forwarded::GetForwardedHeaderService;
    use crate::service::web::WebService;
    use crate::service::web::endpoint::extract::test_support::serve_get;
    use crate::{HeaderName, StatusCode};

    async fn extract_required(Authority(authority): Authority) -> String {
        authority.to_string()
    }

    async fn extract_optional(authority: Option<Authority>) -> String {
        authority.map_or_else(
            || "none".to_owned(),
            |Authority(authority)| authority.to_string(),
        )
    }

    async fn test_authority_from_request(
        uri: &str,
        authority: &str,
        headers: Vec<(&HeaderName, &str)>,
    ) {
        let required = GetForwardedHeaderService::x_forwarded_host(
            WebService::default().with_get("/", extract_required),
        );
        let optional = GetForwardedHeaderService::x_forwarded_host(
            WebService::default().with_get("/", extract_optional),
        );

        for (status, body) in [
            serve_get(&required, uri, &headers).await,
            serve_get(&optional, uri, &headers).await,
        ] {
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, authority);
        }
    }

    #[tokio::test]
    async fn host_header() {
        test_authority_from_request(
            "/",
            "some-domain:123",
            vec![(&rama_http_types::header::HOST, "some-domain:123")],
        )
        .await;
    }

    #[tokio::test]
    async fn x_forwarded_host_header() {
        test_authority_from_request(
            "/",
            "some-domain:456",
            vec![(&X_FORWARDED_HOST, "some-domain:456")],
        )
        .await;
    }

    #[tokio::test]
    async fn x_forwarded_host_precedence_over_host_header() {
        test_authority_from_request(
            "/",
            "some-domain:456",
            vec![
                (&X_FORWARDED_HOST, "some-domain:456"),
                (&rama_http_types::header::HOST, "some-domain:123"),
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn uri_host() {
        test_authority_from_request("http://example.com", "example.com", vec![]).await;
    }

    #[tokio::test]
    async fn missing_authority() {
        let required = WebService::default().with_get("/", extract_required);
        let optional = WebService::default().with_get("/", extract_optional);

        assert_eq!(
            serve_get(&required, "/", &[]).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            serve_get(&optional, "/", &[]).await,
            (StatusCode::OK, "none".into())
        );
    }
}
