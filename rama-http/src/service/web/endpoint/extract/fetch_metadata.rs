//! Extract the [Fetch Metadata] request headers (and `Sec-Purpose`) as
//! `Option<FetchMetadata>`.
//!
//! The extractor is optional only: a request without fetch metadata (a
//! non-browser client) is a normal request, not a rejection.
//!
//! [Fetch Metadata]: https://w3c.github.io/webappsec-fetch-metadata/

use std::convert::Infallible;

use super::OptionalFromPartsStateRefPair;
use crate::headers::FetchMetadata;
use crate::request::Parts;

impl<State> OptionalFromPartsStateRefPair<State> for FetchMetadata
where
    State: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_parts_state_ref_pair(
        parts: &Parts,
        _state: &State,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(Self::from_headers(&parts.headers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::StatusCode;
    use crate::header::{
        SEC_FETCH_DEST, SEC_FETCH_MODE, SEC_FETCH_SITE, SEC_FETCH_USER, SEC_PURPOSE,
    };
    use crate::headers::{SecFetchDest, SecFetchMode, SecFetchSite};
    use crate::service::web::WebService;
    use crate::service::web::endpoint::extract::test_support::serve_get;

    async fn describe(metadata: Option<FetchMetadata>) -> String {
        match metadata {
            None => "none".to_owned(),
            Some(FetchMetadata {
                site,
                mode,
                dest,
                user,
                purpose,
            }) => format!(
                "{} {} {} {user} {}",
                site.as_ref().map_or("-", SecFetchSite::as_str),
                mode.as_ref().map_or("-", SecFetchMode::as_str),
                dest.as_ref().map_or("-", SecFetchDest::as_str),
                purpose.map_or_else(|| "-".to_owned(), |purpose| purpose.to_string()),
            ),
        }
    }

    #[tokio::test]
    async fn extracts_navigation() {
        let svc = WebService::default().with_get("/", describe);
        let (status, body) = serve_get(
            &svc,
            "/",
            &[
                (&SEC_FETCH_SITE, "none"),
                (&SEC_FETCH_MODE, "navigate"),
                (&SEC_FETCH_DEST, "document"),
                (&SEC_FETCH_USER, "?1"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "none navigate document true -");
    }

    #[tokio::test]
    async fn extracts_partial_set() {
        let svc = WebService::default().with_get("/", describe);
        let (status, body) = serve_get(&svc, "/", &[(&SEC_FETCH_SITE, "cross-site")]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "cross-site - - false -");
    }

    #[tokio::test]
    async fn extracts_speculative_navigation() {
        let svc = WebService::default().with_get("/", describe);
        let (status, body) = serve_get(
            &svc,
            "/",
            &[
                (&SEC_FETCH_SITE, "same-origin"),
                (&SEC_FETCH_MODE, "navigate"),
                (&SEC_FETCH_DEST, "document"),
                (&SEC_PURPOSE, "prefetch;prerender"),
            ],
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body,
            "same-origin navigate document false prefetch;prerender"
        );
    }

    #[tokio::test]
    async fn missing_metadata_is_none() {
        let svc = WebService::default().with_get("/", describe);
        assert_eq!(
            serve_get(&svc, "/", &[]).await,
            (StatusCode::OK, "none".into())
        );
        // Invalid values carry no metadata either.
        assert_eq!(
            serve_get(&svc, "/", &[(&SEC_FETCH_USER, "?0")]).await,
            (StatusCode::OK, "none".into())
        );
    }
}
