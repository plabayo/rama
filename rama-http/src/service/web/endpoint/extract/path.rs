//! Module in function of the [`Path`] extractor.

use super::FromPartsStateRefPair;
use crate::matcher::{UriParams, UriParamsDeserializeError};
use crate::request::Parts;
use crate::utils::macros::{composite_http_rejection, define_http_rejection};
use serde::de::DeserializeOwned;
use std::ops::{Deref, DerefMut};

/// Extractor to get path parameters from the context in deserialized form.
#[derive(Debug, Clone)]
pub struct Path<T>(pub T);

define_http_rejection! {
    #[status = INTERNAL_SERVER_ERROR]
    #[body = "No paths parameters found for matched route"]
    /// Rejection type used if rama's internal representation of path parameters is missing.
    pub struct MissingPathParams;
}

composite_http_rejection! {
    /// Rejection used for [`Path`].
    ///
    /// Contains one variant for each way the [`Path`](super::Path) extractor
    /// can fail.
    pub enum PathRejection {
        UriParamsDeserializeError,
        MissingPathParams,
    }
}

impl<T, State> FromPartsStateRefPair<State> for Path<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
    State: Send + Sync,
{
    type Rejection = PathRejection;

    async fn from_parts_state_ref_pair(
        parts: &Parts,
        _state: &State,
    ) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<UriParams>() {
            Some(params) => {
                let params = params.deserialize::<T>()?;
                Ok(Self(params))
            }
            None => Err(MissingPathParams.into()),
        }
    }
}

impl<T> Deref for Path<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Path<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::service::web::WebService;
    use crate::{Body, Request, StatusCode};
    use rama_core::Service;

    #[tokio::test]
    async fn test_host_from_request() {
        #[derive(Debug, serde::Deserialize)]
        struct Params {
            foo: String,
            bar: u32,
        }

        let svc = WebService::default().with_get(
            "/a/{foo}/{bar}/b/*",
            async |Path(params): Path<Params>| {
                assert_eq!(params.foo, "hello");
                assert_eq!(params.bar, 42);
                StatusCode::OK
            },
        );

        let builder = Request::builder()
            .method("GET")
            .uri("http://example.com/a/hello/42/b/extra");
        let req = builder.body(Body::empty()).unwrap();

        let resp = svc.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
