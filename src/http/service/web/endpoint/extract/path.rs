use super::FromRequestParts;
use crate::http::dep::http::request::Parts;
use crate::http::matcher::{UriParams, UriParamsDeserializeError};
use crate::service::Context;
use serde::de::DeserializeOwned;
use std::ops::{Deref, DerefMut};

/// Extractor to get path parameters from the context in deserialized form.
pub struct Path<T>(pub T);

crate::__define_http_rejection! {
    #[status = INTERNAL_SERVER_ERROR]
    #[body = "No paths parameters found for matched route"]
    /// Rejection type used if rama's internal representation of path parameters is missing.
    pub struct MissingPathParams;
}

crate::__composite_http_rejection! {
    /// Rejection used for [`Path`].
    ///
    /// Contains one variant for each way the [`Path`](super::Path) extractor
    /// can fail.
    pub enum PathRejection {
        UriParamsDeserializeError,
        MissingPathParams,
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Path<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Path").field(&self.0).finish()
    }
}

impl<T: Clone> Clone for Path<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S, T> FromRequestParts<S> for Path<T>
where
    S: Send + Sync + 'static,
    T: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = PathRejection;

    async fn from_request_parts(ctx: &Context<S>, _parts: &Parts) -> Result<Self, Self::Rejection> {
        match ctx.get::<UriParams>() {
            Some(params) => {
                let params = params.deserialize::<T>()?;
                Ok(Path(params))
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

    use crate::http::service::web::WebService;
    use crate::http::{Body, Request, StatusCode};
    use crate::service::Service;

    #[tokio::test]
    async fn test_host_from_request() {
        #[derive(Debug, serde::Deserialize)]
        struct Params {
            foo: String,
            bar: u32,
        }

        let svc = WebService::default().get(
            "/a/:foo/:bar/b/*",
            |Path(params): Path<Params>| async move {
                assert_eq!(params.foo, "hello");
                assert_eq!(params.bar, 42);
                StatusCode::OK
            },
        );

        let builder = Request::builder()
            .method("GET")
            .uri("http://example.com/a/hello/42/b/extra");
        let req = builder.body(Body::empty()).unwrap();

        let resp = svc.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
