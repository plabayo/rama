use super::FromPartsStateRefPair;
use crate::request::Parts;
use crate::service::web::extract::OptionalFromPartsStateRefPair;
use crate::utils::macros::define_http_rejection;
use rama_utils::macros::impl_deref;
use std::convert::Infallible;

#[derive(Debug, Clone)]
/// Extractor that extracts an extension from the request extensions
pub struct Extension<T>(pub T);

impl_deref!(Extension<T>: T);

define_http_rejection! {
    #[status = INTERNAL_SERVER_ERROR]
    #[body = "Internal server error"]
    /// Rejection type used in case the extension is missing
    pub struct MissingExtension;
}

impl<State, T> FromPartsStateRefPair<State> for Extension<T>
where
    State: Send + Sync,
    T: Send + Sync + Clone + std::fmt::Debug + 'static,
{
    type Rejection = MissingExtension;

    async fn from_parts_state_ref_pair(
        parts: &Parts,
        _state: &State,
    ) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<T>() {
            Some(ext) => Ok(Self(ext.clone())),
            None => Err(MissingExtension),
        }
    }
}
impl<State, T> OptionalFromPartsStateRefPair<State> for Extension<T>
where
    State: Send + Sync,
    T: Send + Sync + Clone + std::fmt::Debug + 'static,
{
    type Rejection = Infallible;

    async fn from_parts_state_ref_pair(
        parts: &Parts,
        _state: &State,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<T>().map(|ext| Self(ext.clone())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::web::IntoEndpointService;
    use rama_core::Service;
    use rama_http_types::{Body, Request, Response};
    use std::convert::Infallible;

    #[derive(Clone, Debug, Default)]
    struct TestExtension(String);

    #[tokio::test]
    async fn should_extract_extension() {
        async fn handler(Extension(ext): Extension<TestExtension>) -> Result<Response, Infallible> {
            assert_eq!(ext.0, "test");
            Ok(Response::new(Body::empty()))
        }

        handler
            .into_endpoint_service()
            .serve(
                Request::builder()
                    .extension(TestExtension("test".to_owned()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn should_extract_optional_extension() {
        async fn is_missing_handler(
            ext: Option<Extension<TestExtension>>,
        ) -> Result<Response, Infallible> {
            assert!(ext.is_none());
            Ok(Response::new(Body::empty()))
        }

        is_missing_handler
            .into_endpoint_service()
            .serve(Request::builder().body(Body::empty()).unwrap())
            .await
            .unwrap();

        async fn is_present_handler(
            ext: Option<Extension<TestExtension>>,
        ) -> Result<Response, Infallible> {
            assert_eq!(ext.unwrap().0.0, "test");
            Ok(Response::new(Body::empty()))
        }

        is_present_handler
            .into_endpoint_service()
            .serve(
                Request::builder()
                    .extension(TestExtension("test".to_owned()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    }
}
