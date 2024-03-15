use headers::Header;
use http::StatusCode;

use super::FromRequestParts;
use crate::http::dep::http::request::Parts;
use crate::http::headers::HeaderMapExt;
use crate::service::Context;
use std::ops::Deref;

/// Extractor to get a TypedHeader from the request.
pub struct TypedHeader<H>(pub H);

impl<H: std::fmt::Debug> std::fmt::Debug for TypedHeader<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("TypedHeader").field(&self.0).finish()
    }
}

impl<H: Clone> Clone for TypedHeader<H> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S, H> FromRequestParts<S> for TypedHeader<H>
where
    S: Send + Sync + 'static,
    H: Header + Send + Sync + 'static,
{
    type Rejection = StatusCode;

    async fn from_request_parts(_ctx: &Context<S>, parts: &Parts) -> Result<Self, Self::Rejection> {
        parts
            .headers
            .typed_get()
            .map_or_else(|| Err(StatusCode::BAD_REQUEST), |value| Ok(Self(value)))
    }
}

impl<H> Deref for TypedHeader<H> {
    type Target = H;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        http::{
            service::web::extract::{FromRequestParts, TypedHeader},
            Body, Request,
        },
        service::Context,
    };
    use headers::ContentType;

    #[tokio::test]
    async fn test_get_typed_header() {
        let req = Request::builder()
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();

        let (parts, _) = req.into_parts();

        let ctx = Context::default();

        let typed_header = match TypedHeader::<ContentType>::from_request_parts(&ctx, &parts).await
        {
            Ok(typed_header) => Some(typed_header),
            Err(_) => panic!("Expected Ok"),
        };

        assert_eq!(typed_header.unwrap().0, "application/json".parse().unwrap());
    }
}
