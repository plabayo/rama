use super::FromRequestParts;
use crate::http::dep::http::request::Parts;
use crate::http::headers::{self, Header};
use crate::http::{HeaderName, IntoResponse, Response};
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
    type Rejection = TypedHeaderRejection;

    async fn from_request_parts(_ctx: &Context<S>, parts: &Parts) -> Result<Self, Self::Rejection> {
        let mut values = parts.headers.get_all(H::name()).iter();
        let is_missing = values.size_hint() == (0, Some(0));
        H::decode(&mut values)
            .map(Self)
            .map_err(|err| TypedHeaderRejection {
                name: H::name(),
                reason: if is_missing {
                    // Report a more precise rejection for the missing header case.
                    TypedHeaderRejectionReason::Missing
                } else {
                    TypedHeaderRejectionReason::Error(err)
                },
            })
    }
}

impl<H> Deref for TypedHeader<H> {
    type Target = H;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Rejection used for [`TypedHeader`].
#[derive(Debug)]
pub struct TypedHeaderRejection {
    name: &'static HeaderName,
    reason: TypedHeaderRejectionReason,
}

impl TypedHeaderRejection {
    /// Name of the header that caused the rejection
    pub fn name(&self) -> &HeaderName {
        self.name
    }

    /// Reason why the header extraction has failed
    pub fn reason(&self) -> &TypedHeaderRejectionReason {
        &self.reason
    }

    /// Returns `true` if the typed header rejection reason is [`Missing`].
    ///
    /// [`Missing`]: TypedHeaderRejectionReason::Missing
    #[must_use]
    pub fn is_missing(&self) -> bool {
        self.reason.is_missing()
    }
}

/// Additional information regarding a [`TypedHeaderRejection`]
#[derive(Debug)]
#[non_exhaustive]
pub enum TypedHeaderRejectionReason {
    /// The header was missing from the HTTP request
    Missing,
    /// An error occurred when parsing the header from the HTTP request
    Error(headers::Error),
}

impl TypedHeaderRejectionReason {
    /// Returns `true` if the typed header rejection reason is [`Missing`].
    ///
    /// [`Missing`]: TypedHeaderRejectionReason::Missing
    #[must_use]
    pub fn is_missing(&self) -> bool {
        matches!(self, Self::Missing)
    }
}

impl IntoResponse for TypedHeaderRejection {
    fn into_response(self) -> Response {
        (http::StatusCode::BAD_REQUEST, self.to_string()).into_response()
    }
}

impl std::fmt::Display for TypedHeaderRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.reason {
            TypedHeaderRejectionReason::Missing => {
                write!(f, "Header of type `{}` was missing", self.name)
            }
            TypedHeaderRejectionReason::Error(err) => {
                write!(f, "{} ({})", err, self.name)
            }
        }
    }
}

impl std::error::Error for TypedHeaderRejection {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.reason {
            TypedHeaderRejectionReason::Error(err) => Some(err),
            TypedHeaderRejectionReason::Missing => None,
        }
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
