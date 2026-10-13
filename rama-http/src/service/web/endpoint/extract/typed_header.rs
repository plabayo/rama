//! module in function of [`TypedHeader`]

use super::IntoResponse;
use super::{FromPartsStateRefPair, OptionalFromPartsStateRefPair};
use crate::headers::{self, HeaderDecode};
use crate::request::Parts;
use crate::{HeaderName, Response};
use std::ops::Deref;

/// Extractor to get a TypedHeader from the request.
#[derive(Debug, Clone)]
pub struct TypedHeader<H>(pub H);

impl<H, State> FromPartsStateRefPair<State> for TypedHeader<H>
where
    H: HeaderDecode + Send + Sync + 'static,
    State: Send + Sync,
{
    type Rejection = TypedHeaderRejection;

    async fn from_parts_state_ref_pair(
        parts: &Parts,
        _state: &State,
    ) -> Result<Self, Self::Rejection> {
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

impl<H, State> OptionalFromPartsStateRefPair<State> for TypedHeader<H>
where
    H: HeaderDecode + Send + Sync + 'static,
    State: Send + Sync,
{
    type Rejection = TypedHeaderRejection;

    async fn from_parts_state_ref_pair(
        parts: &Parts,
        _state: &State,
    ) -> Result<Option<Self>, Self::Rejection> {
        let mut values = parts.headers.get_all(H::name()).iter();
        // A missing header is `None` even for headers that decode from zero values.
        if values.size_hint() == (0, Some(0)) {
            return Ok(None);
        }
        H::decode(&mut values)
            .map(|header| Some(Self(header)))
            .map_err(|err| TypedHeaderRejection {
                name: H::name(),
                reason: TypedHeaderRejectionReason::Error(err),
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
    #[must_use]
    pub fn name(&self) -> &HeaderName {
        self.name
    }

    /// Reason why the header extraction has failed
    #[must_use]
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
        (rama_http_types::StatusCode::BAD_REQUEST, self.to_string()).into_response()
    }
}

impl std::fmt::Display for TypedHeaderRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.reason {
            TypedHeaderRejectionReason::Missing => {
                write!(f, "Header of type `{}` was missing", self.name)
            }
            // The decode error is exposed via `source`; repeating it here duplicates reports.
            TypedHeaderRejectionReason::Error(_) => {
                write!(f, "Failed to parse header `{}`", self.name)
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
        Body, HeaderName, HeaderValue, Request, header,
        headers::{self, ContentType, HeaderDecode},
        request::Parts,
        service::web::extract::{
            FromPartsStateRefPair, TypedHeader, typed_header::TypedHeaderRejection,
        },
    };

    #[derive(Debug)]
    struct DecodesFromNothing;

    impl headers::TypedHeader for DecodesFromNothing {
        fn name() -> &'static HeaderName {
            &header::COOKIE
        }
    }

    impl HeaderDecode for DecodesFromNothing {
        fn decode<'i, I>(_values: &mut I) -> Result<Self, headers::Error>
        where
            I: Iterator<Item = &'i HeaderValue>,
        {
            Ok(Self)
        }
    }

    fn parts_with(headers: &[(&'static str, &'static str)]) -> Parts {
        let mut builder = Request::builder();
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(Body::empty()).unwrap().into_parts().0
    }

    async fn extract_optional<H>(
        parts: &Parts,
    ) -> Result<Option<TypedHeader<H>>, TypedHeaderRejection>
    where
        H: HeaderDecode + Send + Sync + 'static,
    {
        <Option<TypedHeader<H>> as FromPartsStateRefPair<()>>::from_parts_state_ref_pair(parts, &())
            .await
    }

    #[tokio::test]
    async fn optional_typed_header_is_none_when_missing() {
        let header = extract_optional::<DecodesFromNothing>(&parts_with(&[]))
            .await
            .unwrap();
        assert!(header.is_none());

        let header = extract_optional::<DecodesFromNothing>(&parts_with(&[("cookie", "a=1")]))
            .await
            .unwrap();
        assert!(header.is_some());
    }

    #[tokio::test]
    async fn invalid_typed_header_rejection_does_not_repeat_its_source() {
        let rejection =
            extract_optional::<ContentType>(&parts_with(&[("content-type", "not a mime type")]))
                .await
                .unwrap_err();

        assert!(!rejection.is_missing());
        assert_eq!(
            rejection.to_string(),
            "Failed to parse header `content-type`"
        );
        assert!(std::error::Error::source(&rejection).is_some());
    }

    #[tokio::test]
    async fn test_get_typed_header() {
        let req = Request::builder()
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();

        let (parts, _) = req.into_parts();

        let typed_header =
            match TypedHeader::<ContentType>::from_parts_state_ref_pair(&parts, &()).await {
                Ok(typed_header) => Some(typed_header),
                Err(_) => panic!("Expected Ok"),
            };

        assert_eq!(typed_header.unwrap().0, "application/json".parse().unwrap());
    }
}
