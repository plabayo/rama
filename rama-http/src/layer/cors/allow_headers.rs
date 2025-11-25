use std::{convert::Infallible, fmt};

use rama_error::OpaqueError;

use crate::{
    header::{self, HeaderName, HeaderValue},
    request::Parts as RequestParts,
};

use super::{Any, WILDCARD, try_separated_by_commas};

/// Holds configuration for how to set the [`Access-Control-Allow-Headers`][mdn] header.
///
/// See [`CorsLayer::allow_headers`] for more details.
///
/// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers
/// [`CorsLayer::allow_headers`]: super::CorsLayer::allow_headers
#[derive(Clone, Default)]
#[must_use]
pub struct AllowHeaders(AllowHeadersInner);

impl AllowHeaders {
    /// Allow any headers by sending a wildcard (`*`)
    ///
    /// See [`CorsLayer::allow_headers`] for more details.
    ///
    /// [`CorsLayer::allow_headers`]: super::CorsLayer::allow_headers
    pub fn any() -> Self {
        Self(AllowHeadersInner::Const(Some(WILDCARD)))
    }

    /// Set multiple allowed headers
    ///
    /// See [`CorsLayer::allow_headers`] for more details.
    ///
    /// [`CorsLayer::allow_headers`]: super::CorsLayer::allow_headers
    pub fn try_list<I>(headers: I) -> Result<Self, OpaqueError>
    where
        I: IntoIterator<Item = HeaderName>,
    {
        Ok(Self(AllowHeadersInner::Const(try_separated_by_commas(
            headers.into_iter().map(|v| Ok::<_, Infallible>(v.into())),
        )?)))
    }

    /// Allow any headers, by mirroring the preflight [`Access-Control-Request-Headers`][mdn]
    /// header.
    ///
    /// See [`CorsLayer::allow_headers`] for more details.
    ///
    /// [`CorsLayer::allow_headers`]: super::CorsLayer::allow_headers
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Request-Headers
    pub fn mirror_request() -> Self {
        Self(AllowHeadersInner::MirrorRequest)
    }

    #[allow(clippy::borrow_interior_mutable_const)]
    pub(super) fn is_wildcard(&self) -> bool {
        matches!(&self.0, AllowHeadersInner::Const(Some(v)) if v == WILDCARD)
    }

    pub(super) fn to_header(&self, parts: &RequestParts) -> Option<(HeaderName, HeaderValue)> {
        let allow_headers = match &self.0 {
            AllowHeadersInner::Const(v) => v.clone()?,
            AllowHeadersInner::MirrorRequest => parts
                .headers
                .get(header::ACCESS_CONTROL_REQUEST_HEADERS)?
                .clone(),
        };

        Some((header::ACCESS_CONTROL_ALLOW_HEADERS, allow_headers))
    }
}

impl fmt::Debug for AllowHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            AllowHeadersInner::Const(inner) => f.debug_tuple("Const").field(inner).finish(),
            AllowHeadersInner::MirrorRequest => f.debug_tuple("MirrorRequest").finish(),
        }
    }
}

impl From<Any> for AllowHeaders {
    fn from(_: Any) -> Self {
        Self::any()
    }
}

impl<const N: usize> TryFrom<[HeaderName; N]> for AllowHeaders {
    type Error = OpaqueError;

    #[inline(always)]
    fn try_from(arr: [HeaderName; N]) -> Result<Self, Self::Error> {
        Self::try_list(arr)
    }
}

impl TryFrom<Vec<HeaderName>> for AllowHeaders {
    type Error = OpaqueError;

    #[inline(always)]
    fn try_from(vec: Vec<HeaderName>) -> Result<Self, Self::Error> {
        Self::try_list(vec)
    }
}

#[derive(Clone)]
enum AllowHeadersInner {
    Const(Option<HeaderValue>),
    MirrorRequest,
}

impl Default for AllowHeadersInner {
    fn default() -> Self {
        Self::Const(None)
    }
}
