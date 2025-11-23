use std::fmt;

use rama_error::{ErrorContext as _, OpaqueError};

use crate::{
    Method,
    header::{self, HeaderName, HeaderValue},
    request::Parts as RequestParts,
};

use super::{Any, WILDCARD, try_separated_by_commas};

/// Holds configuration for how to set the [`Access-Control-Allow-Methods`][mdn] header.
///
/// See [`CorsLayer::allow_methods`] for more details.
///
/// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods
/// [`CorsLayer::allow_methods`]: super::CorsLayer::allow_methods
#[derive(Clone, Default)]
#[must_use]
pub struct AllowMethods(AllowMethodsInner);

impl AllowMethods {
    /// Allow any method by sending a wildcard (`*`)
    ///
    /// See [`CorsLayer::allow_methods`] for more details.
    ///
    /// [`CorsLayer::allow_methods`]: super::CorsLayer::allow_methods
    pub fn any() -> Self {
        Self(AllowMethodsInner::Const(Some(WILDCARD)))
    }

    /// Set a single allowed method
    ///
    /// See [`CorsLayer::allow_methods`] for more details.
    ///
    /// [`CorsLayer::allow_methods`]: super::CorsLayer::allow_methods
    pub fn try_exact(method: &Method) -> Result<Self, OpaqueError> {
        Ok(Self(AllowMethodsInner::Const(Some(
            HeaderValue::from_str(method.as_str())
                .context("stringified method is not a valid header value")?,
        ))))
    }

    /// Set multiple allowed methods
    ///
    /// See [`CorsLayer::allow_methods`] for more details.
    ///
    /// [`CorsLayer::allow_methods`]: super::CorsLayer::allow_methods
    pub fn try_list<I>(methods: I) -> Result<Self, OpaqueError>
    where
        I: IntoIterator<Item = Method>,
    {
        Ok(Self(AllowMethodsInner::Const(try_separated_by_commas(
            methods.into_iter().map(|m| {
                HeaderValue::from_str(m.as_str())
                    .context("stringified method is not a valid header value")
            }),
        )?)))
    }

    /// Allow any method, by mirroring the preflight [`Access-Control-Request-Method`][mdn]
    /// header.
    ///
    /// See [`CorsLayer::allow_methods`] for more details.
    ///
    /// [`CorsLayer::allow_methods`]: super::CorsLayer::allow_methods
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Request-Method
    pub fn mirror_request() -> Self {
        Self(AllowMethodsInner::MirrorRequest)
    }

    #[allow(clippy::borrow_interior_mutable_const)]
    pub(super) fn is_wildcard(&self) -> bool {
        matches!(&self.0, AllowMethodsInner::Const(Some(v)) if v == WILDCARD)
    }

    pub(super) fn to_header(&self, parts: &RequestParts) -> Option<(HeaderName, HeaderValue)> {
        let allow_methods = match &self.0 {
            AllowMethodsInner::Const(v) => v.clone()?,
            AllowMethodsInner::MirrorRequest => parts
                .headers
                .get(header::ACCESS_CONTROL_REQUEST_METHOD)?
                .clone(),
        };

        Some((header::ACCESS_CONTROL_ALLOW_METHODS, allow_methods))
    }
}

impl fmt::Debug for AllowMethods {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            AllowMethodsInner::Const(inner) => f.debug_tuple("Const").field(inner).finish(),
            AllowMethodsInner::MirrorRequest => f.debug_tuple("MirrorRequest").finish(),
        }
    }
}

impl From<Any> for AllowMethods {
    #[inline(always)]
    fn from(_: Any) -> Self {
        Self::any()
    }
}

impl TryFrom<Method> for AllowMethods {
    type Error = OpaqueError;

    #[inline(always)]
    fn try_from(value: Method) -> Result<Self, Self::Error> {
        Self::try_exact(&value)
    }
}

impl TryFrom<&Method> for AllowMethods {
    type Error = OpaqueError;

    #[inline(always)]
    fn try_from(value: &Method) -> Result<Self, Self::Error> {
        Self::try_exact(value)
    }
}

impl<const N: usize> TryFrom<[Method; N]> for AllowMethods {
    type Error = OpaqueError;

    #[inline(always)]
    fn try_from(arr: [Method; N]) -> Result<Self, Self::Error> {
        Self::try_list(arr)
    }
}

impl TryFrom<Vec<Method>> for AllowMethods {
    type Error = OpaqueError;

    #[inline(always)]
    fn try_from(vec: Vec<Method>) -> Result<Self, Self::Error> {
        Self::try_list(vec)
    }
}

#[derive(Clone)]
enum AllowMethodsInner {
    Const(Option<HeaderValue>),
    MirrorRequest,
}

impl Default for AllowMethodsInner {
    fn default() -> Self {
        Self::Const(None)
    }
}
