use super::{Headers, IntoResponse};
use crate::headers::ContentType;
use crate::{Body, Response};
use rama_utils::macros::impl_deref;
use std::fmt;

/// An HTML response.
///
/// Will automatically get `Content-Type: text/css; charset=utf-8`.
pub struct Css<T>(pub T);

impl<T: fmt::Debug> fmt::Debug for Css<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Css").field(&self.0).finish()
    }
}

impl<T: Clone> Clone for Css<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Copy> Copy for Css<T> {}

impl_deref!(Css);

impl<T> IntoResponse for Css<T>
where
    T: Into<Body>,
{
    fn into_response(self) -> Response {
        (Headers::single(ContentType::css_utf8()), self.0.into()).into_response()
    }
}

impl<T> From<T> for Css<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}
