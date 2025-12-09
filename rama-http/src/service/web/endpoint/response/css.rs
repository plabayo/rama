use super::{Headers, IntoResponse};
use crate::headers::ContentType;
use crate::{Body, Response};
use rama_utils::macros::impl_deref;

/// An HTML response.
///
/// Will automatically get `Content-Type: text/css; charset=utf-8`.
#[derive(Debug, Clone, Copy)]
pub struct Css<T>(pub T);

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
