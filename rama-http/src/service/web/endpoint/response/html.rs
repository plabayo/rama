use super::{Headers, IntoResponse};
use crate::headers::ContentType;
use crate::{Body, Response};
use rama_utils::macros::impl_deref;

/// An HTML response.
///
/// Will automatically get `Content-Type: text/html`.
#[derive(Debug, Clone, Copy)]
pub struct Html<T>(pub T);

impl_deref!(Html);

impl<T> IntoResponse for Html<T>
where
    T: Into<Body>,
{
    fn into_response(self) -> Response {
        (Headers::single(ContentType::html_utf8()), self.0.into()).into_response()
    }
}

impl<T> From<T> for Html<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}
