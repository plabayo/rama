use super::{Headers, IntoResponse};
use crate::headers::ContentType;
use crate::{Body, Response};
use rama_utils::macros::impl_deref;
use std::fmt;

/// An HTML response.
///
/// Will automatically get `Content-Type: text/html`.
pub struct Html<T>(pub T);

impl<T: fmt::Debug> fmt::Debug for Html<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Html").field(&self.0).finish()
    }
}

impl<T: Clone> Clone for Html<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

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
