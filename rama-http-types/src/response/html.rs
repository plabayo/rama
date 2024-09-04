use crate::{header, Body, HeaderValue, IntoResponse, Response};
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
        (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static(mime::TEXT_HTML_UTF_8.as_ref()),
            )],
            self.0.into(),
        )
            .into_response()
    }
}

impl<T> From<T> for Html<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}
