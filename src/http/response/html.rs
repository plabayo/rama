use crate::http::{header, Body, HeaderValue, IntoResponse, Response};

/// An HTML response.
///
/// Will automatically get `Content-Type: text/html`.
#[derive(Clone, Copy, Debug)]
#[must_use]
pub struct Html<T>(pub T);

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
