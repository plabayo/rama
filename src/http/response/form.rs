use crate::http::dep::http::header::CONTENT_TYPE;
use crate::http::dep::http::StatusCode;
use crate::http::response::{IntoResponse, Response};
use serde::Serialize;

/// Wrapper used to create Form Http [`Response`]s,
/// as well as to extract Form from Http [`Request`] bodies.
///
/// [`Request`]: crate::http::Request
/// [`Response`]: crate::http::Response
///
/// # Examples
///
/// ```

#[derive(Debug, Clone, Copy, Default)]
#[must_use]
pub struct Form<T>(pub T);

__impl_deref!(Form);

impl<T> From<T> for Form<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> IntoResponse for Form<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        match serde_urlencoded::to_string(&self.0) {
            Ok(body) => (
                [(CONTENT_TYPE, mime::APPLICATION_WWW_FORM_URLENCODED.as_ref())],
                body,
            )
                .into_response(),
            Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
        }
    }
}
