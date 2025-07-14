use std::fmt;

use super::IntoResponse;
use crate::Body;
use crate::Response;
use crate::dep::http::StatusCode;
use crate::headers::ContentType;
use rama_core::error::OpaqueError;
use rama_core::telemetry::tracing;
use rama_utils::macros::impl_deref;
use serde::Serialize;

use super::Headers;

/// Wrapper used to create Form Http [`Response`]s,
/// as well as to extract Form from Http [`Request`] bodies.
///
/// [`Request`]: crate::Request
/// [`Response`]: crate::Response
///
/// # Examples
/// ## Creating a Form Response
///
/// ```
/// use serde::Serialize;
/// use rama_http::service::web::response::{
///     IntoResponse, Form,
/// };
///
/// #[derive(Serialize)]
/// struct Payload {
///     name: String,
///     age: i32,
///     is_student: bool
/// }
///
/// async fn handler() -> impl IntoResponse {
///     Form(Payload {
///         name: "john".to_string(),
///         age: 30,
///         is_student: false
///     })
/// }
/// ```
///
/// ## Extracting Form from a Request
///
/// ```
/// use rama_http::service::web::response::Form;
///
/// #[derive(Debug, serde::Deserialize)]
/// struct Input {
///     name: String,
///     age: u8,
///     alive: Option<bool>,
/// }
///
/// # fn bury(name: impl AsRef<str>) {}
///
/// async fn handler(Form(input): Form<Input>) {
///     if !input.alive.unwrap_or_default() {
///         bury(&input.name);
///     }
/// }
/// ```
pub struct Form<T>(pub T);

impl<T: fmt::Debug> fmt::Debug for Form<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Form").field(&self.0).finish()
    }
}

impl<T: Clone> Clone for Form<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl_deref!(Form);

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
        // Extracted into separate fn so it's only compiled once for all T.
        fn make_response(ser_result: Result<String, serde_html_form::ser::Error>) -> Response {
            match ser_result {
                Ok(body) => {
                    (Headers::single(ContentType::form_url_encoded()), body).into_response()
                }
                Err(err) => {
                    tracing::error!("response error: {err:?}");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            }
        }
        make_response(serde_html_form::to_string(&self.0))
    }
}

impl<T> TryFrom<Form<T>> for Body
where
    T: Serialize,
{
    type Error = OpaqueError;

    fn try_from(form: Form<T>) -> Result<Self, Self::Error> {
        match serde_html_form::to_string(&form.0) {
            Ok(body) => Ok(body.into()),
            Err(err) => Err(OpaqueError::from_std(err)),
        }
    }
}
