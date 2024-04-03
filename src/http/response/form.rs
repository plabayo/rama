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
/// ## Creating a Form Response
///
/// ```
/// use serde::Serialize;
/// use rama::http::{
///     IntoResponse,
///     response::Form
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
/// use rama::http::service::web::extract::{
///     Form
/// };
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
