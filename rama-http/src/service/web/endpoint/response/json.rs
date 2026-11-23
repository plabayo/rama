use super::{IntoResponse, IntoResponseFailed};
use crate::headers::ContentType;
use crate::{Body, Response, StatusCode};
use rama_core::error::BoxError;
use rama_utils::macros::impl_deref;
use serde::Serialize;

use super::Headers;

/// Wrapper used to create Json Http [`Response`]s,
/// as well as to extract Json from Http [`Request`] bodies.
///
/// [`Request`]: crate::Request
/// [`Response`]: crate::Response
///
/// # Examples
///
/// ## Creating a Json Response
///
/// ```
/// use serde_json::json;
/// use rama_http::service::web::response::{IntoResponse, Json};
///
/// async fn handler() -> impl IntoResponse {
///     Json(json!({
///         "name": "john",
///         "age": 30,
///         "is_student": false
///     }))
/// }
/// ```
///
/// ## Extracting Json from a Request
///
/// ```
/// use serde_json::json;
/// use rama_http::service::web::response::Json;
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
/// async fn handler(Json(input): Json<Input>) {
///     if !input.alive.unwrap_or_default() {
///         bury(&input.name);
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Json<T>(pub T);

impl_deref!(Json);

impl<T> From<T> for Json<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}

impl<T> IntoResponse for Json<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        // Extracted into separate fn so it's only compiled once for all T.
        fn make_response(result: serde_json::Result<Vec<u8>>) -> Response {
            match result {
                Ok(buf) => (Headers::single(ContentType::json()), buf).into_response(),
                Err(err) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Headers::single(ContentType::text_utf8()),
                    IntoResponseFailed,
                    err.to_string(),
                )
                    .into_response(),
            }
        }
        make_response(serde_json::to_vec(&self.0))
    }
}

impl<T> TryFrom<Json<T>> for Body
where
    T: Serialize,
{
    type Error = BoxError;

    fn try_from(json: Json<T>) -> Result<Self, Self::Error> {
        Ok(serde_json::to_vec(&json.0)?.into())
    }
}
