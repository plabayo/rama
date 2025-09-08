use super::IntoResponse;
use crate::headers::ContentType;
use crate::{Body, Response, StatusCode};
use rama_core::bytes::{BufMut, BytesMut};
use rama_core::error::OpaqueError;
use rama_utils::macros::impl_deref;
use serde::Serialize;
use std::fmt;

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
pub struct Json<T>(pub T);

impl<T: fmt::Debug> fmt::Debug for Json<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Json").field(&self.0).finish()
    }
}

impl<T: Clone> Clone for Json<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

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
        fn make_response(buf: BytesMut, ser_result: serde_json::Result<()>) -> Response {
            match ser_result {
                Ok(()) => (Headers::single(ContentType::json()), buf.freeze()).into_response(),
                Err(err) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Headers::single(ContentType::text_utf8()),
                    err.to_string(),
                )
                    .into_response(),
            }
        }
        // Use a small initial capacity of 128 bytes like serde_json::to_vec
        // https://docs.rs/serde_json/1.0.82/src/serde_json/ser.rs.html#2189
        let mut buf = BytesMut::with_capacity(128).writer();
        let res = serde_json::to_writer(&mut buf, &self.0);
        make_response(buf.into_inner(), res)
    }
}

impl<T> TryFrom<Json<T>> for Body
where
    T: Serialize,
{
    type Error = OpaqueError;

    fn try_from(json: Json<T>) -> Result<Self, Self::Error> {
        // Use a small initial capacity of 128 bytes like serde_json::to_vec
        // https://docs.rs/serde_json/1.0.82/src/serde_json/ser.rs.html#2189
        let mut buf = BytesMut::with_capacity(128).writer();
        match serde_json::to_writer(&mut buf, &json.0) {
            Ok(()) => Ok(buf.into_inner().freeze().into()),
            Err(err) => Err(OpaqueError::from_std(err)),
        }
    }
}
