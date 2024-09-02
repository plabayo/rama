use crate::response::{IntoResponse, Response};
use crate::{
    dep::http::{
        header::{self, HeaderValue},
        StatusCode,
    },
    Body,
};
use bytes::{BufMut, BytesMut};
use rama_error::OpaqueError;
use rama_macros::impl_deref;
use serde::Serialize;
use std::fmt;

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
/// use rama::http::{
///     IntoResponse,
///     // re-exported also as rama::http::service::web::extract::Json
///     response::Json,
/// };
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
/// use rama::http::service::web::extract::{
///     // re-exported from rama::http::response::Json
///     Json,
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
        // Use a small initial capacity of 128 bytes like serde_json::to_vec
        // https://docs.rs/serde_json/1.0.82/src/serde_json/ser.rs.html#2189
        let mut buf = BytesMut::with_capacity(128).writer();
        match serde_json::to_writer(&mut buf, &self.0) {
            Ok(()) => (
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static(mime::APPLICATION_JSON.as_ref()),
                )],
                buf.into_inner().freeze(),
            )
                .into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static(mime::TEXT_PLAIN_UTF_8.as_ref()),
                )],
                err.to_string(),
            )
                .into_response(),
        }
    }
}

impl<T> TryInto<Body> for Json<T>
where
    T: Serialize,
{
    type Error = OpaqueError;

    fn try_into(self) -> Result<Body, Self::Error> {
        // Use a small initial capacity of 128 bytes like serde_json::to_vec
        // https://docs.rs/serde_json/1.0.82/src/serde_json/ser.rs.html#2189
        let mut buf = BytesMut::with_capacity(128).writer();
        match serde_json::to_writer(&mut buf, &self.0) {
            Ok(()) => Ok(buf.into_inner().freeze().into()),
            Err(err) => Err(OpaqueError::from_std(err)),
        }
    }
}
