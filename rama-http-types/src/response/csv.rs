use crate::response::{IntoResponse, Response};
use crate::{dep::http::StatusCode, Body};
use bytes::{BufMut, BytesMut};
use csv;
use headers::ContentType;
use http::header::CONTENT_TYPE;
use http::HeaderValue;
use rama_error::OpaqueError;
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
/// use rama_http_types::{IntoResponse, response::Csv};
///
/// async fn handler() -> impl IntoResponse {
///     Csv(
///         vec![
///             json!({
///                 "name": "john",
///                 "age": 30,
///                 "is_student": false
///             })
///         ]
///     )
/// }
/// ```
///
/// ## Extracting Json from a Request
///
/// ```
/// use serde_json::json;
/// use rama_http_types::response::Csv;
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
/// async fn handler(Csv(input): Csv<Vec<Input>>) {
///     if !input[0].alive.unwrap_or_default() {
///         bury(&input[0].name);
///     }
/// }
/// ```
pub struct Csv<T>(pub T);

impl<T: fmt::Debug> fmt::Debug for Csv<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Csv").field(&self.0).finish()
    }
}

impl<T: Clone> Clone for Csv<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl_deref!(Csv);

impl<T> From<T> for Csv<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}

impl<T> IntoResponse for Csv<T>
where
    T: IntoIterator<Item: Serialize> + std::fmt::Debug,
{
    fn into_response(self) -> Response {
        // Use a small initial capacity of 128 bytes like serde_json::to_vec
        // https://docs.rs/serde_json/1.0.82/src/serde_json/ser.rs.html#2189
        let mut buf = BytesMut::with_capacity(128).writer();
        {
            let mut wtr = csv::Writer::from_writer(&mut buf);
            let res: Result<Vec<_>, _> = self.0.into_iter().map(|rec| wtr.serialize(rec)).collect();
            if let Err(err) = res {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Headers::single(ContentType::text_utf8()),
                    err.to_string(),
                )
                    .into_response();
            }
            if let Err(err) = wtr.flush() {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Headers::single(ContentType::text_utf8()),
                    err.to_string(),
                )
                    .into_response();
            }
        }

        (
            [(
                CONTENT_TYPE,
                HeaderValue::from_str(&mime::TEXT_CSV.to_string()).unwrap(),
            )],
            buf.into_inner().freeze(),
        )
            .into_response()
    }
}

impl<T> TryInto<Body> for Csv<T>
where
    T: IntoIterator<Item: Serialize>,
{
    type Error = OpaqueError;

    fn try_into(self) -> Result<Body, Self::Error> {
        // Use a small initial capacity of 128 bytes like serde_json::to_vec
        // https://docs.rs/serde_json/1.0.82/src/serde_json/ser.rs.html#2189
        let mut buf = BytesMut::with_capacity(128).writer();
        {
            let mut wtr = csv::Writer::from_writer(&mut buf);
            let res: Result<Vec<_>, _> = self.0.into_iter().map(|rec| wtr.serialize(rec)).collect();
            if let Err(err) = res {
                return Err(OpaqueError::from_std(err));
            }
            if let Err(err) = wtr.flush() {
                return Err(OpaqueError::from_std(err));
            }
        }

        Ok(buf.into_inner().freeze().into())
    }
}
