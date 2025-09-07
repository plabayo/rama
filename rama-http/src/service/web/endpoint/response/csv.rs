use super::IntoResponse;
use crate::{Body, Response, dep::http::StatusCode};
use csv;
use rama_core::bytes::buf::Writer;
use rama_core::bytes::{BufMut, BytesMut};
use rama_core::error::OpaqueError;
use rama_http_headers::ContentType;
use rama_utils::macros::impl_deref;
use serde::Serialize;
use std::fmt;

use super::Headers;

/// Wrapper used to create Csv Http [`Response`]s,
/// as well as to extract Csv from Http [`Request`] bodies.
///
/// [`Request`]: crate::Request
/// [`Response`]: crate::Response
///
/// # Examples
///
/// ## Creating a Csv Response
///
/// ```
/// use serde_json::json;
/// use rama_http::service::web::response::{IntoResponse, Csv};
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
/// ## Extracting Csv from a Request
///
/// ```
/// use serde_json::json;
/// use rama_http::service::web::response::Csv;
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
        // Extracted into separate fn so it's only compiled once for all T.
        fn make_response(
            res: csv::Result<Vec<()>>,
            mut wtr: csv::Writer<Writer<BytesMut>>,
        ) -> Response {
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

            let bw = match wtr.into_inner() {
                Ok(bw) => bw,
                Err(err) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Headers::single(ContentType::text_utf8()),
                        err.to_string(),
                    )
                        .into_response();
                }
            };

            (
                Headers::single(ContentType::csv_utf8()),
                bw.into_inner().freeze(),
            )
                .into_response()
        }

        // Use a small initial capacity of 128 bytes like serde_json::to_vec
        // https://docs.rs/serde_json/1.0.82/src/serde_json/ser.rs.html#2189
        let buf = BytesMut::with_capacity(128).writer();

        let mut wtr = csv::Writer::from_writer(buf);
        let res: Result<Vec<_>, _> = self.0.into_iter().map(|rec| wtr.serialize(rec)).collect();

        make_response(res, wtr)
    }
}

impl<T> TryFrom<Csv<T>> for Body
where
    T: IntoIterator<Item: Serialize>,
{
    type Error = OpaqueError;

    fn try_from(csv: Csv<T>) -> Result<Self, Self::Error> {
        // Use a small initial capacity of 128 bytes like serde_json::to_vec
        // https://docs.rs/serde_json/1.0.82/src/serde_json/ser.rs.html#2189
        let mut buf = BytesMut::with_capacity(128).writer();
        {
            let mut wtr = csv::Writer::from_writer(&mut buf);
            let res: Result<Vec<_>, _> = csv.0.into_iter().map(|rec| wtr.serialize(rec)).collect();
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
