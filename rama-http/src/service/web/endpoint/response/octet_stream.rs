use super::{Headers, IntoResponse};
use crate::headers::ContentType;
use crate::{Body, Response};
use rama_http_headers::ContentDisposition;
use std::fmt;

/// An octet-stream response for serving arbitrary binary data.
///
/// Will automatically get `Content-Type: application/octet-stream`.
///
/// This is commonly used for:
/// - Serving unknown or arbitrary binary files
/// - Downloadable content that doesn't fit other MIME types
/// - Raw binary data streams
///
/// # Examples
///
/// ## Basic binary response
///
/// ```
/// use rama_http::service::web::response::{IntoResponse, OctetStream};
///
/// async fn handler() -> impl IntoResponse {
///     let data = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F]; // "Hello"
///     OctetStream::new(data)
/// }
/// ```
///
/// ## Download with filename
///
/// ```
/// use rama_http::service::web::response::{IntoResponse, OctetStream};
///
/// async fn download() -> impl IntoResponse {
///     let data = b"file contents".to_vec();
///     OctetStream::attachment(data, "data.bin")
/// }
/// ```
///
/// ## Tuple struct syntax (simple use case)
///
/// ```
/// use rama_http::service::web::response::{IntoResponse, OctetStream};
///
/// async fn handler() -> impl IntoResponse {
///     let data = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F];
///     OctetStream(data)  // Equivalent to OctetStream::new(data)
/// }
/// ```
pub struct OctetStream<T> {
    data: T,
    filename: Option<String>,
}

impl<T> OctetStream<T> {
    /// Create a new `OctetStream` response.
    pub fn new(data: T) -> Self {
        Self {
            data,
            filename: None,
        }
    }

    /// Create a new `OctetStream` response with `Content-Disposition: attachment` header.
    ///
    /// This will trigger a file download in browsers with the specified filename.
    pub fn attachment(data: T, filename: impl Into<String>) -> Self {
        Self {
            data,
            filename: Some(filename.into()),
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for OctetStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OctetStream")
            .field("data", &self.data)
            .field("filename", &self.filename)
            .finish()
    }
}

impl<T: Clone> Clone for OctetStream<T> {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            filename: self.filename.clone(),
        }
    }
}

impl<T> IntoResponse for OctetStream<T>
where
    T: Into<Body>,
{
    fn into_response(self) -> Response {
        let body = self.data.into();

        if let Some(filename) = self.filename {
            // With Content-Disposition header
            (
                Headers((
                    ContentType::octet_stream(),
                    ContentDisposition::attachment(filename.as_str()),
                )),
                body,
            )
                .into_response()
        } else {
            // Simple case without Content-Disposition
            (Headers::single(ContentType::octet_stream()), body).into_response()
        }
    }
}

impl<T> From<T> for OctetStream<T> {
    fn from(data: T) -> Self {
        Self::new(data)
    }
}
