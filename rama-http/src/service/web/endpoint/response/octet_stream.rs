use super::{Headers, IntoResponse};
use crate::headers::ContentType;
use crate::{Body, Response, StatusCode};
use rama_http_headers::{ContentDisposition, ContentRange, Error, HeaderMapExt};
use std::fmt;
use std::ops::RangeBounds;

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
///     let data = b"file contents";
///     OctetStream::new(data).with_file_name("data.bin".to_string())
/// }
/// ```
///
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

    rama_utils::macros::generate_set_and_with! {
        /// Set the filename for `Content-Disposition: attachment` header.
        ///
        /// This will trigger a file download in browsers with the specified filename.
        pub fn file_name(mut self, filename: String) -> Self {
            self.filename = Some(filename);
            self
        }
    }

    /// Convert into a partial content (HTTP 206) range response.
    ///
    /// This method consumes the `OctetStream` and converts it into a Response
    /// with the specified byte range, including appropriate `Content-Range` and
    /// `Accept-Ranges` headers. If a filename was set, the `Content-Disposition`
    /// header will also be included.
    ///
    /// # Arguments
    ///
    /// * `range` - The byte range to serve (e.g., `0..5` for bytes 0-4)
    /// * `complete_length` - The total length of the complete resource
    ///
    /// # Returns
    ///
    /// Returns `Ok(Response)` with status 206 (Partial Content) if the range is valid,
    /// or `Err(Error)` if the range is invalid or out of bounds.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_http::service::web::response::OctetStream;
    ///
    /// # fn example() -> Result<(), rama_http_headers::Error> {
    /// let data = b"Hello, World!".to_vec();
    /// let total_len = data.len() as u64;
    ///
    /// // Serve bytes 0-4 (inclusive) out of 13 total bytes
    /// let response = OctetStream::new(data)
    ///     .try_into_range_response(0..5, total_len)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn try_into_range_response(
        self,
        range: impl RangeBounds<u64>,
        complete_length: u64,
    ) -> Result<Response, Error>
    where
        T: Into<Body>,
    {
        let content_range =
            ContentRange::bytes(range, complete_length).map_err(|_| Error::invalid())?;

        let body = self.data.into();

        let mut response = (
            StatusCode::PARTIAL_CONTENT,
            Headers((ContentType::octet_stream(), content_range)),
            body,
        )
            .into_response();

        // Add Content-Disposition if filename is provided
        if let Some(filename) = self.filename {
            response
                .headers_mut()
                .typed_insert(ContentDisposition::attachment(filename.as_str()));
        }

        Ok(response)
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
