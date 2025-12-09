use super::{Headers, IntoResponse};
use crate::headers::ContentType;
use crate::{Body, Response, StatusCode};
use rama_core::bytes::Bytes;
use rama_core::futures::TryStream;
use rama_core::stream::io::ReaderStream;
use rama_error::BoxError;
use rama_http_headers::{ContentDisposition, ContentLength, ContentRange, Error, HeaderMapExt};
use std::ops::RangeBounds;
use std::path::Path;
use tokio::fs::File;

/// An octet-stream response for serving arbitrary binary data.
///
/// Will automatically get `Content-Type: application/octet-stream`.
///
/// This is commonly used for:
/// - Serving unknown or arbitrary binary files
/// - Downloadable content that doesn't fit other MIME types
/// - Raw binary data streams
///
/// User Agents often treat it as if the `Content-Disposition` header was set to attachment,
/// and propose a "Save As" dialog.
///
/// # Examples
///
/// ## Basic binary response
///
/// ```
/// use rama_http::service::web::response::{IntoResponse, OctetStream};
/// use rama_core::stream::io::ReaderStream;
///
/// async fn handler() -> impl IntoResponse {
///     let data = b"Hello";
///     let cursor = std::io::Cursor::new(data);
///     let stream = ReaderStream::new(cursor);
///     OctetStream::new(stream)
/// }
/// ```
///
/// ## Download with filename and size
///
/// ```
/// use rama_http::service::web::response::{IntoResponse, OctetStream};
/// use rama_core::stream::io::ReaderStream;
///
/// async fn download() -> impl IntoResponse {
///     let data = b"file contents";
///     let size = data.len() as u64;
///     let cursor = std::io::Cursor::new(data);
///     let stream = ReaderStream::new(cursor);
///     OctetStream::new(stream)
///         .with_file_name("data.bin".to_owned())
///         .with_content_size(size)
/// }
/// ```
///
/// ## Partial content (range request)
///
/// ```
/// use rama_http::service::web::response::OctetStream;
/// use rama_core::stream::io::ReaderStream;
///
/// # fn example() -> Result<(), rama_http_headers::Error> {
/// // Serving first 5 bytes of "Hello, World!" (13 bytes total)
/// let partial_data = b"Hello";
/// let cursor = std::io::Cursor::new(partial_data);
/// let stream = ReaderStream::new(cursor);
/// let response = OctetStream::new(stream)
///     .with_content_size(13) // Total size of "Hello, World!"
///     .try_into_range_response(0..5)?; // Serving bytes 0-4
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct OctetStream<S> {
    stream: S,
    filename: Option<String>,
    content_size: Option<u64>,
}

impl<S> OctetStream<S> {
    /// Create a new `OctetStream` response.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            filename: None,
            content_size: None,
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

    rama_utils::macros::generate_set_and_with! {
        /// Set the content size for `Content-Length`- or as part of the `Content-Range` header.
        ///
        /// This indicates the total size of the resource in bytes. When set, it will
        /// be included as `Content-Length` header in normal responses, or used as the
        /// complete length in `Content-Range` header for partial content responses.
        pub fn content_size(mut self, content_size: u64) -> Self {
            self.content_size = Some(content_size);
            self
        }
    }

    /// Convert into a partial content (HTTP 206) range response.
    ///
    /// This method consumes the `OctetStream` and converts it into a Response
    /// with HTTP 206 status and appropriate `Content-Range` header.
    /// The `content_size` field must be set before calling this method to indicate
    /// the total size of the complete resource.
    ///
    /// # Arguments
    ///
    /// * `range` - The byte range being served (e.g., `0..500` for bytes 0-499)
    ///
    /// # Note
    ///
    /// It is the responsibility of the caller to ensure that the stream contains
    /// the correct data matching the specified range. This method does not validate
    /// the stream contents against the provided range by design, to avoid performance
    /// overhead of reading the entire stream.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Response)` with status 206 (Partial Content) if successful,
    /// or `Err(Error)` if the range is invalid or `content_size` is not set.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_http::service::web::response::OctetStream;
    /// use rama_core::stream::io::ReaderStream;
    ///
    /// # fn example() -> Result<(), rama_http_headers::Error> {
    /// // Serving first 5 bytes of "Hello, World!" (13 bytes total)
    /// let partial_data = b"Hello";
    /// let cursor = std::io::Cursor::new(partial_data);
    /// let stream = ReaderStream::new(cursor);
    ///
    /// let response = OctetStream::new(stream)
    ///     .with_content_size(13) // Total size of "Hello, World!"
    ///     .try_into_range_response(0..5)?; // Serving bytes 0-4
    /// # Ok(())
    /// # }
    /// ```
    pub fn try_into_range_response(self, range: impl RangeBounds<u64>) -> Result<Response, Error>
    where
        S: TryStream<Ok: Into<Bytes>, Error: Into<BoxError>> + Send + 'static,
    {
        let body = Body::from_stream(self.stream);
        let content_range =
            ContentRange::bytes(range, self.content_size).map_err(|_| Error::invalid())?;

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

    /// Helper function to open file and extract metadata.
    /// Returns (file, content_size, filename).
    async fn open_file_with_metadata(
        path: &Path,
    ) -> std::io::Result<(File, Option<u64>, Option<String>)> {
        let file = File::open(path).await?;

        let metadata = file.metadata().await.ok();
        let content_size = metadata.as_ref().map(|m| m.len());

        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|s| s.to_owned());

        Ok((file, content_size, filename))
    }

    /// Create an `OctetStream` from a file path.
    ///
    /// This constructor opens the file and automatically extracts metadata when available:
    /// - File size is set as `content_size` if the metadata can be read
    /// - Filename is extracted from the path if it can be converted to a valid UTF-8 string
    ///
    /// Both operations are graceful - if metadata cannot be read or the filename cannot
    /// be extracted, the corresponding field will be `None`.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file to serve
    ///
    /// # Returns
    ///
    /// Returns `Ok(OctetStream)` if the file can be opened, or `Err(io::Error)` if the
    /// file cannot be accessed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rama_http::service::web::response::OctetStream;
    /// use rama_core::stream::io::ReaderStream;
    /// use tokio::fs::File;
    ///
    /// # async fn example() -> std::io::Result<()> {
    /// // Opens file and automatically sets filename and content_size
    /// let response = OctetStream::<ReaderStream<File>>::try_from_path("/path/to/file.bin").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn try_from_path(
        path: impl AsRef<Path>,
    ) -> std::io::Result<OctetStream<ReaderStream<File>>> {
        let (file, content_size, filename) = Self::open_file_with_metadata(path.as_ref()).await?;
        let stream = ReaderStream::new(file);

        Ok(OctetStream {
            stream,
            filename,
            content_size,
        })
    }

    /// Create a range response directly from a file path.
    ///
    /// This is a convenience method that combines file opening, seeking to the range start,
    /// and creating a partial content (HTTP 206) response in one step. It automatically
    /// extracts the filename from the path and uses the file size as the complete length.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file to serve
    /// * `start` - Start byte position (inclusive)
    /// * `end` - End byte position (exclusive, following Rust range convention)
    ///
    /// # Returns
    ///
    /// Returns `Ok(Response)` with status 206 (Partial Content) if successful,
    /// or `Err(io::Error)` if the file cannot be accessed, or if the range is invalid.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rama_http::service::web::response::OctetStream;
    /// use rama_core::stream::io::ReaderStream;
    /// use tokio::fs::File;
    ///
    /// # async fn example() -> std::io::Result<()> {
    /// // Serve bytes 0-499 of a file
    /// let response = OctetStream::<ReaderStream<File>>::try_range_response_from_path("/path/to/file.bin", 0, 500).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn try_range_response_from_path(
        path: impl AsRef<Path>,
        start: u64,
        end: u64,
    ) -> std::io::Result<Response> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};

        let (mut file, content_size, filename) =
            Self::open_file_with_metadata(path.as_ref()).await?;

        // Take only the requested range
        file.seek(std::io::SeekFrom::Start(start)).await?;
        let stream = ReaderStream::new(file.take(end - start));

        let octet_stream = OctetStream {
            stream,
            filename,
            content_size,
        };

        octet_stream
            .try_into_range_response(start..end)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
    }
}

impl<S> IntoResponse for OctetStream<S>
where
    S: TryStream<Ok: Into<Bytes>, Error: Into<BoxError>> + Send + 'static,
{
    fn into_response(self) -> Response {
        let body = Body::from_stream(self.stream);
        let mut response = (Headers::single(ContentType::octet_stream()), body).into_response();

        // Add Content-Disposition if filename is provided
        if let Some(filename) = self.filename {
            response
                .headers_mut()
                .typed_insert(ContentDisposition::attachment(filename.as_str()));
        }

        // Add Content-Length if content_size is provided
        if let Some(size) = self.content_size {
            response.headers_mut().typed_insert(ContentLength(size));
        }

        response
    }
}

impl<S> From<S> for OctetStream<S> {
    fn from(stream: S) -> Self {
        Self::new(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_octet_stream() {
        let data = vec![1u8, 2, 3, 4, 5];
        let stream = OctetStream::new(data.clone());

        assert_eq!(stream.stream, data);
        assert_eq!(stream.filename, None);
        assert_eq!(stream.content_size, None);
    }

    #[test]
    fn test_with_file_name() {
        let data = vec![1u8, 2, 3];
        let stream = OctetStream::new(data).with_file_name("test.bin".to_owned());

        assert_eq!(stream.filename, Some("test.bin".to_owned()));
    }

    #[test]
    fn test_with_content_size() {
        let data = vec![1u8, 2, 3];
        let stream = OctetStream::new(data).with_content_size(1024);

        assert_eq!(stream.content_size, Some(1024));
    }

    #[test]
    fn test_chained_setters() {
        let data = vec![1u8, 2, 3];
        let stream = OctetStream::new(data)
            .with_file_name("test.bin".to_owned())
            .with_content_size(1024);

        assert_eq!(stream.filename, Some("test.bin".to_owned()));
        assert_eq!(stream.content_size, Some(1024));
    }

    #[tokio::test]
    async fn test_into_response() {
        use crate::header::{CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE};

        let cursor = std::io::Cursor::new(b"hello");
        let stream = ReaderStream::new(cursor);
        let octet_stream = OctetStream::new(stream)
            .with_file_name("test.bin".to_owned())
            .with_content_size(5);
        let response = octet_stream.into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );
        assert_eq!(response.headers().get(CONTENT_LENGTH).unwrap(), "5");
        assert_eq!(
            response.headers().get(CONTENT_DISPOSITION).unwrap(),
            "attachment; filename=test.bin"
        );
    }

    #[tokio::test]
    async fn test_try_into_range_response() {
        use crate::header::{CONTENT_DISPOSITION, CONTENT_RANGE, CONTENT_TYPE};

        let cursor = std::io::Cursor::new(b"hello");
        let stream = ReaderStream::new(cursor);
        let octet_stream = OctetStream::new(stream)
            .with_file_name("test.bin".to_owned())
            .with_content_size(13);
        let response = octet_stream.try_into_range_response(0..5).unwrap();

        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );
        assert_eq!(
            response.headers().get(CONTENT_RANGE).unwrap(),
            "bytes 0-4/13"
        );
        assert_eq!(
            response.headers().get(CONTENT_DISPOSITION).unwrap(),
            "attachment; filename=test.bin"
        );
    }

    #[tokio::test]
    async fn test_try_from_path() {
        let file_path = "../test-files/hello.txt";
        let stream = OctetStream::<ReaderStream<File>>::try_from_path(file_path)
            .await
            .unwrap();

        assert_eq!(stream.filename, Some("hello.txt".to_owned()));

        #[cfg(target_os = "windows")]
        assert_eq!(stream.content_size, Some(15)); // "Hello, World!\r\n" is 15 bytes
        #[cfg(not(target_os = "windows"))]
        assert_eq!(stream.content_size, Some(14)); // "Hello, World!\n" is 14 bytes
    }

    #[tokio::test]
    async fn test_try_range_response_from_path() {
        use crate::header::{CONTENT_DISPOSITION, CONTENT_RANGE};

        let file_path = "../test-files/hello.txt";
        let response =
            OctetStream::<ReaderStream<File>>::try_range_response_from_path(file_path, 0, 5)
                .await
                .unwrap();

        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);

        // Verify Content-Range header
        let value = response.headers().get(CONTENT_RANGE).unwrap();
        #[cfg(target_os = "windows")]
        assert_eq!(value, "bytes 0-4/15"); // "Hello, World!\r\n" is 15 bytes
        #[cfg(not(target_os = "windows"))]
        assert_eq!(value, "bytes 0-4/14"); // "Hello, World!\n" is 14 bytes

        // Verify Content-Disposition header with filename
        assert_eq!(
            response.headers().get(CONTENT_DISPOSITION).unwrap(),
            "attachment; filename=hello.txt"
        );
    }
}
