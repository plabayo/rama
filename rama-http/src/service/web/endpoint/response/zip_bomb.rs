use crate::service::web::response::IntoResponse;
use rama_core::futures::{Stream, StreamExt};
use rama_core::{bytes::Bytes, telemetry::tracing};
use rama_error::{ErrorContext, OpaqueError};
use rama_http_types::{Body, HeaderValue, StatusCode};
use rama_utils::macros::generate_set_and_with;
use std::{
    borrow::Cow,
    fmt,
    io::{self, Cursor, Read, Write},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, BufReader};
use tokio_util::io::ReaderStream;

#[derive(Debug, Clone)]
/// A minimal in-memory ZIP archive that acts as
/// a decompression or resource exhaustion trap.
///
/// `ZipBomb` produces a small, valid ZIP archive that declares
/// an extremely large uncompressed file,
/// with no actual payload. When extracted, it causes naive clients or
/// bots to attempt writing or allocating gigabytes of disk or memory,
/// despite its tiny compressed size.
///
/// This is useful for:
/// - Honeypots
/// - Anti-bot traps
/// - Defensive deception systems
pub struct ZipBomb {
    filename: Cow<'static, str>,

    depth: usize,
    fanout: usize,
    file_size: usize,
}

impl Default for ZipBomb {
    #[inline]
    fn default() -> Self {
        Self::new_static("token_backup")
    }
}

impl ZipBomb {
    const DEFAULT_DEPTH: usize = 6;
    const DEFAULT_FANOUT: usize = 16;
    const DEFAULT_FILE_SIZE: usize = 4 * 1024 * 1024 * 1024;

    #[must_use]
    /// Create a new [`ZipBomb`].
    pub fn new(filename: String) -> Self {
        Self {
            filename: Cow::Owned(filename),

            depth: Self::DEFAULT_DEPTH,
            fanout: Self::DEFAULT_FANOUT,
            file_size: Self::DEFAULT_FILE_SIZE,
        }
    }

    #[must_use]
    /// Create a new [`ZipBomb`] with a _static_ filename.
    pub const fn new_static(filename: &'static str) -> Self {
        Self {
            filename: Cow::Borrowed(filename),

            depth: Self::DEFAULT_DEPTH,
            fanout: Self::DEFAULT_FANOUT,
            file_size: Self::DEFAULT_FILE_SIZE,
        }
    }

    generate_set_and_with! {
        /// Overwrite the default depth of the bomb.
        ///
        /// Default is used in case the value given is 0.
        pub fn depth(mut self, depth: usize) -> Self {
            self.depth = if depth > 0 { depth } else { Self::DEFAULT_DEPTH};
            self
        }
    }

    generate_set_and_with! {
        /// Overwrite the default fanout of the bomb.
        ///
        /// Default is used in case the value given is 0.
        pub fn fanout(mut self, fanout: usize) -> Self {
            self.fanout = if fanout > 0 { fanout } else { Self::DEFAULT_FANOUT};
            self
        }
    }

    generate_set_and_with! {
        /// Overwrite the default file size of the leaf files of the bomb.
        ///
        /// Default is used in case the value given is 0.
        pub fn file_size(mut self, file_size: usize) -> Self {
            self.file_size = if file_size > 0 { file_size } else { Self::DEFAULT_FILE_SIZE};
            self
        }
    }

    /// Turn the [`ZipBomb`] into a body
    pub fn into_body(self) -> Body {
        let stream = RecursiveZipBomb::new(&self.filename, self.depth, self.fanout, self.file_size);
        Body::from_stream(stream)
    }
}

impl IntoResponse for ZipBomb {
    fn into_response(self) -> rama_http_types::Response {
        (
            [
                ("Robots", HeaderValue::from_static("none")),
                (
                    "X-Robots-Tag",
                    HeaderValue::from_static("noindex, nofollow"),
                ),
                ("Content-Type", HeaderValue::from_static("application/zip")),
                (
                    "Content-Disposition",
                    match format!("attachment; filename={}.zip", self.filename).parse() {
                        Ok(v) => v,
                        Err(err) => {
                            tracing::debug!(
                                "failed to format ZipBomb's Content-Disposition header: {err}"
                            );
                            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                        }
                    },
                ),
            ],
            self.into_body(),
        )
            .into_response()
    }
}

struct RecursiveZipBomb {
    depth: usize,
    fanout: usize,
    file_size: usize,
    base: Vec<u8>,
    emitted: bool,
    stream: Option<ReaderStream<BufReader<Box<dyn AsyncRead + Unpin + Send>>>>,
}

impl fmt::Debug for RecursiveZipBomb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecursiveZipBomb")
            .field("depth", &self.depth)
            .field("fanout", &self.fanout)
            .field("file_size", &self.file_size)
            .finish()
    }
}

impl RecursiveZipBomb {
    fn new(filename: &str, depth: usize, fanout: usize, file_size: usize) -> Self {
        let base = generate_recursive_base_zip(filename, depth, fanout, file_size);
        Self {
            depth,
            fanout,
            file_size,
            base,
            emitted: false,
            stream: None,
        }
    }
}

fn write_nested_zip(
    index: usize,
    filename: &str,
    zip: &mut rawzip::ZipArchiveWriter<&mut Cursor<Vec<u8>>>,
    data: &[u8],
) -> Result<(), OpaqueError> {
    let mut file = zip
        .new_file(&format!("{filename}_batch_{index}.zip"))
        .compression_method(rawzip::CompressionMethod::Deflate)
        .create()
        .context("create fanout zip batch")?;

    let encoder = flate2::write::DeflateEncoder::new(&mut file, flate2::Compression::default());
    let mut writer = rawzip::ZipDataWriter::new(encoder);
    writer
        .write_all(data)
        .context("compress and write data into archive")?;
    let (_, descriptor) = writer.finish().context("finalize data descriptor")?;
    let _ = file.finish(descriptor).context("write descriptor")?;
    Ok(())
}

fn write_fake_binary_data(
    filename: &str,
    zip: &mut rawzip::ZipArchiveWriter<&mut Cursor<Vec<u8>>>,
    file_size: usize,
) -> Result<(), OpaqueError> {
    let mut file = zip
        .new_file(&format!("{filename}.enc.bin"))
        .compression_method(rawzip::CompressionMethod::Deflate)
        .create()
        .context("create fanout zip batch")?;

    let encoder = flate2::write::DeflateEncoder::new(&mut file, flate2::Compression::default());
    let mut writer = rawzip::ZipDataWriter::new(encoder);

    let mut zero_reader = ZeroReader(file_size);
    io::copy(&mut zero_reader, &mut writer).context("write fake zero data")?;

    let (_, descriptor) = writer.finish().context("finalize data descriptor")?;
    let _ = file.finish(descriptor).context("write descriptor")?;
    Ok(())
}

fn generate_recursive_base_zip(
    filename: &str,
    depth: usize,
    fanout: usize,
    file_size: usize,
) -> Vec<u8> {
    let mut buffer = Cursor::new(Vec::new());
    let mut zip = rawzip::ZipArchiveWriter::new(&mut buffer);

    if depth == 0 {
        if let Err(err) = write_fake_binary_data(filename, &mut zip, file_size) {
            tracing::debug!(
                "failed to create 0-byte enc bin (leaf node is corrupted, but returned): {err}"
            );
            return buffer.into_inner();
        }
    } else {
        let nested = generate_recursive_base_zip(filename, depth - 1, fanout, file_size);
        for i in 0..fanout {
            if let Err(err) = write_nested_zip(i, filename, &mut zip, &nested) {
                tracing::debug!(
                    "failed to create fanout zip batch (nested zip is corrupted, but returned): {err}"
                );
                return buffer.into_inner();
            }
        }
    }

    if let Err(err) = zip.finish() {
        tracing::debug!("failed to finish archive (output is corrupted, but returned): {err}");
    }
    buffer.into_inner()
}

struct ZeroReader(usize);

impl Read for ZeroReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.0 == 0 {
            return Ok(0);
        }
        let len = buf.len().min(self.0);
        for byte in &mut buf[..len] {
            *byte = 0;
        }
        self.0 -= len;
        Ok(len)
    }
}

impl Stream for RecursiveZipBomb {
    type Item = Result<Bytes, std::convert::Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.emitted {
            return Poll::Ready(None);
        }

        match self.stream.as_mut() {
            None => {
                let reader: Box<dyn AsyncRead + Unpin + Send> =
                    Box::new(Cursor::new(self.base.clone()));
                self.stream = Some(ReaderStream::new(BufReader::new(reader)));
                self.poll_next(cx)
            }
            Some(stream) => match stream.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Some(Ok(chunk))),
                Poll::Ready(Some(Err(err))) => {
                    self.emitted = true;
                    tracing::debug!("stream error: {err}");
                    Poll::Ready(Some(Ok(Bytes::from_static(b"<stream error>"))))
                }
                Poll::Ready(None) => {
                    self.emitted = true;
                    Poll::Ready(None)
                }
                Poll::Pending => Poll::Pending,
            },
        }
    }
}
