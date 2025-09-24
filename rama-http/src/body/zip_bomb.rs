use crate::service::web::response::IntoResponse;
use flate2::write::DeflateEncoder;
use rama_core::stream::io::{ReaderStream, SyncIoBridge};
use rama_core::telemetry::tracing;
use rama_core::{bytes::Bytes, futures::Stream};
use rama_error::{ErrorContext, OpaqueError};
use rama_http_types::{Body, HeaderValue, Response};
use rama_utils::macros::generate_set_and_with;
use rawzip::{CompressionMethod, ZipArchiveWriter};
use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{
    borrow::Cow,
    io::{self, Cursor, Read, Write},
};
use tokio::io::{BufReader, duplex};

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
    const DEFAULT_DEPTH: usize = 8;
    const DEFAULT_FANOUT: usize = 32;
    const DEFAULT_FILE_SIZE: usize = 512 * 1024 * 1024;

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

    /// Try to generate a [`ZipBomb`] as a [`Body`]
    pub fn generate_body(&self) -> Body {
        let Self {
            filename,
            depth,
            fanout,
            file_size,
        } = self.clone();

        let stream = RecursiveZipBomb::new(filename.clone(), depth, fanout, file_size);
        Body::from_stream(stream)
    }

    fn generate_response_headers(&self) -> [(&'static str, HeaderValue); 4] {
        [
            ("Robots", HeaderValue::from_static("none")),
            (
                "X-Robots-Tag",
                HeaderValue::from_static("noindex, nofollow"),
            ),
            ("Content-Type", HeaderValue::from_static("application/zip")),
            (
                "Content-Disposition",
                format!("attachment; filename={}.zip", self.filename)
                    .parse()
                    .unwrap_or_else(|err| {
                        tracing::debug!("failed to format ZipBomb's Content-Disposition header: fall back to default: {err}");
                        HeaderValue::from_static("attachment; filename=data.zip")
                    }),
            ),
        ]
    }

    /// Generate a [`Response`] from the [`ZipBomb`].
    #[must_use]
    pub fn generate_response(&self) -> Response {
        let headers = self.generate_response_headers();
        let body = self.generate_body();
        (headers, body).into_response()
    }

    /// Turn the [`ZipBomb`] into a [`Body`]
    pub fn into_generate_body(self) -> Body {
        let Self {
            filename,
            depth,
            fanout,
            file_size,
        } = self;

        let stream = RecursiveZipBomb::new(filename.clone(), depth, fanout, file_size);
        Body::from_stream(stream)
    }

    /// Turn the [`ZipBomb`] into a [`Response`]
    #[must_use]
    pub fn into_generate_response(self) -> Response {
        let headers = self.generate_response_headers();
        let body = self.into_generate_body();
        (headers, body).into_response()
    }
}

impl IntoResponse for ZipBomb {
    #[inline]
    fn into_response(self) -> rama_http_types::Response {
        self.into_generate_response()
    }
}

impl From<ZipBomb> for Body {
    #[inline]
    fn from(value: ZipBomb) -> Self {
        value.into_generate_body()
    }
}

pin_project_lite::pin_project! {
    pub struct RecursiveZipBomb {
        depth: usize,
        fanout: usize,
        file_size: usize,
        #[pin]
        stream: ReaderStream<BufReader<tokio::io::DuplexStream>>,
    }
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
    fn new(filename: Cow<'static, str>, depth: usize, fanout: usize, file_size: usize) -> Self {
        let mut buffer_size = 64 * 1024;
        buffer_size += fanout * 32 * 1024;
        buffer_size += file_size.min(4 * 1024 * 1024);
        buffer_size += depth * 16 * 1024;

        let (writer, reader) = duplex(buffer_size.min(8 * 1024 * 1024));

        tokio::task::spawn_blocking(move || {
            generate_recursive_base_zip(
                SyncIoBridge::new(writer),
                &filename,
                depth,
                fanout,
                file_size,
            )
        });

        let stream = ReaderStream::new(BufReader::new(reader));

        Self {
            depth,
            fanout,
            file_size,
            stream,
        }
    }
}

fn write_nested_zip_file<W: io::Write>(
    index: usize,
    filename: &str,
    zip: &mut ZipArchiveWriter<W>,
    data: &[u8],
) -> Result<(), OpaqueError> {
    let (mut file, builder) = zip
        .new_file(&format!("{filename}_batch_{index}.zip"))
        .compression_method(CompressionMethod::Deflate)
        .start()
        .context("create batch zip file entry")?;

    let encoder = DeflateEncoder::new(&mut file, flate2::Compression::default());
    let mut writer = builder.wrap(encoder);
    writer.write_all(data).context("write nested ZIP data")?;
    let (_, descriptor) = writer.finish().context("finish ZIP entry descriptor")?;
    file.finish(descriptor).context("finish ZIP entry")?;
    Ok(())
}

fn write_fake_binary_data<W: io::Write>(
    filename: &str,
    zip: &mut ZipArchiveWriter<W>,
    file_size: usize,
) -> Result<(), OpaqueError> {
    tracing::trace!("generate fake binary data for {filename}: file_size={file_size}");
    let (mut file, builder) = zip
        .new_file(&format!("{filename}.enc.bin"))
        .compression_method(CompressionMethod::Deflate)
        .start()
        .context("write leaf binary payload")?;

    let encoder = DeflateEncoder::new(&mut file, flate2::Compression::default());
    let mut writer = builder.wrap(encoder);
    let mut zero_reader = ZeroReader(file_size);
    io::copy(&mut zero_reader, &mut writer).context("write zero data")?;
    let (_, descriptor) = writer.finish().context("finish leaf entry desciptor")?;
    file.finish(descriptor).context("finish leaf entry")?;
    Ok(())
}

fn generate_recursive_base_zip<W: io::Write>(
    buffer: W,
    filename: &str,
    depth: usize,
    fanout: usize,
    file_size: usize,
) {
    tracing::trace!(
        "generate recursive zip for {filename}: depth={depth}, fanout={fanout}, file_size={file_size}"
    );

    let mut zip = ZipArchiveWriter::new(buffer);

    if depth == 0 {
        if let Err(err) = write_fake_binary_data(filename, &mut zip, file_size) {
            tracing::debug!(
                "failed to create fake binary data (return corrupted data early): {err}"
            );
            return;
        }
    } else {
        let mut nested_buffer = Cursor::new(Vec::default());
        generate_recursive_base_zip(&mut nested_buffer, filename, depth - 1, fanout, file_size);
        let nested_buffer = nested_buffer.into_inner();
        for i in 0..fanout {
            tracing::trace!("write nested zip file #{i} for {filename}");
            if let Err(err) = write_nested_zip_file(i, filename, &mut zip, &nested_buffer) {
                tracing::debug!(
                    "failed to write nested zip file {i} (return corrupted data early): {err}"
                );
                return;
            }
        }
    }

    if let Err(err) = zip.finish() {
        tracing::debug!("failed to finalize zip data might be corrupted): {err}");
    }
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
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        this.stream.poll_next(cx)
    }
}
