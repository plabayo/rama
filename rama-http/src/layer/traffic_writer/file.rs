use super::{
    RequestWriter, ResponseWriter, TrafficWriterId, WriterMode, ensure_traffic_writer_id,
    write_headers_body_flags,
};
use crate::{Request, Response, io::write_http_request_streaming};
use rama_core::error::BoxError;
use rama_core::extensions::ExtensionsRef as _;
use rama_core::telemetry::tracing;
use rama_utils::fs::{CreatedFilePermissions, OpenOptions, is_reserved_device_name};
use rama_utils::time::unix_timestamp_millis;
use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::io::{AsyncWriteExt as _, BufWriter};

const MAX_PREFIX_LEN: usize = 32;
const MAX_METHOD_LEN: usize = 16;
const MAX_FILE_NAME_LEN: usize = 160;
const CREATE_ATTEMPTS: usize = 8;

/// Writes every captured request and response to an independent file.
///
/// Independent files allow bodies to stream concurrently without frame
/// interleaving or cross-message backpressure. Generated filenames use only
/// portable ASCII characters and are bounded to 160 bytes, comfortably below
/// the commonly supported 255-byte component limit. The caller-provided
/// destination can still be rejected by the operating system when the complete
/// path exceeds a platform-specific path limit.
/// Raw URIs are never included because they can contain secrets, path
/// separators, platform-specific characters, or unbounded input.
/// Request and response files captured for the same HTTP exchange contain the
/// same UUID, regardless of request/response writer layer order.
///
/// Files are created without overwriting existing paths. On Unix, newly
/// created files receive owner-only read/write permissions before the process
/// umask is applied. The destination directory is canonicalized and every file
/// open is confined to it.
#[derive(Clone, Debug)]
pub struct PerMessageFileWriter {
    directory: Arc<PathBuf>,
    prefix: Arc<str>,
    request_mode: Option<WriterMode>,
    response_mode: Option<WriterMode>,
}

impl PerMessageFileWriter {
    /// Create a per-message file writer, creating `directory` when necessary.
    ///
    /// `prefix` must be 1 to 32 ASCII letters, digits, `-`, or `_`. This
    /// deliberately conservative alphabet is valid in filenames on Unix,
    /// Windows, and common removable filesystems.
    pub async fn try_new(
        directory: impl Into<PathBuf>,
        prefix: impl AsRef<str>,
    ) -> io::Result<Self> {
        let prefix = validate_prefix(prefix.as_ref())?;
        let directory = directory.into();
        tokio::fs::create_dir_all(&directory).await?;
        let directory = tokio::fs::canonicalize(directory).await?;
        Ok(Self {
            directory: Arc::new(directory),
            prefix: Arc::from(prefix),
            request_mode: Some(WriterMode::All),
            response_mode: Some(WriterMode::All),
        })
    }

    /// Set how request files are written.
    #[must_use]
    pub fn with_request_mode(mut self, mode: Option<WriterMode>) -> Self {
        self.request_mode = mode;
        self
    }

    /// Set how response files are written.
    #[must_use]
    pub fn with_response_mode(mut self, mode: Option<WriterMode>) -> Self {
        self.response_mode = mode;
        self
    }

    /// Return the canonical destination directory.
    #[must_use]
    pub fn directory(&self) -> &Path {
        self.directory.as_ref()
    }

    /// Return the portable filename prefix.
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Return the configured request writer mode.
    #[must_use]
    pub const fn request_mode(&self) -> Option<WriterMode> {
        self.request_mode
    }

    /// Return the configured response writer mode.
    #[must_use]
    pub const fn response_mode(&self) -> Option<WriterMode> {
        self.response_mode
    }

    async fn open_unique(
        &self,
        name: impl Fn(usize) -> String,
    ) -> io::Result<(BufWriter<tokio::fs::File>, PathBuf)> {
        for attempt in 0..CREATE_ATTEMPTS {
            let filename = name(attempt);
            if !is_portable_filename(&filename) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "generated traffic capture filename is not portable",
                ));
            }

            let result = OpenOptions::new()
                .write(true)
                .create_new(true)
                .created_file_permissions(CreatedFilePermissions::OwnerReadWrite)
                .jail(self.directory.as_ref())
                .open(&filename)
                .await;
            match result {
                Ok(file) => {
                    let path = self.directory.join(filename);
                    return Ok((BufWriter::new(file), path));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "failed to allocate a unique traffic capture filename",
        ))
    }
}

impl RequestWriter for PerMessageFileWriter {
    async fn write_request(&self, request: Request) {
        let (write_headers, write_body) = write_headers_body_flags(self.request_mode);
        if !write_headers && !write_body {
            return;
        }

        let method = portable_method(request.method().as_str());
        let traffic_writer_id = ensure_traffic_writer_id(request.extensions());
        let timestamp = unix_timestamp_millis();
        let opened = self
            .open_unique(|attempt| {
                request_filename(&self.prefix, timestamp, &method, traffic_writer_id, attempt)
            })
            .await;
        let (mut file, path) = match opened {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(%error, "failed to create request capture file");
                return;
            }
        };

        let result =
            write_http_request_streaming(&mut file, request, write_headers, write_body).await;
        finish_file_write(&mut file, &path, "request", result).await;
    }
}

impl ResponseWriter for PerMessageFileWriter {
    async fn write_response(&self, response: Response) {
        let (write_headers, write_body) = write_headers_body_flags(self.response_mode);
        if !write_headers && !write_body {
            return;
        }

        let status = response.status().as_u16();
        let traffic_writer_id = ensure_traffic_writer_id(response.extensions());
        let timestamp = unix_timestamp_millis();
        let opened = self
            .open_unique(|attempt| {
                response_filename(&self.prefix, timestamp, status, traffic_writer_id, attempt)
            })
            .await;
        let (mut file, path) = match opened {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(%error, "failed to create response capture file");
                return;
            }
        };

        let result = crate::io::write_http_response_streaming(
            &mut file,
            response,
            write_headers,
            write_body,
        )
        .await;
        finish_file_write(&mut file, &path, "response", result).await;
    }
}

async fn finish_file_write(
    file: &mut BufWriter<tokio::fs::File>,
    path: &Path,
    message_kind: &'static str,
    write_result: Result<(), BoxError>,
) {
    if let Err(error) = write_result {
        tracing::error!(
            %error,
            path = %path.display(),
            message_kind,
            "failed to write HTTP capture file"
        );
    }
    if let Err(error) = file.flush().await {
        tracing::error!(
            %error,
            path = %path.display(),
            message_kind,
            "failed to flush HTTP capture file"
        );
    }
}

fn validate_prefix(prefix: &str) -> io::Result<String> {
    if prefix.is_empty()
        || prefix.len() > MAX_PREFIX_LEN
        || !prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || is_reserved_device_name(prefix)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "traffic capture filename prefix must be 1 to 32 portable ASCII letters, digits, '-' or '_' and not a reserved device name",
        ));
    }
    Ok(prefix.to_owned())
}

fn portable_method(method: &str) -> String {
    method
        .bytes()
        .take(MAX_METHOD_LEN)
        .map(|byte| {
            if byte.is_ascii_alphanumeric() {
                char::from(byte.to_ascii_uppercase())
            } else {
                '_'
            }
        })
        .collect()
}

fn request_filename(
    prefix: &str,
    timestamp: i64,
    method: &str,
    traffic_writer_id: TrafficWriterId,
    attempt: usize,
) -> String {
    let id = traffic_writer_id.0.simple();
    if attempt == 0 {
        format!("{prefix}-{timestamp}-request-{method}-{id}.http")
    } else {
        format!("{prefix}-{timestamp}-request-{method}-{id}-{attempt}.http")
    }
}

fn response_filename(
    prefix: &str,
    timestamp: i64,
    status: u16,
    traffic_writer_id: TrafficWriterId,
    attempt: usize,
) -> String {
    let id = traffic_writer_id.0.simple();
    if attempt == 0 {
        format!("{prefix}-{timestamp}-response-{status}-{id}.http")
    } else {
        format!("{prefix}-{timestamp}-response-{status}-{id}-{attempt}.http")
    }
}

fn is_portable_filename(filename: &str) -> bool {
    !filename.is_empty()
        && filename.len() <= MAX_FILE_NAME_LEN
        && filename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !filename.ends_with(['.', ' '])
        && !is_reserved_device_name(filename)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Body, Method, StatusCode,
        body::util::BodyExt as _,
        layer::traffic_writer::{RequestWriterLayer, ResponseWriterLayer},
    };
    use ahash::{HashSet, HashSetExt as _};
    use rama_core::{Layer as _, Service as _, rt::Executor, service::service_fn};
    use std::{convert::Infallible, time::Duration};
    use uuid::Uuid;

    async fn wait_for_exchange_files(directory: &Path) -> Vec<(String, Vec<u8>)> {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let mut entries = tokio::fs::read_dir(directory).await.unwrap();
                let mut files = Vec::new();
                while let Some(entry) = entries.next_entry().await.unwrap() {
                    files.push((
                        entry.file_name().into_string().unwrap(),
                        tokio::fs::read(entry.path()).await.unwrap(),
                    ));
                }
                if files.len() == 2
                    && files
                        .iter()
                        .any(|(_, bytes)| bytes.ends_with(b"\r\nrequest-body"))
                    && files
                        .iter()
                        .any(|(_, bytes)| bytes.ends_with(b"\r\nresponse-body"))
                {
                    return files;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("request and response capture files should finish")
    }

    fn assert_exchange_files_share_id(files: &[(String, Vec<u8>)]) {
        fn id(name: &str) -> &str {
            name.strip_suffix(".http")
                .unwrap()
                .rsplit('-')
                .next()
                .unwrap()
        }

        let request = files
            .iter()
            .find(|(name, _)| name.contains("-request-POST-"))
            .unwrap();
        let response = files
            .iter()
            .find(|(name, _)| name.contains("-response-200-"))
            .unwrap();
        let request_id = id(&request.0);
        let response_id = id(&response.0);
        assert_eq!(request_id.len(), 32);
        assert!(request_id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(request_id, response_id);
    }

    async fn consume_request(request: Request) -> Result<Response, Infallible> {
        assert_eq!(
            request.into_body().collect().await.unwrap().to_bytes(),
            "request-body"
        );
        Ok(Response::new(Body::from("response-body")))
    }

    #[test]
    fn generated_filenames_are_unique_portable_and_bounded() {
        let method = portable_method("CUSTOM/METHOD-THAT-IS-TOO-LONG");
        assert_eq!(method, "CUSTOM_METHOD_TH");
        let mut names = HashSet::new();

        for _ in 0..128 {
            let traffic_writer_id = TrafficWriterId(Uuid::new_v4());
            let request = request_filename(
                "portable_prefix-123456789012345",
                1_700_000_000_000,
                &method,
                traffic_writer_id,
                0,
            );
            let response = response_filename(
                "portable_prefix-123456789012345",
                1_700_000_000_001,
                599,
                traffic_writer_id,
                0,
            );
            let id = traffic_writer_id.0.simple().to_string();
            assert!(request.contains(&id));
            assert!(response.contains(&id));
            for filename in [request, response] {
                assert!(is_portable_filename(&filename));
                assert!(filename.len() <= MAX_FILE_NAME_LEN);
                assert_eq!(Path::new(&filename).components().count(), 1);
                assert!(!filename.contains("access_token"));
                assert!(names.insert(filename));
            }
        }

        let traffic_writer_id = TrafficWriterId(Uuid::new_v4());
        let base = request_filename("capture", 1, "GET", traffic_writer_id, 0);
        let retry = request_filename("capture", 1, "GET", traffic_writer_id, 1);
        assert_ne!(base, retry);
        assert!(retry.ends_with(&format!("-{}-1.http", traffic_writer_id.0.simple())));
        assert!(is_portable_filename(&retry));

        let base = response_filename("capture", 1, 200, traffic_writer_id, 0);
        let retry = response_filename("capture", 1, 200, traffic_writer_id, 1);
        assert_ne!(base, retry);
        assert!(retry.ends_with(&format!("-{}-1.http", traffic_writer_id.0.simple())));
        assert!(is_portable_filename(&retry));

        let longest = request_filename(
            "12345678901234567890123456789012",
            i64::MIN,
            &method,
            traffic_writer_id,
            CREATE_ATTEMPTS - 1,
        );
        assert!(longest.len() <= MAX_FILE_NAME_LEN);
        assert!(is_portable_filename(&longest));
    }

    #[tokio::test]
    async fn file_layers_share_exchange_id_with_request_layer_outermost() {
        let temp = rama_utils::fs::tempdir().unwrap();
        let executor = Executor::new();
        let request = RequestWriterLayer::file_per_request(
            &executor,
            temp.path(),
            "traffic",
            Some(WriterMode::All),
        )
        .await
        .unwrap();
        let response = ResponseWriterLayer::file_per_response(
            &executor,
            temp.path(),
            "traffic",
            Some(WriterMode::All),
        )
        .await
        .unwrap();
        let service = request.into_layer(response.into_layer(service_fn(consume_request)));

        let response = service
            .serve(
                Request::builder()
                    .method(Method::POST)
                    .uri("/capture")
                    .body(Body::from("request-body"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "response-body"
        );
        drop(service);

        let files = wait_for_exchange_files(temp.path()).await;
        assert_exchange_files_share_id(&files);
    }

    #[tokio::test]
    async fn file_layers_share_exchange_id_with_response_layer_outermost() {
        let temp = rama_utils::fs::tempdir().unwrap();
        let executor = Executor::new();
        let request = RequestWriterLayer::file_per_request(
            &executor,
            temp.path(),
            "traffic",
            Some(WriterMode::All),
        )
        .await
        .unwrap();
        let response = ResponseWriterLayer::file_per_response(
            &executor,
            temp.path(),
            "traffic",
            Some(WriterMode::All),
        )
        .await
        .unwrap();
        let service = response.into_layer(request.into_layer(service_fn(consume_request)));

        let response = service
            .serve(
                Request::builder()
                    .method(Method::POST)
                    .uri("/capture")
                    .body(Body::from("request-body"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "response-body"
        );
        drop(service);

        let files = wait_for_exchange_files(temp.path()).await;
        assert_exchange_files_share_id(&files);
    }

    #[tokio::test]
    async fn prefix_validation_is_platform_conservative() {
        let temp = rama_utils::fs::tempdir().unwrap();
        for prefix in [
            "",
            "contains space",
            "contains.dot",
            "../escape",
            r"back\slash",
            "unicode-λ",
            "CON",
            "nul",
            "123456789012345678901234567890123",
        ] {
            let error = PerMessageFileWriter::try_new(temp.path(), prefix)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{prefix:?}");
        }

        let writer = PerMessageFileWriter::try_new(temp.path(), "Abc_123-xyz-12345678901234567890")
            .await
            .unwrap();
        assert_eq!(writer.prefix().len(), MAX_PREFIX_LEN);
        assert_eq!(writer.directory(), temp.path().canonicalize().unwrap());
    }

    #[tokio::test]
    async fn unique_creation_never_overwrites_an_existing_file() {
        let temp = rama_utils::fs::tempdir().unwrap();
        let writer = PerMessageFileWriter::try_new(temp.path(), "capture")
            .await
            .unwrap();
        let colliding = "capture-1-request-GET-00000000000000000000000000000000.http";
        let unique = "capture-2-request-GET-00000000000000000000000000000000.http";
        assert!(is_portable_filename(colliding));
        assert!(is_portable_filename(unique));
        let path = temp.path().join(colliding);
        tokio::fs::write(&path, b"existing").await.unwrap();

        let (_, created_path) = writer
            .open_unique(|attempt| {
                if attempt == 0 {
                    colliding.to_owned()
                } else {
                    unique.to_owned()
                }
            })
            .await
            .unwrap();
        assert_eq!(created_path, writer.directory().join(unique));
        assert_eq!(tokio::fs::read(path).await.unwrap(), b"existing");
    }

    #[tokio::test]
    async fn unique_creation_reports_exhausted_collisions() {
        let temp = rama_utils::fs::tempdir().unwrap();
        let writer = PerMessageFileWriter::try_new(temp.path(), "capture")
            .await
            .unwrap();
        let filename = "capture-1-request-GET-00000000000000000000000000000000.http";
        tokio::fs::write(temp.path().join(filename), b"existing")
            .await
            .unwrap();

        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let error = writer
            .open_unique(|_| {
                attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                filename.to_owned()
            })
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::Relaxed),
            CREATE_ATTEMPTS
        );
    }

    #[tokio::test]
    async fn unique_creation_propagates_non_collision_errors() {
        let temp = rama_utils::fs::tempdir().unwrap();
        let directory = temp.path().join("removed");
        let writer = PerMessageFileWriter::try_new(&directory, "capture")
            .await
            .unwrap();
        tokio::fs::remove_dir(directory).await.unwrap();

        let error = writer
            .open_unique(|_| "capture-unique.http".to_owned())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn unique_creation_rejects_non_portable_generated_names() {
        let temp = rama_utils::fs::tempdir().unwrap();
        let writer = PerMessageFileWriter::try_new(temp.path(), "capture")
            .await
            .unwrap();

        let overly_long = "x".repeat(MAX_FILE_NAME_LEN + 1);
        for filename in ["../escape.http", "trailing.", overly_long.as_str()] {
            let error = writer
                .open_unique(|_| filename.to_owned())
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
        assert!(
            tokio::fs::read_dir(temp.path())
                .await
                .unwrap()
                .next_entry()
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn request_and_response_files_stream_independently() {
        let temp = rama_utils::fs::tempdir().unwrap();
        let writer = PerMessageFileWriter::try_new(temp.path(), "traffic")
            .await
            .unwrap();
        let traffic_writer_id = TrafficWriterId(Uuid::new_v4());

        let (first_tx, first_rx) = tokio::sync::mpsc::unbounded_channel();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let first_body = Body::from_stream(rama_core::futures::stream::unfold(
            (first_rx, Some(started_tx)),
            |(mut receiver, started)| async move {
                if let Some(started) = started {
                    _ = started.send(());
                }
                receiver.recv().await.map(|item| (item, (receiver, None)))
            },
        ));
        let first_response = Response::builder()
            .status(StatusCode::OK)
            .body(first_body)
            .unwrap();
        first_response.extensions().insert(traffic_writer_id);
        let first_writer = writer.clone();
        let first = tokio::spawn(async move {
            first_writer.write_response(first_response).await;
        });
        let second_request = Request::builder()
            .method(Method::POST)
            .uri("https://example.com/upload?token=secret")
            .header("x-test", "yes")
            .body(Body::from("second"))
            .unwrap();
        second_request.extensions().insert(traffic_writer_id);
        let second = writer.write_request(second_request);
        tokio::time::timeout(Duration::from_secs(10), started_rx)
            .await
            .expect("response writer should start")
            .expect("response writer should poll its body");
        first_tx
            .send(Ok::<_, std::convert::Infallible>(
                rama_core::bytes::Bytes::from_static(b"first"),
            ))
            .unwrap();

        tokio::time::timeout(Duration::from_secs(10), second)
            .await
            .expect("a separate request file must not wait for a live response");
        drop(first_tx);
        first.await.unwrap();

        let mut entries = tokio::fs::read_dir(temp.path()).await.unwrap();
        let mut files = Vec::new();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            let name = entry.file_name().into_string().unwrap();
            assert!(is_portable_filename(&name));
            files.push((name, tokio::fs::read(entry.path()).await.unwrap()));
        }
        assert_eq!(files.len(), 2);
        assert!(files.iter().any(|(name, bytes)| {
            name.contains("-request-POST-")
                && bytes.starts_with(b"POST /upload?token=secret HTTP/1.1\r\n")
                && bytes.ends_with(b"\r\nsecond")
        }));
        assert!(files.iter().any(|(name, bytes)| {
            name.contains("-response-200-")
                && bytes.starts_with(b"HTTP/1.1 200 OK\r\n")
                && bytes.ends_with(b"\r\nfirst")
        }));
        assert!(files.iter().all(|(name, _)| !name.contains("secret")));
        let id = traffic_writer_id.0.simple().to_string();
        assert!(files.iter().all(|(name, _)| name.contains(&id)));
    }

    #[tokio::test]
    async fn body_error_flushes_partial_request_capture() {
        let temp = rama_utils::fs::tempdir().unwrap();
        let writer = PerMessageFileWriter::try_new(temp.path(), "traffic")
            .await
            .unwrap()
            .with_response_mode(None);
        let body = Body::from_stream(rama_core::futures::stream::iter([
            Ok::<_, io::Error>(rama_core::bytes::Bytes::from_static(b"first")),
            Err(io::Error::other("body failed")),
        ]));

        writer
            .write_request(
                Request::builder()
                    .method(Method::POST)
                    .uri("/broken")
                    .body(body)
                    .unwrap(),
            )
            .await;

        let entry = tokio::fs::read_dir(temp.path())
            .await
            .unwrap()
            .next_entry()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            tokio::fs::read(entry.path()).await.unwrap(),
            b"POST /broken HTTP/1.1\r\n\r\nfirst"
        );
    }

    #[tokio::test]
    async fn disabled_request_does_not_create_a_file() {
        let temp = rama_utils::fs::tempdir().unwrap();
        let writer = PerMessageFileWriter::try_new(temp.path(), "traffic")
            .await
            .unwrap()
            .with_request_mode(None);
        writer
            .write_request(Request::new(Body::from("ignored")))
            .await;
        assert!(
            tokio::fs::read_dir(temp.path())
                .await
                .unwrap()
                .next_entry()
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn disabled_response_does_not_create_a_file() {
        let temp = rama_utils::fs::tempdir().unwrap();
        let writer = PerMessageFileWriter::try_new(temp.path(), "traffic")
            .await
            .unwrap()
            .with_response_mode(None);
        writer
            .write_response(Response::new(Body::from("ignored")))
            .await;
        assert!(
            tokio::fs::read_dir(temp.path())
                .await
                .unwrap()
                .next_entry()
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn response_headers_mode_creates_a_file() {
        let temp = rama_utils::fs::tempdir().unwrap();
        let writer = PerMessageFileWriter::try_new(temp.path(), "traffic")
            .await
            .unwrap()
            .with_request_mode(None)
            .with_response_mode(Some(WriterMode::Headers));
        writer
            .write_response(
                Response::builder()
                    .status(StatusCode::ACCEPTED)
                    .header("x-mode", "headers")
                    .body(Body::from("ignored"))
                    .unwrap(),
            )
            .await;

        let entry = tokio::fs::read_dir(temp.path())
            .await
            .unwrap()
            .next_entry()
            .await
            .unwrap()
            .unwrap();
        let bytes = tokio::fs::read(entry.path()).await.unwrap();
        assert!(bytes.starts_with(b"HTTP/1.1 202 Accepted\r\n"));
        assert!(bytes.ends_with(b"x-mode: headers\r\n"));
        assert!(!bytes.windows(7).any(|window| window == b"ignored"));
    }

    #[tokio::test]
    async fn request_and_response_modes_control_file_contents() {
        let temp = rama_utils::fs::tempdir().unwrap();
        let writer = PerMessageFileWriter::try_new(temp.path(), "modes")
            .await
            .unwrap()
            .with_request_mode(Some(WriterMode::Headers))
            .with_response_mode(Some(WriterMode::Body));

        writer
            .write_request(
                Request::builder()
                    .uri("/headers")
                    .header("x-mode", "headers")
                    .body(Body::from("not written"))
                    .unwrap(),
            )
            .await;
        writer
            .write_response(
                Response::builder()
                    .status(StatusCode::CREATED)
                    .header("x-mode", "not written")
                    .body(Body::from("body only"))
                    .unwrap(),
            )
            .await;

        let mut entries = tokio::fs::read_dir(temp.path()).await.unwrap();
        let mut files = Vec::new();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            files.push((
                entry.file_name().into_string().unwrap(),
                tokio::fs::read(entry.path()).await.unwrap(),
            ));
        }
        assert_eq!(files.len(), 2);
        assert!(files.iter().any(|(name, bytes)| {
            name.contains("-request-GET-")
                && bytes.starts_with(b"GET /headers HTTP/1.1\r\n")
                && bytes.ends_with(b"x-mode: headers\r\n")
                && !bytes.windows(11).any(|window| window == b"not written")
        }));
        assert!(
            files.iter().any(|(name, bytes)| {
                name.contains("-response-201-") && bytes == b"\r\nbody only"
            })
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn capture_files_are_not_group_or_world_accessible() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = rama_utils::fs::tempdir().unwrap();
        let writer = PerMessageFileWriter::try_new(temp.path(), "traffic")
            .await
            .unwrap();
        writer
            .write_response(Response::new(Body::from("private")))
            .await;

        let entry = tokio::fs::read_dir(temp.path())
            .await
            .unwrap()
            .next_entry()
            .await
            .unwrap()
            .unwrap();
        let mode = entry.metadata().await.unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
    }
}
