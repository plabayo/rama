use super::capture::{
    CaptureDetails, CaptureStore, StoredRecord, captured_header_value, captured_http_version,
};
use arc_swap::ArcSwapOption;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use parking_lot::Mutex as SyncMutex;
use rama::{
    error::{BoxError, ErrorContext as _},
    extensions::Extensions,
    http::layer::har::{
        recorder::{
            FileRecorder, FileRecorderSession, HttpRequestCapture, Recorder, StreamingRecorder,
        },
        spec,
        toggle::Toggle,
    },
    utils::fs::TempDir,
};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fmt,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, LazyLock},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, BufWriter, ReadBuf},
    sync::{OwnedSemaphorePermit, RwLock, Semaphore},
};

const MAX_CONCURRENT_SELECTED_EXPORTS: usize = 2;
static SELECTED_EXPORT_LIMIT: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_CONCURRENT_SELECTED_EXPORTS)));

#[derive(Debug, Clone, Serialize)]
pub(super) struct HarStatus {
    pub active: bool,
    pub suspended: bool,
    pub path: Option<String>,
    pub started_at: Option<String>,
}

#[derive(Debug)]
struct ActiveHar {
    suspended: std::sync::atomic::AtomicBool,
    recorder: FileRecorder,
    path: PathBuf,
    display_path: String,
    started_at: String,
    staging: SyncMutex<Option<TempDir>>,
}

/// A stopped browser-backed HAR recording and its private staging guard.
pub(super) struct HarDownload {
    pub(super) content_length: u64,
    pub(super) file_name: String,
    pub(super) reader: HarDownloadReader,
}

/// File reader that removes the browser HAR staging directory when dropped.
pub(super) struct HarDownloadReader {
    file: tokio::fs::File,
    _staging: TempDir,
    _selected_export_permit: Option<OwnedSemaphorePermit>,
}

impl AsyncRead for HarDownloadReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.file).poll_read(cx, buffer)
    }
}

/// Materialize the selected encrypted captures one exchange at a time and
/// return a reader that removes the private staging directory when dropped.
pub(super) async fn export_selected(
    capture: &CaptureStore,
    request_ids: &BTreeSet<u64>,
    connection_ids: &BTreeSet<u64>,
) -> Result<HarDownload, BoxError> {
    let mut selection = capture.selected_exchanges(request_ids, connection_ids);
    if selection.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "select at least one retained connection or request",
        )
        .into());
    }

    // Retain the permit until the response body is dropped so slow or abandoned
    // downloads cannot accumulate an unbounded number of staged HAR files.
    let selected_export_permit =
        acquire_selected_export_permit(Arc::clone(&SELECTED_EXPORT_LIMIT))?;

    let staging = TempDir::with_prefix("rama-proxy-selected-har-")
        .context("create private selected HAR staging directory")?;
    let path = staging.path().join("selected.har");
    let mut writer = BufWriter::new(
        tokio::fs::File::create(&path)
            .await
            .context("create selected HAR file")?,
    );
    write_log_prefix(&mut writer).await?;
    let mut wrote_entry = false;
    while let Some(details) = selection.next_details().await? {
        if wrote_entry {
            writer
                .write_all(b",")
                .await
                .context("separate selected HAR entries")?;
        }
        let entry = captured_har_entry(details)?;
        let encoded = serde_json::to_vec(&entry).context("serialize selected HAR entry")?;
        writer
            .write_all(&encoded)
            .await
            .context("write selected HAR entry")?;
        wrote_entry = true;
    }
    writer
        .write_all(b"],\"comment\":null}}")
        .await
        .context("finish selected HAR")?;
    writer.flush().await.context("flush selected HAR")?;
    drop(writer);

    let file = tokio::fs::File::open(&path)
        .await
        .context("open selected HAR for download")?;
    let content_length = file
        .metadata()
        .await
        .context("read selected HAR size")?
        .len();
    Ok(HarDownload {
        content_length,
        file_name: format!(
            "rama-proxy-selection-{}.har",
            jiff::Timestamp::now().as_millisecond()
        ),
        reader: HarDownloadReader {
            file,
            _staging: staging,
            _selected_export_permit: Some(selected_export_permit),
        },
    })
}

fn acquire_selected_export_permit(limit: Arc<Semaphore>) -> std::io::Result<OwnedSemaphorePermit> {
    limit.try_acquire_owned().map_err(|_error| {
        std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "too many selected HAR exports are already in progress",
        )
    })
}

async fn write_log_prefix(writer: &mut (impl AsyncWrite + Unpin)) -> Result<(), BoxError> {
    let log = spec::Log::default();
    writer.write_all(b"{\"log\":{\"version\":").await?;
    write_json(writer, &log.version).await?;
    writer.write_all(b",\"creator\":").await?;
    write_json(writer, &log.creator).await?;
    writer.write_all(b",\"browser\":").await?;
    write_json(writer, &log.browser).await?;
    writer.write_all(b",\"entries\":[").await?;
    Ok(())
}

async fn write_json(
    writer: &mut (impl AsyncWrite + Unpin),
    value: &impl Serialize,
) -> Result<(), BoxError> {
    let encoded = serde_json::to_vec(value).context("serialize selected HAR metadata")?;
    writer
        .write_all(&encoded)
        .await
        .context("write selected HAR metadata")?;
    Ok(())
}

fn captured_har_entry(details: CaptureDetails) -> Result<spec::Entry, BoxError> {
    let mut request_head = None;
    let mut response_head = None;
    let mut request_body = Vec::new();
    let mut response_body = Vec::new();
    let mut web_socket_messages = Vec::new();
    for record in details.records {
        match record {
            StoredRecord::RequestHead {
                method,
                url,
                version,
                headers,
                ..
            } => request_head = Some((method, url, version, headers)),
            StoredRecord::Interception {
                direction,
                forwarded_headers: Some(headers),
                ..
            } if direction == "request" => {
                if let Some((_, _, _, current)) = &mut request_head {
                    *current = headers;
                }
            }
            StoredRecord::RequestBody { data } => request_body.extend(
                BASE64
                    .decode(data)
                    .context("decode selected HAR request body")?,
            ),
            StoredRecord::ResponseHead {
                status,
                version,
                headers,
                ..
            } => response_head = Some((status, version, headers)),
            StoredRecord::ResponseBody { data } => response_body.extend(
                BASE64
                    .decode(data)
                    .context("decode selected HAR response body")?,
            ),
            StoredRecord::WebSocketMessage {
                at,
                direction,
                kind,
                data,
                ..
            } => {
                let message_type = if direction.eq_ignore_ascii_case("ingress") {
                    spec::WebSocketMessageType::Send
                } else {
                    spec::WebSocketMessageType::Receive
                };
                let timestamp = at
                    .parse::<jiff::Timestamp>()
                    .context("parse captured WebSocket message timestamp")?;
                let seconds = timestamp.as_millisecond() as f64 / 1_000.0;
                let message = match kind.as_str() {
                    "text" => Some(spec::WebSocketMessage::text(
                        message_type,
                        seconds,
                        String::from_utf8(
                            BASE64
                                .decode(data)
                                .context("decode selected HAR WebSocket text")?,
                        )
                        .context("decode selected HAR WebSocket UTF-8")?,
                    )),
                    "binary" => Some(spec::WebSocketMessage::new(
                        message_type,
                        seconds,
                        spec::WebSocketMessageOpcode::BINARY,
                        data,
                    )),
                    _ => None,
                };
                web_socket_messages.extend(message);
            }
            _ => {}
        }
    }

    let (method, mut url, request_version, request_headers) =
        request_head.context("captured request head missing for HAR export")?;
    if url.starts_with('/') {
        url = format!(
            "{}://{}{}",
            details.summary.protocol, details.summary.endpoint, url
        );
    }
    let request_version = captured_http_version(&request_version)?;
    let mut request_builder = rama::http::Request::builder()
        .method(
            method
                .parse::<rama::http::Method>()
                .context("parse selected HAR request method")?,
        )
        .uri(url)
        .version(request_version);
    for (name, value) in request_headers {
        request_builder = request_builder.header(name, captured_header_value(&value)?);
    }
    let (request_parts, ()) = request_builder
        .body(())
        .context("build selected HAR request")?
        .into_parts();
    let mut request = spec::Request::from_http_request_parts(&request_parts, &request_body, false)?;

    let web_socket = matches!(details.summary.protocol.as_str(), "ws" | "wss");
    let request_size = if web_socket {
        request_body.len() as u64
    } else {
        details.summary.request_bytes
    };
    request.body_size = byte_count(request_size);
    if details.summary.request_truncated && !web_socket {
        request.comment = Some("Body truncated by the inspector capture limit".into());
    }

    let response = match response_head {
        Some((status, version, headers)) => {
            let mut response_builder = rama::http::Response::builder()
                .status(status)
                .version(captured_http_version(&version)?);
            for (name, value) in headers {
                response_builder = response_builder.header(name, captured_header_value(&value)?);
            }
            let (response_parts, ()) = response_builder
                .body(())
                .context("build selected HAR response")?
                .into_parts();
            let mut response =
                spec::Response::from_http_response_parts(&response_parts, &response_body, false)?;
            let response_size = if web_socket {
                response_body.len() as u64
            } else {
                details.summary.response_bytes
            };
            response.body_size = byte_count(response_size);
            response.content.size = byte_count(response_size);
            if details.summary.response_truncated && !web_socket {
                response.comment = Some("Body truncated by the inspector capture limit".into());
            }
            response
        }
        None => spec::Response {
            status: 0,
            status_text: None,
            http_version: request_version.into(),
            cookies: Vec::new(),
            headers: Vec::new(),
            content: spec::Content {
                size: 0,
                compression: None,
                mime_type: None,
                text: None,
                encoding: None,
                comment: None,
            },
            redirect_url: None,
            headers_size: -1,
            body_size: -1,
            comment: Some("No response had been captured when this HAR was exported".into()),
        },
    };

    let started = details.summary.started_at;
    let response_started = details.summary.response_started_at;
    let completed = details.summary.completed_at.unwrap_or_else(|| {
        if details.summary.active {
            jiff::Timestamp::now()
        } else {
            response_started.unwrap_or(started)
        }
    });
    let wait = response_started
        .map(|response_started| elapsed_millis(started, response_started))
        .unwrap_or_else(|| elapsed_millis(started, completed));
    let receive = response_started
        .map(|response_started| elapsed_millis(response_started, completed))
        .unwrap_or_default();

    Ok(spec::Entry {
        page_ref: None,
        started_date_time: started,
        time: wait.saturating_add(receive),
        request,
        response,
        cache: spec::Cache::default(),
        timings: spec::Timings {
            wait,
            receive,
            ..Default::default()
        },
        server_ip_address: details
            .summary
            .egress_peer_address
            .as_deref()
            .and_then(|address| address.parse::<SocketAddr>().ok())
            .map(|address| address.ip()),
        connection: (details.summary.connection_display_id != 0)
            .then(|| details.summary.connection_display_id.to_string().into()),
        comment: Some(format!("Rama Proxy Inspector request #{}", details.summary.id).into()),
        resource_type: web_socket.then(|| "websocket".into()),
        web_socket_messages: web_socket.then_some(web_socket_messages),
    })
}

fn elapsed_millis(start: jiff::Timestamp, end: jiff::Timestamp) -> i64 {
    end.as_millisecond()
        .saturating_sub(start.as_millisecond())
        .max(0)
}

fn byte_count(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[derive(Clone)]
pub(super) struct HarController {
    // The transition lock also gates recorder admission. A completed stop is
    // therefore a quiescence boundary: no recorder cloned before it can submit
    // work afterward and reopen the completed file.
    active: Arc<ArcSwapOption<ActiveHar>>,
    transition: Arc<RwLock<()>>,
}

impl Default for HarController {
    fn default() -> Self {
        Self {
            active: Arc::new(ArcSwapOption::empty()),
            transition: Arc::new(RwLock::new(())),
        }
    }
}

impl fmt::Debug for HarController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HarController")
            .field("active", &self.active.load().is_some())
            .finish_non_exhaustive()
    }
}

impl HarController {
    #[cfg(test)]
    pub(super) async fn start(&self, path: PathBuf) -> Result<HarStatus, BoxError> {
        if path.as_os_str().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "select a HAR output file",
            )
            .into());
        }
        if path.extension().and_then(|value| value.to_str()) != Some("har") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "HAR output file must have a .har extension",
            )
            .into());
        }
        let display_path = path.display().to_string();
        self.start_at(path, display_path, None, true).await
    }

    /// Start a HAR that will be streamed to a browser-selected file on stop.
    pub(super) async fn start_browser(&self, file_name: String) -> Result<HarStatus, BoxError> {
        let file_name = file_name.trim();
        if file_name.is_empty()
            || file_name
                .chars()
                .any(|character| character.is_ascii_control() || matches!(character, '"' | '\\'))
            || Path::new(file_name)
                .file_name()
                .and_then(|name| name.to_str())
                != Some(file_name)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "select a valid HAR output file",
            )
            .into());
        }
        if !Path::new(file_name)
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("har"))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "HAR output file must have a .har extension",
            )
            .into());
        }
        let staging = TempDir::with_prefix("rama-proxy-har-")
            .context("create private HAR staging directory")?;
        let path = staging.path().join("recording.har");
        self.start_at(path, file_name.to_owned(), Some(staging), false)
            .await
    }

    async fn start_at(
        &self,
        path: PathBuf,
        display_path: String,
        staging: Option<TempDir>,
        require_new_path: bool,
    ) -> Result<HarStatus, BoxError> {
        let _transition = self.transition.write().await;
        if self.active.load().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "a HAR recording is already active",
            )
            .into());
        }
        if require_new_path
            && tokio::fs::try_exists(&path)
                .await
                .context("check HAR output path")?
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "HAR output file already exists; choose a new file",
            )
            .into());
        }
        if staging.is_some() {
            let empty = serde_json::to_vec(&spec::LogFile {
                log: spec::Log::default(),
            })
            .context("serialize empty HAR recording")?;
            tokio::fs::write(&path, empty)
                .await
                .context("initialize browser HAR recording")?;
        }
        let recorder = FileRecorder::try_new_at(&path).context("create HAR recorder")?;
        let active = ActiveHar {
            suspended: std::sync::atomic::AtomicBool::new(false),
            recorder,
            path,
            display_path,
            started_at: jiff::Timestamp::now().to_string(),
            staging: SyncMutex::new(staging),
        };
        let status = HarStatus {
            active: true,
            suspended: false,
            path: Some(active.display_path.clone()),
            started_at: Some(active.started_at.clone()),
        };
        self.active.store(Some(Arc::new(active)));
        Ok(status)
    }

    /// Stop a browser-backed recording and stream its staged HAR to the client.
    pub(super) async fn stop_browser(&self) -> Result<HarDownload, BoxError> {
        let _transition = self.transition.write().await;
        let Some(current) = self.active.load_full() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no HAR recording is active",
            )
            .into());
        };
        if current.staging.lock().is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the active HAR recording is not browser-backed",
            )
            .into());
        }

        let active = self.active.swap(None).ok_or_else(|| {
            std::io::Error::other("active HAR disappeared during its serialized stop transition")
        })?;
        active.recorder.stop_record().await;
        let file = tokio::fs::File::open(&active.path)
            .await
            .context("open completed HAR recording")?;
        let content_length = file
            .metadata()
            .await
            .context("read completed HAR size")?
            .len();
        let staging = active.staging.lock().take().ok_or_else(|| {
            std::io::Error::other("browser-backed HAR lost its private staging directory")
        })?;
        Ok(HarDownload {
            content_length,
            file_name: active.display_path.clone(),
            reader: HarDownloadReader {
                file,
                _staging: staging,
                _selected_export_permit: None,
            },
        })
    }

    /// Finalize the current HAR without losing its staged download. A new HAR
    /// must be started explicitly: reopening an exact-path recorder would overwrite it.
    pub(super) async fn pause(&self) {
        let _transition = self.transition.write().await;
        if let Some(active) = self.active.load_full() {
            active
                .suspended
                .store(true, std::sync::atomic::Ordering::Release);
            active.recorder.stop_record().await;
        }
    }

    #[cfg(test)]
    pub(super) async fn stop(&self) -> HarStatus {
        let _transition = self.transition.write().await;
        let active = self.active.swap(None);
        if let Some(active) = active {
            active.recorder.stop_record().await;
            HarStatus {
                active: false,
                suspended: false,
                path: Some(active.display_path.clone()),
                started_at: Some(active.started_at.clone()),
            }
        } else {
            HarStatus {
                active: false,
                suspended: false,
                path: None,
                started_at: None,
            }
        }
    }

    pub(super) fn status(&self) -> HarStatus {
        let state = self.active.load();
        HarStatus {
            active: state.is_some(),
            suspended: state
                .as_deref()
                .is_some_and(|a| a.suspended.load(std::sync::atomic::Ordering::Acquire)),
            path: state.as_deref().map(|active| active.display_path.clone()),
            started_at: state.as_deref().map(|active| active.started_at.clone()),
        }
    }
}

impl Toggle for HarController {
    async fn status(&self) -> bool {
        self.active
            .load()
            .as_deref()
            .is_some_and(|a| !a.suspended.load(std::sync::atomic::Ordering::Acquire))
    }
}

impl Recorder for HarController {
    async fn record(&self, log: spec::Log) -> Option<Extensions> {
        let _transition = self.transition.read().await;
        match self.active.load_full() {
            Some(active) if !active.suspended.load(std::sync::atomic::Ordering::Acquire) => {
                active.recorder.record(log).await
            }
            _ => None,
        }
    }

    async fn stop_record(&self) {
        // HARExportService calls this whenever its toggle is off. Lifecycle is
        // controlled explicitly here: that observation must neither delete a
        // suspended download nor stop a recording started by another request.
    }
}

impl StreamingRecorder for HarController {
    type Session = FileRecorderSession;

    async fn start_http_recording(&self, request: HttpRequestCapture) -> Option<Self::Session> {
        let _transition = self.transition.read().await;
        match self.active.load_full() {
            Some(active) if !active.suspended.load(std::sync::atomic::Ordering::Acquire) => {
                active.recorder.start_http_recording(request).await
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt as _;

    #[test]
    fn captured_har_time_and_size_conversions_are_bounded() {
        let start = "2026-08-23T12:00:00Z".parse().unwrap();
        let end = "2026-08-23T12:00:00.125Z".parse().unwrap();

        assert_eq!(elapsed_millis(start, end), 125);
        assert_eq!(elapsed_millis(end, start), 0);
        assert_eq!(byte_count(42), 42);
        assert_eq!(byte_count(u64::MAX), i64::MAX);
    }

    #[test]
    fn captured_har_entry_preserves_observed_timing_and_byte_totals() {
        let entry = captured_har_entry(CaptureDetails {
            summary: super::super::capture::ExchangeSummary {
                decision: None,
                id: 7,
                connection_id: 11,
                connection_display_id: 3,
                started_at: "2026-08-23T12:00:00Z".parse().unwrap(),
                method: "POST".to_owned(),
                http_version: "HTTP/1.1".to_owned(),
                url: "https://example.test/upload".to_owned(),
                endpoint: "example.test".to_owned(),
                protocol: "https".to_owned(),
                ingress_local_address: None,
                ingress_peer_address: None,
                user_agent: None,
                user_agent_kind: None,
                status: Some(201),
                active: false,
                response_started_at: Some("2026-08-23T12:00:00.125Z".parse().unwrap()),
                completed_at: Some("2026-08-23T12:00:00.375Z".parse().unwrap()),
                egress_local_address: None,
                egress_peer_address: None,
                request_bytes: 42,
                response_bytes: 84,
                request_truncated: false,
                response_truncated: false,
                ja3: None,
                ja4: None,
                peetprint: None,
                ja4h: None,
                akamai_h2: None,
                known_fingerprint: None,
                has_emulation_profile: false,
            },
            records: vec![
                StoredRecord::RequestHead {
                    method: "POST".to_owned(),
                    url: "https://example.test/upload".to_owned(),
                    version: "HTTP/1.1".to_owned(),
                    headers: vec![(
                        "content-type".to_owned(),
                        "application/x-www-form-urlencoded".to_owned(),
                    )],
                    emulation_profile: None,
                    tls_client_hello: None,
                    ingress_tls: None,
                },
                StoredRecord::RequestBody {
                    data: BASE64.encode(b"a=b&c=hello+world"),
                },
                StoredRecord::ResponseHead {
                    status: 201,
                    version: "HTTP/1.1".to_owned(),
                    headers: Vec::new(),
                    egress_tls: None,
                },
            ],
        })
        .unwrap();

        assert_eq!(entry.time, 375);
        assert_eq!(entry.timings.send, 0);
        assert_eq!(entry.timings.wait, 125);
        assert_eq!(entry.timings.receive, 250);
        assert_eq!(entry.request.body_size, 42);
        let params = entry.request.post_data.unwrap().params.unwrap();
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].name, "a");
        assert_eq!(params[0].value.as_deref(), Some("b"));
        assert_eq!(params[1].name, "c");
        assert_eq!(params[1].value.as_deref(), Some("hello world"));
        assert_eq!(entry.response.body_size, 84);
        assert_eq!(entry.response.content.size, 84);
    }

    #[tokio::test]
    async fn requires_a_fresh_har_path_and_reports_active_state() {
        let directory = rama::utils::fs::tempdir().unwrap();
        let path = directory.path().join("capture.har");
        let unused_path = directory.path().join("unused.har");
        let controller = HarController::default();
        let status = controller.start(path.clone()).await.unwrap();
        assert!(status.active);
        assert_eq!(status.path.as_deref(), Some(path.to_str().unwrap()));
        assert!(status.started_at.is_some());

        let error = controller.start(unused_path.clone()).await.unwrap_err();
        assert!(error.to_string().contains("already active"));
        assert!(
            !unused_path.exists(),
            "rejecting a second recording must not create an unused HAR file"
        );

        let stopped = controller.stop().await;
        assert!(!stopped.active);
        assert_eq!(stopped.path.as_deref(), Some(path.to_str().unwrap()));
        assert!(!controller.status().active);

        tokio::fs::write(&path, "existing").await.unwrap();
        controller.start(path).await.unwrap_err();

        assert!(
            controller
                .start(directory.path().join("capture.json"))
                .await
                .unwrap_err()
                .to_string()
                .contains(".har extension")
        );
        assert!(
            controller
                .start(PathBuf::new())
                .await
                .unwrap_err()
                .to_string()
                .contains("select a HAR output file")
        );
        let stopped = controller.stop().await;
        assert!(stopped.path.is_none());
        assert!(stopped.started_at.is_none());
    }

    #[tokio::test]
    async fn concurrent_start_transitions_create_exactly_one_recorder() {
        let directory = rama::utils::fs::tempdir().unwrap();
        let first_path = directory.path().join("first.har");
        let second_path = directory.path().join("second.har");
        let controller = HarController::default();

        let (first, second) = tokio::join!(
            controller.start(first_path.clone()),
            controller.start(second_path.clone())
        );
        assert_ne!(first.is_ok(), second.is_ok());
        let expected_path = if first.is_ok() {
            first_path
        } else {
            second_path
        };
        let status = controller.status();
        assert!(status.active);
        assert_eq!(status.path.as_deref(), expected_path.to_str());

        let stopped = controller.stop().await;
        assert!(!stopped.active);
        assert!(!controller.status().active);
    }

    #[tokio::test]
    async fn recorder_admission_is_serialized_with_lifecycle_transitions() {
        let controller = HarController::default();
        controller
            .start_browser("capture.har".to_owned())
            .await
            .unwrap();

        let transition = controller.transition.write().await;
        let mut record = tokio::spawn({
            let controller = controller.clone();
            async move { controller.record(spec::Log::default()).await }
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut record)
                .await
                .is_err(),
            "a recording call must not clone the file recorder outside the lifecycle lock"
        );

        drop(transition);
        assert!(record.await.unwrap().is_some());
        let download = controller.stop_browser().await.unwrap();
        assert!(!controller.status().active);
        assert!(controller.record(spec::Log::default()).await.is_none());
        drop(download);
    }

    #[tokio::test]
    async fn selected_export_limit_is_held_until_the_download_reader_is_dropped() {
        let limit = Arc::new(Semaphore::new(1));
        let permit = acquire_selected_export_permit(Arc::clone(&limit)).unwrap();
        let staging = TempDir::with_prefix("rama-proxy-selected-har-limit-test-").unwrap();
        let path = staging.path().join("selected.har");
        tokio::fs::write(&path, b"{}" as &[u8]).await.unwrap();
        let reader = HarDownloadReader {
            file: tokio::fs::File::open(path).await.unwrap(),
            _staging: staging,
            _selected_export_permit: Some(permit),
        };

        let error = acquire_selected_export_permit(Arc::clone(&limit))
            .expect_err("a live download reader must retain its export permit");
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);

        drop(reader);
        let _permit = acquire_selected_export_permit(limit).unwrap();
    }

    #[tokio::test]
    async fn browser_recording_requires_a_file_name_and_streams_owned_staging() {
        let controller = HarController::default();
        for invalid in [
            "",
            "capture.json",
            "../capture.har",
            "nested/capture.har",
            "quoted\".har",
            "escaped\\.har",
        ] {
            controller
                .start_browser(invalid.to_owned())
                .await
                .unwrap_err();
        }

        let status = controller
            .start_browser("selected.har".to_owned())
            .await
            .unwrap();
        assert!(status.active);
        assert_eq!(status.path.as_deref(), Some("selected.har"));
        let staging = controller
            .active
            .load_full()
            .unwrap()
            .path
            .parent()
            .unwrap()
            .to_owned();
        assert!(staging.exists());

        let download = controller.stop_browser().await.unwrap();
        assert!(!controller.status().active);
        assert_eq!(download.file_name, "selected.har");
        let expected_length = download.content_length;
        let mut reader = download.reader;
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes.len() as u64, expected_length);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(value.get("log").is_some());
        drop(reader);
        assert!(!staging.exists());
    }
    #[tokio::test]
    async fn paused_har_stays_frozen_and_downloadable_while_traffic_continues() {
        use rama::{
            Layer as _, Service as _,
            http::{Body, Request, Response, layer::har::layer::HARExportLayer},
            service::service_fn,
        };
        let controller = HarController::default();
        controller.start_browser("paused.har".into()).await.unwrap();
        let service = HARExportLayer::new(controller.clone(), controller.clone()).into_layer(
            service_fn(async |_: Request| Ok::<_, BoxError>(Response::new(Body::empty()))),
        );
        service
            .serve(
                Request::builder()
                    .uri("http://example.test/before")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        controller.pause().await;
        let active = controller.active.load_full().unwrap();
        let before = tokio::fs::read(&active.path).await.unwrap();
        service
            .serve(
                Request::builder()
                    .uri("http://example.test/after")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(controller.status().suspended);
        assert_eq!(tokio::fs::read(&active.path).await.unwrap(), before);
        let mut download = controller.stop_browser().await.unwrap();
        let mut bytes = Vec::new();
        download.reader.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, before);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["log"]["entries"].as_array().unwrap().len(), 1);
        assert_eq!(
            value["log"]["entries"][0]["request"]["url"],
            "http://example.test/before"
        );
    }
}
