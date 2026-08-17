use super::{
    BodyCaptureStream, HttpRequestCapture, HttpResponseCapture, Recorder, RecorderSession,
    StreamingRecorder, WebSocketCapture, WebSocketCaptureCloseHandle, WebSocketCaptureWriter,
};
use crate::layer::har::spec;
use crate::{BodyCaptureEvent, CaptureOutcome};
use base64::engine::general_purpose::STANDARD as BASE64;
use jiff::Timestamp;
use parking_lot::Mutex;
use rama_core::error::{BoxError, ErrorContext};
use rama_core::extensions::{Extension, Extensions};
use rama_core::telemetry::tracing;
use rama_utils::{
    fs::{CreatedFilePermissions, OpenOptions, safe_open, safe_open_sync},
    time::now_unix,
};
use serde_json::Value;
use std::io::{Read, SeekFrom, Write};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Once};
use std::task::{Context, Poll};
use tempfile::TempPath;
use tokio::fs::File;
use tokio::io::{AsyncSeekExt, AsyncWriteExt, BufWriter};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::{CancellationToken, PollSender};

/// Recorder that creates one file per recording session.
///
/// Live HTTP bodies are captured into private per-exchange temporary files.
/// Completed entries are then copied into the destination HAR by one writer,
/// so concurrent streams cannot interleave and body memory remains bounded.
#[derive(Debug, Clone)]
pub struct FileRecorder {
    tx: mpsc::Sender<FileRecorderMessage>,
    task: Arc<FileRecorderTaskStarter>,
}

#[derive(Debug)]
struct FileRecorderTaskStarter {
    once: Once,
    task: Mutex<Option<FileRecorderTask>>,
}

#[derive(Debug)]
pub struct FileRecorderSession {
    tx: mpsc::Sender<CaptureWorkerMessage>,
    path: HarFilePath,
    web_socket_capture: Option<WebSocketCapture>,
}

#[derive(Debug, Clone, Extension)]
#[extension(tags(http))]
/// Path to the HAR file that the [`FileRecorder`] is recording into.
///
/// Inserted into response extensions. The file remains an in-progress JSON
/// document until [`Recorder::stop_record`] completes.
pub struct HarFilePath(Arc<PathBuf>);

impl AsRef<Path> for HarFilePath {
    fn as_ref(&self) -> &Path {
        self.0.as_ref()
    }
}

impl Deref for HarFilePath {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

#[derive(Debug)]
enum FileRecorderMessage {
    StartHttp {
        request: Box<HttpRequestCapture>,
        reply: oneshot::Sender<Option<FileRecorderSession>>,
    },
    Record {
        log: Box<spec::Log>,
        reply: oneshot::Sender<Extensions>,
    },
    Stop {
        done: oneshot::Sender<()>,
    },
}

#[derive(Debug)]
enum CaptureWorkerMessage {
    Response {
        response: Box<HttpResponseCapture>,
        headers_at: Instant,
    },
    RequestOnly,
}

#[derive(Debug)]
struct FileRecorderTask {
    rx: mpsc::Receiver<FileRecorderMessage>,
    dir: PathBuf,
    prefix: String,
    start: Instant,
    start_epoch: i64,
}

#[derive(Debug)]
struct Storage {
    file: File,
    path: PathBuf,
    has_entries: bool,
    valid_position: u64,
    valid: bool,
}

impl Storage {
    async fn try_new(path: PathBuf, log: &spec::Log) -> Result<Self, BoxError> {
        if let Some(parent) = path.parent() {
            create_har_parent_dir(parent)
                .await
                .context("create HAR file parent dir")?;
        }
        // Archives can contain credentials, cookies, and bodies. Apply 0600 at
        // creation on Unix so their bytes are never briefly world-readable.
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .created_file_permissions(CreatedFilePermissions::OwnerReadWrite)
            .open(&path)
            .await
            .context("create HAR file")?;

        let mut header = Vec::new();
        serde_json::to_writer(
            &mut header,
            &serde_json::json!({
                "log": {
                    "version": log.version,
                    "creator": log.creator,
                    "browser": log.browser,
                    "comment": log.comment,
                    "pages": [],
                },
            }),
        )
        .context("serialize HAR header")?;
        header.truncate(header.len() - 2);
        header.extend_from_slice(b",\"entries\":[");
        file.write_all(&header).await.context("write HAR header")?;

        Ok(Self {
            file,
            path,
            has_entries: false,
            valid_position: u64::try_from(header.len()).unwrap_or(u64::MAX),
            valid: true,
        })
    }

    async fn append_artifact(&mut self, path: &Path) -> Result<(), BoxError> {
        let mut artifact = safe_open(path)
            .await
            .context("open completed HAR entry artifact")?;
        let checkpoint = self.valid_position;
        self.valid = false;
        let result = async {
            let separator_len = if self.has_entries {
                self.file
                    .write_u8(b',')
                    .await
                    .context("write HAR entry separator")?;
                1
            } else {
                0
            };
            let copied = tokio::io::copy(&mut artifact, &mut self.file)
                .await
                .context("copy completed HAR entry artifact")?;
            Ok::<_, BoxError>((separator_len, copied))
        }
        .await;

        match result {
            Ok((separator_len, copied)) => {
                self.valid_position = checkpoint
                    .saturating_add(separator_len)
                    .saturating_add(copied);
                self.has_entries = true;
                self.valid = true;
                Ok(())
            }
            Err(err) => {
                if let Err(rollback_err) = self.rollback(checkpoint).await {
                    return Err(std::io::Error::other(format!(
                        "append HAR artifact failed ({err:?}) and rollback failed: {rollback_err}"
                    ))
                    .into());
                }
                self.valid = true;
                Err(err)
            }
        }
    }

    async fn rollback(&mut self, position: u64) -> std::io::Result<()> {
        self.file.set_len(position).await?;
        self.file.seek(SeekFrom::Start(position)).await?;
        Ok(())
    }
}

impl FileRecorderTask {
    fn new(rx: mpsc::Receiver<FileRecorderMessage>, dir: PathBuf, prefix: String) -> Self {
        Self {
            rx,
            dir,
            prefix,
            start: Instant::now(),
            start_epoch: now_unix(),
        }
    }

    async fn run(mut self) {
        let mut storage = None;
        let mut counter = 0_u64;
        let mut workers: JoinSet<Result<TempPath, BoxError>> = JoinSet::new();
        let (cancel_tx, _) = watch::channel(false);

        loop {
            tokio::select! {
                worker = workers.join_next(), if !workers.is_empty() => {
                    handle_worker(worker, &mut storage).await;
                }
                message = self.rx.recv() => {
                    let Some(message) = message else {
                        break;
                    };
                    match message {
                        FileRecorderMessage::StartHttp { request, reply } => {
                            let result = match self
                                .ensure_storage(&mut storage, &mut counter, &spec::Log::default())
                                .await
                            {
                                Ok(storage_ref) => {
                                    let path = HarFilePath(Arc::new(storage_ref.path.clone()));
                                    let (tx, rx) = mpsc::channel(1);
                                    let web_socket = if request.is_web_socket() {
                                        match create_web_socket_capture(self.dir.clone()).await {
                                            Ok(capture) => Some(capture),
                                            Err(err) => {
                                                tracing::debug!(
                                                    "failed to create WebSocket HAR capture: {err}"
                                                );
                                                _ = reply.send(None);
                                                continue;
                                            }
                                        }
                                    } else {
                                        None
                                    };
                                    let web_socket_capture = web_socket
                                        .as_ref()
                                        .map(|(capture, _, _)| capture.clone());
                                    let web_socket = web_socket.map(
                                        |(_capture, completion, closer)| (closer, completion),
                                    );
                                    workers.spawn(capture_http_entry(
                                        *request,
                                        rx,
                                        self.dir.clone(),
                                        cancel_tx.subscribe(),
                                        web_socket,
                                    ));
                                    Some(FileRecorderSession {
                                        tx,
                                        path,
                                        web_socket_capture,
                                    })
                                }
                                Err(err) => {
                                    tracing::debug!(
                                        "failed to create storage for HAR recording: {err}"
                                    );
                                    None
                                }
                            };
                            if reply.send(result).is_err() {
                                tracing::debug!("HAR recording caller dropped its start reply");
                            }
                        }
                        FileRecorderMessage::Record { log, reply } => {
                            let result = self
                                .record_materialized(&mut storage, &mut counter, *log)
                                .await;
                            match result {
                                Ok(path) => {
                                    let extensions = Extensions::new();
                                    extensions.insert(HarFilePath(Arc::new(path)));
                                    _ = reply.send(extensions);
                                }
                                Err(err) => {
                                    tracing::debug!("failed to record materialized HAR log: {err}");
                                    if let Some(storage) = storage.take() {
                                        finish_storage(storage).await;
                                    }
                                }
                            }
                        }
                        FileRecorderMessage::Stop { done } => {
                            cancel_tx.send_replace(true);
                            while let Some(worker) = workers.join_next().await {
                                handle_worker(Some(worker), &mut storage).await;
                            }
                            if let Some(storage) = storage.take() {
                                finish_storage(storage).await;
                            }
                            cancel_tx.send_replace(false);
                            _ = done.send(());
                        }
                    }
                }
            }
        }

        cancel_tx.send_replace(true);
        while let Some(worker) = workers.join_next().await {
            handle_worker(Some(worker), &mut storage).await;
        }
        if let Some(storage) = storage {
            finish_storage(storage).await;
        }
    }

    async fn ensure_storage<'a>(
        &self,
        storage: &'a mut Option<Storage>,
        counter: &mut u64,
        log: &spec::Log,
    ) -> Result<&'a mut Storage, BoxError> {
        if storage.is_none() {
            create_har_parent_dir(&self.dir)
                .await
                .context("create HAR recording dir")?;
            let file_name = format!(
                "{}_{}_{}_{}.har",
                self.prefix,
                self.start_epoch,
                *counter,
                self.start.elapsed().as_secs()
            );
            *counter = counter.saturating_add(1);
            let path = rama_utils::fs::safe_path_in(&self.dir, file_name)
                .await
                .context("validate HAR file path")?;
            *storage = Some(Storage::try_new(path, log).await?);
        }
        storage
            .as_mut()
            .ok_or_else(|| std::io::Error::other("HAR storage was not initialized").into())
    }

    async fn record_materialized(
        &self,
        storage: &mut Option<Storage>,
        counter: &mut u64,
        log: spec::Log,
    ) -> Result<PathBuf, BoxError> {
        if log.pages.as_ref().is_some_and(|pages| !pages.is_empty()) {
            tracing::debug!("HAR pages are not supported by the file recorder");
        }
        let storage = self.ensure_storage(storage, counter, &log).await?;
        for entry in log.entries {
            let artifact = serialize_materialized_entry(self.dir.clone(), entry).await?;
            storage.append_artifact(&artifact).await?;
        }
        Ok(storage.path.clone())
    }
}

async fn serialize_materialized_entry(
    dir: PathBuf,
    entry: spec::Entry,
) -> Result<TempPath, BoxError> {
    tokio::task::spawn_blocking(move || {
        let named = tempfile::Builder::new()
            .prefix(".rama-har-entry-")
            .tempfile_in(dir)
            .context("create private materialized HAR entry artifact")?;
        let (mut file, path) = named.into_parts();
        serde_json::to_writer(&mut file, &entry).context("serialize materialized HAR entry")?;
        file.flush()
            .context("flush materialized HAR entry artifact")?;
        Ok(path)
    })
    .await
    .context("join materialized HAR entry serialization task")?
}

async fn handle_worker(
    worker: Option<Result<Result<TempPath, BoxError>, tokio::task::JoinError>>,
    storage: &mut Option<Storage>,
) {
    let Some(worker) = worker else {
        return;
    };
    let artifact = match worker {
        Ok(Ok(artifact)) => artifact,
        Ok(Err(err)) => {
            tracing::debug!("failed to capture streaming HAR entry: {err}");
            return;
        }
        Err(err) => {
            tracing::debug!("streaming HAR entry task failed: {err}");
            return;
        }
    };

    let Some(storage_ref) = storage.as_mut() else {
        tracing::debug!("discard streaming HAR artifact without active storage");
        return;
    };
    if let Err(err) = storage_ref.append_artifact(&artifact).await {
        tracing::debug!("failed to append streaming HAR entry: {err}");
        if let Some(storage) = storage.take() {
            finish_storage(storage).await;
        }
    }
}

#[derive(Debug)]
struct BodyArtifact {
    path: TempPath,
    size: i64,
    outcome: CaptureOutcome,
    finished_at: Instant,
}

#[derive(Debug)]
struct WebSocketArtifact {
    path: TempPath,
}

type WebSocketCaptureCompletion = oneshot::Receiver<Result<WebSocketArtifact, String>>;

struct FileWebSocketCaptureWriter {
    sender: PollSender<spec::WebSocketMessage>,
}

impl WebSocketCaptureWriter for FileWebSocketCaptureWriter {
    fn poll_ready(&mut self, ctx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        self.sender
            .poll_reserve(ctx)
            .map_err(|err| std::io::Error::other(err).into())
    }

    fn start_record(&mut self, message: spec::WebSocketMessage) -> Result<(), BoxError> {
        self.sender
            .send_item(message)
            .map_err(|err| std::io::Error::other(err).into())
    }
}

async fn create_web_socket_capture(
    dir: PathBuf,
) -> Result<
    (
        WebSocketCapture,
        WebSocketCaptureCompletion,
        WebSocketCaptureCloseHandle,
    ),
    BoxError,
> {
    let (file, path) = create_temp_file(dir, "websocket").await?;
    let (sender, receiver) = mpsc::channel(1);
    let cancellation = CancellationToken::new();
    let capture = WebSocketCapture::new(
        FileWebSocketCaptureWriter {
            sender: PollSender::new(sender),
        },
        {
            let cancellation = cancellation.clone();
            move || cancellation.cancel()
        },
    );
    let closer = capture.close_handle();
    let (done, completion) = oneshot::channel();
    tokio::spawn(async move {
        _ = done.send(write_web_socket_capture(file, path, receiver, cancellation).await);
    });
    Ok((capture, completion, closer))
}

async fn write_web_socket_capture(
    file: File,
    path: TempPath,
    mut receiver: mpsc::Receiver<spec::WebSocketMessage>,
    cancellation: CancellationToken,
) -> Result<WebSocketArtifact, String> {
    let mut writer = BufWriter::new(file);
    let mut has_messages = false;
    let mut cancelled = false;
    loop {
        let message = if cancelled {
            receiver.recv().await
        } else {
            tokio::select! {
                message = receiver.recv() => message,
                () = cancellation.cancelled() => {
                    receiver.close();
                    cancelled = true;
                    continue;
                }
            }
        };
        let Some(message) = message else {
            break;
        };
        if has_messages {
            writer
                .write_all(b",")
                .await
                .map_err(|err| format!("write WebSocket HAR separator: {err}"))?;
        }
        let encoded = serde_json::to_vec(&message)
            .map_err(|err| format!("serialize WebSocket HAR message: {err}"))?;
        writer
            .write_all(&encoded)
            .await
            .map_err(|err| format!("write WebSocket HAR message: {err}"))?;
        has_messages = true;
    }
    writer
        .flush()
        .await
        .map_err(|err| format!("flush WebSocket HAR artifact: {err}"))?;
    drop(writer);
    Ok(WebSocketArtifact { path })
}

async fn capture_http_entry(
    request: HttpRequestCapture,
    mut rx: mpsc::Receiver<CaptureWorkerMessage>,
    dir: PathBuf,
    mut cancel: watch::Receiver<bool>,
    web_socket: Option<(WebSocketCaptureCloseHandle, WebSocketCaptureCompletion)>,
) -> Result<TempPath, BoxError> {
    let (started_date_time, begin, request, mime_type, request_body, _) = request.into_parts();
    let request_capture = spool_body(request_body, dir.clone(), cancel.clone());
    tokio::pin!(request_capture);
    let mut request_artifact = None;

    let command = loop {
        tokio::select! {
            biased;
            result = &mut request_capture, if request_artifact.is_none() => {
                request_artifact = Some(result?);
            }
            command = rx.recv() => break command.unwrap_or(CaptureWorkerMessage::RequestOnly),
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
                    break CaptureWorkerMessage::RequestOnly;
                }
            }
        }
    };

    let is_web_socket = web_socket.is_some();
    let (request_artifact, response, completed_at) = match command {
        CaptureWorkerMessage::Response {
            response,
            headers_at,
        } => {
            let response = *response;
            let (response, body) = response.into_parts();
            let response_capture = spool_body(body, dir.clone(), cancel.clone());
            let (request_artifact, response_artifact) =
                if let Some(request_artifact) = request_artifact {
                    let response_artifact = response_capture.await?;
                    (request_artifact, response_artifact)
                } else {
                    let (request_artifact, response_artifact) =
                        tokio::join!(&mut request_capture, response_capture);
                    (request_artifact?, response_artifact?)
                };
            let completed_at = if is_web_socket {
                // A WebSocket entry measures the HTTP handshake. Its message
                // stream may remain open for hours and must not extend `time`.
                headers_at
            } else {
                request_artifact
                    .finished_at
                    .max(response_artifact.finished_at)
            };
            (
                request_artifact,
                Some((response, response_artifact)),
                completed_at,
            )
        }
        CaptureWorkerMessage::RequestOnly => {
            let request_artifact = match request_artifact {
                Some(artifact) => artifact,
                None => request_capture.await?,
            };
            let completed_at = request_artifact.finished_at;
            (request_artifact, None, completed_at)
        }
    };

    let web_socket = match web_socket {
        Some((closer, completion)) => {
            Some(await_web_socket_capture(closer, completion, cancel.clone()).await?)
        }
        None => None,
    };

    build_entry_artifact(
        dir,
        started_date_time,
        elapsed_millis(begin, completed_at),
        request,
        mime_type,
        request_artifact,
        response,
        web_socket,
    )
    .await
}

async fn await_web_socket_capture(
    closer: WebSocketCaptureCloseHandle,
    mut completion: WebSocketCaptureCompletion,
    mut cancel: watch::Receiver<bool>,
) -> Result<WebSocketArtifact, BoxError> {
    if *cancel.borrow() {
        closer.close();
    } else {
        tokio::select! {
            result = &mut completion => {
                return result
                    .context("WebSocket HAR capture completion dropped")?
                    .map_err(|err| std::io::Error::other(err).into());
            },
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
                    closer.close();
                }
            }
        }
    }
    completion
        .await
        .context("WebSocket HAR capture completion dropped")?
        .map_err(|err| std::io::Error::other(err).into())
}

async fn spool_body(
    mut stream: BodyCaptureStream,
    dir: PathBuf,
    mut cancel: watch::Receiver<bool>,
) -> Result<BodyArtifact, BoxError> {
    let (file, path) = create_temp_file(dir, "body").await?;
    let mut file = BufWriter::new(file);
    let mut size = 0_i64;
    let outcome = loop {
        if *cancel.borrow() {
            if let Some(BodyCaptureEvent::Frame(frame)) = stream.try_next_event()
                && let Ok(data) = frame.into_data()
            {
                file.write_all(&data)
                    .await
                    .context("spool accepted HAR body frame during stop")?;
                size = size.saturating_add(i64::try_from(data.len()).unwrap_or(i64::MAX));
            }
            break CaptureOutcome::Aborted;
        }
        tokio::select! {
            biased;
            event = stream.next_event() => match event {
                Some(BodyCaptureEvent::Frame(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        file.write_all(&data).await.context("spool HAR body frame")?;
                        size = size.saturating_add(i64::try_from(data.len()).unwrap_or(i64::MAX));
                    }
                }
                Some(BodyCaptureEvent::End(outcome)) => break outcome,
                None => break CaptureOutcome::Aborted,
            },
            _ = cancel.changed() => {}
        }
    };
    let finished_at = Instant::now();
    file.flush().await.context("flush HAR body artifact")?;
    drop(file);
    Ok(BodyArtifact {
        path,
        size,
        outcome,
        finished_at,
    })
}

async fn create_temp_file(dir: PathBuf, kind: &'static str) -> Result<(File, TempPath), BoxError> {
    tokio::task::spawn_blocking(move || {
        let named = tempfile::Builder::new()
            .prefix(&format!(".rama-har-{kind}-"))
            .tempfile_in(dir)
            .context("create private HAR artifact")?;
        let (file, path) = named.into_parts();
        Ok((File::from_std(file), path))
    })
    .await
    .context("join HAR artifact creation task")?
}

fn elapsed_millis(begin: Instant, completed_at: Instant) -> i64 {
    completed_at
        .saturating_duration_since(begin)
        .as_millis()
        .min(i64::MAX as u128) as i64
}

#[expect(clippy::too_many_arguments)]
async fn build_entry_artifact(
    dir: PathBuf,
    started_date_time: Timestamp,
    elapsed_time: i64,
    mut request: spec::Request,
    request_mime_type: Option<crate::mime::Mime>,
    request_body: BodyArtifact,
    response: Option<(spec::Response, BodyArtifact)>,
    web_socket: Option<WebSocketArtifact>,
) -> Result<TempPath, BoxError> {
    tokio::task::spawn_blocking(move || {
        request.body_size = request_body.size;
        request.post_data = (request_body.size > 0).then(|| spec::PostData {
            mime_type: request_mime_type,
            params: None,
            text: None,
            comment: None,
        });

        let (response, response_body) = match response {
            Some((mut response, body)) => {
                response.body_size = body.size;
                response.content.size = body.size;
                response.content.text = None;
                response.content.encoding = None;
                (Some(response), Some(body))
            }
            None => (None, None),
        };

        let entry = spec::Entry {
            page_ref: None,
            started_date_time,
            time: elapsed_time,
            request,
            response,
            cache: spec::Cache::default(),
            timings: spec::Timings::default(),
            server_ip_address: None,
            connection: None,
            comment: None,
            web_socket_messages: web_socket.as_ref().map(|_| Vec::new()),
        };

        let named = tempfile::Builder::new()
            .prefix(".rama-har-entry-")
            .tempfile_in(dir)
            .context("create private HAR entry artifact")?;
        let (mut file, path) = named.into_parts();
        write_streaming_entry(
            &mut file,
            &entry,
            &request_body,
            response_body.as_ref(),
            web_socket.as_ref(),
        )?;
        file.flush().context("flush HAR entry artifact")?;
        tracing::trace!(
            request_outcome = ?request_body.outcome,
            response_outcome = ?response_body.as_ref().map(|body| body.outcome),
            "completed streaming HAR entry artifact"
        );
        Ok(path)
    })
    .await
    .context("join HAR entry serialization task")?
}

fn write_streaming_entry(
    writer: &mut impl Write,
    entry: &spec::Entry,
    request_body: &BodyArtifact,
    response_body: Option<&BodyArtifact>,
    web_socket: Option<&WebSocketArtifact>,
) -> Result<(), BoxError> {
    let value = serde_json::to_value(entry).context("serialize HAR entry metadata")?;
    write_json_object(writer, &value, |writer, key, value| match key {
        "request" => {
            write_request(writer, value, request_body)?;
            Ok(true)
        }
        "response" => {
            if let Some(response_body) = response_body {
                write_response(writer, value, response_body)?;
                Ok(true)
            } else {
                Ok(false)
            }
        }
        "_webSocketMessages" => {
            if let Some(web_socket) = web_socket {
                write_web_socket_messages(writer, web_socket)?;
                Ok(true)
            } else {
                Ok(false)
            }
        }
        _ => Ok(false),
    })
}

fn write_web_socket_messages(
    writer: &mut impl Write,
    messages: &WebSocketArtifact,
) -> Result<(), BoxError> {
    writer.write_all(b"[")?;
    let mut file = std::io::BufReader::new(
        safe_open_sync(&messages.path).context("open WebSocket HAR artifact")?,
    );
    std::io::copy(&mut file, writer).context("copy WebSocket HAR messages")?;
    writer.write_all(b"]")?;
    Ok(())
}

fn write_request(
    writer: &mut impl Write,
    request: &Value,
    body: &BodyArtifact,
) -> Result<(), BoxError> {
    write_json_object(writer, request, |writer, key, value| {
        if key == "postData" && body.size > 0 {
            write_json_object(writer, value, |writer, key, _| {
                if key == "text" {
                    write_body_text(writer, body)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            })?;
            Ok(true)
        } else {
            Ok(false)
        }
    })
}

fn write_response(
    writer: &mut impl Write,
    response: &Value,
    body: &BodyArtifact,
) -> Result<(), BoxError> {
    write_json_object(writer, response, |writer, key, value| {
        if key == "content" {
            let is_text = body_is_utf8(&body.path)?;
            write_json_object(writer, value, |writer, key, _value| match key {
                "text" if body.size > 0 => {
                    write_body_text_with_encoding(writer, body, is_text)?;
                    Ok(true)
                }
                "encoding" if body.size > 0 && !is_text => {
                    serde_json::to_writer(writer, "base64")?;
                    Ok(true)
                }
                _ => Ok(false),
            })?;
            Ok(true)
        } else {
            Ok(false)
        }
    })
}

fn write_json_object<W, F>(
    writer: &mut W,
    value: &Value,
    mut override_field: F,
) -> Result<(), BoxError>
where
    W: Write,
    F: FnMut(&mut W, &str, &Value) -> Result<bool, BoxError>,
{
    let object = value
        .as_object()
        .ok_or_else(|| std::io::Error::other("expected serialized HAR object"))?;
    writer.write_all(b"{")?;
    for (index, (key, value)) in object.iter().enumerate() {
        if index > 0 {
            writer.write_all(b",")?;
        }
        serde_json::to_writer(&mut *writer, key)?;
        writer.write_all(b":")?;
        if !override_field(writer, key, value)? {
            serde_json::to_writer(&mut *writer, value)?;
        }
    }
    writer.write_all(b"}")?;
    Ok(())
}

fn write_body_text(writer: &mut impl Write, body: &BodyArtifact) -> Result<(), BoxError> {
    let is_text = body_is_utf8(&body.path)?;
    write_body_text_with_encoding(writer, body, is_text)
}

fn write_body_text_with_encoding(
    writer: &mut impl Write,
    body: &BodyArtifact,
    is_text: bool,
) -> Result<(), BoxError> {
    writer.write_all(b"\"")?;
    let file = safe_open_sync(&body.path).context("open HAR body artifact")?;
    if is_text {
        write_escaped_utf8(writer, file)?;
    } else {
        let mut encoder = base64::write::EncoderWriter::new(&mut *writer, &BASE64);
        std::io::copy(&mut std::io::BufReader::new(file), &mut encoder)
            .context("base64 encode HAR body")?;
        encoder.finish().context("finish base64 HAR body")?;
    }
    writer.write_all(b"\"")?;
    Ok(())
}

fn body_is_utf8(path: &Path) -> Result<bool, BoxError> {
    let mut file = std::io::BufReader::new(
        safe_open_sync(path).context("open HAR body for UTF-8 validation")?,
    );
    let mut buffer = [0_u8; 8192];
    let mut trailing = Vec::with_capacity(4);
    loop {
        let read = file
            .read(&mut buffer)
            .context("read HAR body for UTF-8 validation")?;
        if read == 0 {
            return Ok(trailing.is_empty());
        }
        let mut bytes = Vec::with_capacity(trailing.len() + read);
        bytes.extend_from_slice(&trailing);
        bytes.extend_from_slice(&buffer[..read]);
        trailing.clear();
        if let Err(err) = std::str::from_utf8(&bytes) {
            if err.error_len().is_some() {
                return Ok(false);
            }
            trailing.extend_from_slice(&bytes[err.valid_up_to()..]);
            if trailing.len() > 3 {
                return Ok(false);
            }
        }
    }
}

fn write_escaped_utf8(writer: &mut impl Write, mut file: impl Read) -> Result<(), BoxError> {
    let mut buffer = [0_u8; 8192];
    let mut trailing = Vec::with_capacity(4);
    loop {
        let read = file.read(&mut buffer).context("read UTF-8 HAR body")?;
        if read == 0 {
            if !trailing.is_empty() {
                let fragment = std::str::from_utf8(&trailing)
                    .context("validate trailing UTF-8 HAR body bytes")?;
                write_escaped_fragment(writer, fragment)?;
            }
            return Ok(());
        }
        let mut bytes = Vec::with_capacity(trailing.len() + read);
        bytes.extend_from_slice(&trailing);
        bytes.extend_from_slice(&buffer[..read]);
        trailing.clear();
        match std::str::from_utf8(&bytes) {
            Ok(fragment) => write_escaped_fragment(writer, fragment)?,
            Err(err) if err.error_len().is_none() => {
                let fragment = std::str::from_utf8(&bytes[..err.valid_up_to()])
                    .context("validate complete UTF-8 HAR body prefix")?;
                write_escaped_fragment(writer, fragment)?;
                trailing.extend_from_slice(&bytes[err.valid_up_to()..]);
            }
            Err(err) => return Err(err).context("validate UTF-8 HAR body"),
        }
    }
}

fn write_escaped_fragment(writer: &mut impl Write, fragment: &str) -> Result<(), BoxError> {
    let escaped = serde_json::to_vec(fragment).context("escape UTF-8 HAR body fragment")?;
    writer.write_all(&escaped[1..escaped.len() - 1])?;
    Ok(())
}

async fn create_har_parent_dir(parent: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        let parent = parent.to_owned();
        tokio::task::spawn_blocking(move || builder.create(&parent))
            .await
            .map_err(std::io::Error::other)??;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::fs::create_dir_all(parent).await
    }
}

async fn finish_storage(storage: Storage) {
    let Storage {
        mut file,
        path,
        valid,
        ..
    } = storage;
    if valid {
        let result = async {
            file.write_all(b"]}}").await?;
            file.flush().await
        }
        .await;
        match result {
            Ok(()) => return,
            Err(err) => tracing::debug!("failed to finish HAR file: {err}"),
        }
    }

    drop(file);
    if let Err(err) = tokio::fs::remove_file(path).await {
        tracing::debug!("failed to remove invalid HAR file: {err}");
    }
}

impl Default for FileRecorder {
    fn default() -> Self {
        Self::new(
            std::env::temp_dir().join("rama").join("har_recordings"),
            format!(
                "rama_{}_recording",
                rama_utils::info::VERSION.replace('.', "_")
            ),
        )
    }
}

impl FileRecorder {
    /// Create a recorder for the given directory and filename prefix.
    ///
    /// Construction does not require an active Tokio runtime. The recorder's
    /// worker starts lazily when its first asynchronous operation is polled.
    #[must_use]
    pub fn new(dir: PathBuf, prefix: String) -> Self {
        let (tx, rx) = mpsc::channel(match std::thread::available_parallelism() {
            Ok(parallelism) => parallelism.get(),
            Err(_) => 1,
        });
        Self {
            tx,
            task: Arc::new(FileRecorderTaskStarter {
                once: Once::new(),
                task: Mutex::new(Some(FileRecorderTask::new(rx, dir, prefix))),
            }),
        }
    }

    fn start_task(&self) {
        self.task.once.call_once(|| {
            let task = self.task.task.lock().take();
            if let Some(task) = task {
                tokio::spawn(task.run());
            }
        });
    }
}

impl RecorderSession for FileRecorderSession {
    fn web_socket_capture(&self) -> Option<WebSocketCapture> {
        self.web_socket_capture.clone()
    }

    async fn record_response(self, response: HttpResponseCapture) -> Option<Extensions> {
        if let Err(err) = self
            .tx
            .send(CaptureWorkerMessage::Response {
                response: Box::new(response),
                headers_at: Instant::now(),
            })
            .await
        {
            if let Some(capture) = &self.web_socket_capture {
                capture.close();
            }
            tracing::debug!("failed to attach response to HAR capture worker: {err}");
            return None;
        }
        let extensions = Extensions::new();
        extensions.insert(self.path);
        Some(extensions)
    }

    async fn record_request_only(self) -> Option<Extensions> {
        if let Some(capture) = &self.web_socket_capture {
            capture.close();
        }
        if let Err(err) = self.tx.send(CaptureWorkerMessage::RequestOnly).await {
            tracing::debug!("failed to finish request-only HAR capture: {err}");
            return None;
        }
        let extensions = Extensions::new();
        extensions.insert(self.path);
        Some(extensions)
    }
}

impl StreamingRecorder for FileRecorder {
    type Session = FileRecorderSession;

    async fn start_http_recording(&self, request: HttpRequestCapture) -> Option<Self::Session> {
        self.start_task();
        let (reply, response) = oneshot::channel();
        if let Err(err) = self
            .tx
            .send(FileRecorderMessage::StartHttp {
                request: Box::new(request),
                reply,
            })
            .await
        {
            tracing::debug!("failed to start streaming HAR recording: {err}");
            return None;
        }
        response
            .await
            .inspect_err(|err| tracing::debug!("HAR start reply failed: {err}"))
            .ok()
            .flatten()
    }
}

impl Recorder for FileRecorder {
    async fn record(&self, log: spec::Log) -> Option<Extensions> {
        self.start_task();
        let (reply, response) = oneshot::channel();
        if let Err(err) = self
            .tx
            .send(FileRecorderMessage::Record {
                log: Box::new(log),
                reply,
            })
            .await
        {
            tracing::debug!("failed to send materialized HAR log to recorder: {err}");
            return None;
        }
        response
            .await
            .inspect_err(|err| tracing::debug!("HAR record reply failed: {err}"))
            .ok()
    }

    async fn stop_record(&self) {
        self.start_task();
        let (done, response) = oneshot::channel();
        if let Err(err) = self.tx.send(FileRecorderMessage::Stop { done }).await {
            tracing::debug!("failed to send stop to HAR recorder: {err}");
            return;
        }
        if let Err(err) = response.await {
            tracing::debug!("failed to await HAR recorder stop: {err}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_recorder_can_be_constructed_without_a_runtime() {
        let recorder = FileRecorder::default();
        assert!(recorder.task.task.lock().is_some());
    }

    #[tokio::test]
    async fn stop_record_waits_until_the_har_file_is_complete() {
        let dir = tempfile::tempdir().unwrap();
        let recorder = FileRecorder::new(dir.path().to_owned(), "recording".to_owned());

        let extensions = recorder.record(spec::Log::default()).await.unwrap();
        let path = extensions.get_ref::<HarFilePath>().unwrap().to_owned();

        recorder.stop_record().await;

        let bytes = tokio::fs::read(path.as_ref()).await.unwrap();
        serde_json::from_slice::<spec::LogFile>(&bytes).unwrap();
    }

    #[tokio::test]
    async fn rollback_keeps_the_last_complete_har_entry_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rollback.har");
        let artifact = dir.path().join("entry.json");
        tokio::fs::write(&artifact, br#"{"marker":true}"#)
            .await
            .unwrap();
        let mut storage = Storage::try_new(path.clone(), &spec::Log::default())
            .await
            .unwrap();
        storage.append_artifact(&artifact).await.unwrap();
        let checkpoint = storage.valid_position;

        storage.file.write_all(b",{\"truncated\":").await.unwrap();
        storage.valid = false;
        storage.rollback(checkpoint).await.unwrap();
        storage.valid = true;
        finish_storage(storage).await;

        let value: Value = serde_json::from_slice(&tokio::fs::read(path).await.unwrap()).unwrap();
        assert_eq!(
            value["log"]["entries"],
            serde_json::json!([{"marker": true}])
        );
    }
}
