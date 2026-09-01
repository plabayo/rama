use super::{
    BodyCaptureStream, HttpRequestCapture, HttpResponseCapture, LogMetaInfo, Recorder,
    RecorderSession, StreamingRecorder, WebSocketCapture, WebSocketCaptureCloseHandle,
    WebSocketCaptureRecorder,
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
    fs::{
        CreatedFilePermissions, OpenOptions, OpenOptionsSync, TempPath, TempPathCleanup, safe_open,
        safe_open_sync,
    },
    time::now_unix,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{BufRead, Read, SeekFrom, Write};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Once};
use tokio::fs::File;
use tokio::io::{AsyncSeekExt, AsyncWriteExt, BufWriter};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio::time::Instant;
use uuid::Uuid;

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
    output: FileRecorderOutput,
    start: Instant,
    start_epoch: i64,
    log_meta_info: LogMetaInfo,
}

type CaptureWorkerResult = (u64, Result<TempPath, BoxError>);

#[derive(Debug)]
enum FileRecorderOutput {
    Generated { prefix: String },
    Exact { file_name: OsString },
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
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::other("HAR file path has no parent"))?;
        let file_name = path
            .file_name()
            .ok_or_else(|| std::io::Error::other("HAR file path has no file name"))?;
        create_har_parent_dir(parent)
            .await
            .context("create HAR file parent dir")?;
        // Archives can contain credentials, cookies, and bodies. Apply 0600 at
        // creation on Unix so their bytes are never briefly world-readable.
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .created_file_permissions(CreatedFilePermissions::OwnerReadWrite)
            .jail(parent)
            .open(file_name)
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
                    return Err(rollback_err)
                        .context_field("append_error", err)
                        .context("rollback failed after appending HAR artifact");
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
    fn new(
        rx: mpsc::Receiver<FileRecorderMessage>,
        dir: PathBuf,
        output: FileRecorderOutput,
        log_meta_info: LogMetaInfo,
    ) -> Self {
        Self {
            rx,
            dir,
            output,
            start: Instant::now(),
            start_epoch: now_unix(),
            log_meta_info,
        }
    }

    async fn run(mut self) {
        let mut storage = None;
        let mut counter = 0_u64;
        let mut workers: JoinSet<CaptureWorkerResult> = JoinSet::new();
        let mut next_sequence = 0_u64;
        let mut next_sequence_to_write = 0_u64;
        let mut completed = BTreeMap::new();
        let (cancel_tx, _) = watch::channel(false);
        let (temp_cleanup, temp_cleanup_worker) = TempPathCleanup::new();
        let temp_cleanup_task = rama_core::rt::spawn(temp_cleanup_worker.run());

        loop {
            tokio::select! {
                worker = workers.join_next(), if !workers.is_empty() => {
                    if handle_worker(
                        worker,
                        &mut storage,
                        &mut completed,
                        &mut next_sequence_to_write,
                    ).await {
                        reset_failed_generation(
                            &cancel_tx,
                            &mut workers,
                            &mut storage,
                            &mut completed,
                            next_sequence,
                            &mut next_sequence_to_write,
                        ).await;
                    }
                }
                message = self.rx.recv() => {
                    let Some(message) = message else {
                        break;
                    };
                    match message {
                        FileRecorderMessage::StartHttp { request, reply } => {
                            let log: spec::Log = self.log_meta_info.clone().into();
                            let result = match self
                                .ensure_storage(&mut storage, &mut counter, &log)
                                .await
                            {
                                Ok(storage_ref) => {
                                    let path = HarFilePath(Arc::new(storage_ref.path.clone()));
                                    let (tx, rx) = mpsc::channel(1);
                                    let web_socket = if request.web_socket {
                                        match create_web_socket_capture(
                                            self.dir.clone(),
                                            temp_cleanup.clone(),
                                        )
                                        .await
                                        {
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
                                    let sequence = next_sequence;
                                    next_sequence = next_sequence.saturating_add(1);
                                    let dir = self.dir.clone();
                                    let temp_cleanup = temp_cleanup.clone();
                                    let cancel = cancel_tx.subscribe();
                                    workers.spawn(async move {
                                        (
                                            sequence,
                                            capture_http_entry(
                                                *request,
                                                rx,
                                                dir,
                                                temp_cleanup,
                                                cancel,
                                                web_socket,
                                            )
                                            .await,
                                        )
                                    });
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
                                .record_materialized(
                                    &mut storage,
                                    &mut counter,
                                    *log,
                                    temp_cleanup.clone(),
                                )
                                .await;
                            match result {
                                Ok(path) => {
                                    let extensions = Extensions::new();
                                    extensions.insert(HarFilePath(Arc::new(path)));
                                    _ = reply.send(extensions);
                                }
                                Err(err) => {
                                    tracing::debug!("failed to record materialized HAR log: {err}");
                                    reset_failed_generation(
                                        &cancel_tx,
                                        &mut workers,
                                        &mut storage,
                                        &mut completed,
                                        next_sequence,
                                        &mut next_sequence_to_write,
                                    ).await;
                                }
                            }
                        }
                        FileRecorderMessage::Stop { done } => {
                            cancel_tx.send_replace(true);
                            while let Some(worker) = workers.join_next().await {
                                if handle_worker(
                                    Some(worker),
                                    &mut storage,
                                    &mut completed,
                                    &mut next_sequence_to_write,
                                ).await
                                    && let Some(storage) = storage.take()
                                {
                                    finish_storage(storage).await;
                                }
                            }
                            if let Some(storage) = storage.take() {
                                finish_storage(storage).await;
                            }
                            completed.clear();
                            next_sequence_to_write = next_sequence;
                            cancel_tx.send_replace(false);
                            temp_cleanup.flush().await;
                            _ = done.send(());
                        }
                    }
                }
            }
        }

        cancel_tx.send_replace(true);
        while let Some(worker) = workers.join_next().await {
            if handle_worker(
                Some(worker),
                &mut storage,
                &mut completed,
                &mut next_sequence_to_write,
            )
            .await
                && let Some(storage) = storage.take()
            {
                finish_storage(storage).await;
            }
        }
        if let Some(storage) = storage {
            finish_storage(storage).await;
        }
        completed.clear();
        temp_cleanup.flush().await;
        drop(temp_cleanup);
        _ = temp_cleanup_task.await;
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
            let file_name = match &self.output {
                FileRecorderOutput::Generated { prefix } => {
                    let file_name = format!(
                        "{}_{}_{}_{}.har",
                        prefix,
                        self.start_epoch,
                        *counter,
                        self.start.elapsed().as_secs()
                    );
                    *counter = counter.saturating_add(1);
                    file_name.into()
                }
                FileRecorderOutput::Exact { file_name } => file_name.clone(),
            };
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
        temp_cleanup: TempPathCleanup,
    ) -> Result<PathBuf, BoxError> {
        if log.pages.as_ref().is_some_and(|pages| !pages.is_empty()) {
            tracing::debug!("HAR pages are not supported by the file recorder");
        }
        let storage = self.ensure_storage(storage, counter, &log).await?;
        for entry in log.entries {
            let artifact =
                serialize_materialized_entry(self.dir.clone(), entry, temp_cleanup.clone()).await?;
            storage.append_artifact(&artifact).await?;
        }
        Ok(storage.path.clone())
    }
}

async fn serialize_materialized_entry(
    dir: PathBuf,
    entry: spec::Entry,
    temp_cleanup: TempPathCleanup,
) -> Result<TempPath, BoxError> {
    tokio::task::spawn_blocking(move || {
        let (path, mut file) = create_temp_file_sync(&dir, "entry", temp_cleanup)
            .context("create private materialized HAR entry artifact")?;
        serde_json::to_writer(&mut file, &entry).context("serialize materialized HAR entry")?;
        file.flush()
            .context("flush materialized HAR entry artifact")?;
        Ok(path)
    })
    .await
    .context("join materialized HAR entry serialization task")?
}

async fn handle_worker(
    worker: Option<Result<CaptureWorkerResult, tokio::task::JoinError>>,
    storage: &mut Option<Storage>,
    completed: &mut BTreeMap<u64, Option<TempPath>>,
    next_sequence_to_write: &mut u64,
) -> bool {
    let Some(worker) = worker else {
        return false;
    };
    let (sequence, artifact) = match worker {
        Ok((sequence, Ok(artifact))) => (sequence, Some(artifact)),
        Ok((sequence, Err(err))) => {
            tracing::debug!("failed to capture streaming HAR entry: {err}");
            (sequence, None)
        }
        Err(err) => {
            tracing::debug!("streaming HAR entry task failed: {err}");
            // A join failure does not contain the sequence returned by the
            // worker, so the current generation can no longer be ordered.
            return true;
        }
    };

    if completed.insert(sequence, artifact).is_some() {
        tracing::debug!(sequence, "duplicate streaming HAR entry sequence");
        return true;
    }

    while let Some(artifact) = completed.remove(next_sequence_to_write) {
        *next_sequence_to_write = next_sequence_to_write.saturating_add(1);
        let Some(artifact) = artifact else {
            continue;
        };
        let Some(storage_ref) = storage.as_mut() else {
            tracing::debug!("discard streaming HAR artifact without active storage");
            continue;
        };
        if let Err(err) = storage_ref.append_artifact(&artifact).await {
            tracing::debug!("failed to append streaming HAR entry: {err}");
            return true;
        }
    }
    false
}

async fn reset_failed_generation(
    cancel: &watch::Sender<bool>,
    workers: &mut JoinSet<CaptureWorkerResult>,
    storage: &mut Option<Storage>,
    completed: &mut BTreeMap<u64, Option<TempPath>>,
    next_sequence: u64,
    next_sequence_to_write: &mut u64,
) {
    cancel.send_replace(true);
    if let Some(storage) = storage.take() {
        finish_storage(storage).await;
    }
    while workers.join_next().await.is_some() {}
    completed.clear();
    *next_sequence_to_write = next_sequence;
    cancel.send_replace(false);
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
    last_activity_at: Option<Instant>,
    closed_at: Instant,
}

type WebSocketCaptureCompletion = oneshot::Receiver<Result<WebSocketArtifact, BoxError>>;

struct RecordedWebSocketMessage {
    message: spec::WebSocketMessage,
    observed_at: Instant,
}

struct FileWebSocketCaptureRecorder {
    sender: mpsc::Sender<RecordedWebSocketMessage>,
}

impl WebSocketCaptureRecorder for FileWebSocketCaptureRecorder {
    async fn record(&self, message: spec::WebSocketMessage) -> Result<(), BoxError> {
        self.sender
            .send(RecordedWebSocketMessage {
                message,
                observed_at: Instant::now(),
            })
            .await
            .map_err(|err| std::io::Error::other(err).into())
    }
}

async fn create_web_socket_capture(
    dir: PathBuf,
    temp_cleanup: TempPathCleanup,
) -> Result<
    (
        WebSocketCapture,
        WebSocketCaptureCompletion,
        WebSocketCaptureCloseHandle,
    ),
    BoxError,
> {
    let (path, file) = create_temp_file(dir, "websocket", temp_cleanup).await?;
    let (sender, receiver) = mpsc::channel(1);
    let (closed_at, closed_at_rx) = watch::channel(None);
    let capture = WebSocketCapture::new(FileWebSocketCaptureRecorder { sender }, {
        move || {
            closed_at.send_replace(Some(Instant::now()));
        }
    });
    let closer = capture.close_handle();
    let (done, completion) = oneshot::channel();
    rama_core::rt::spawn(async move {
        _ = done.send(write_web_socket_capture(file, path, receiver, closed_at_rx).await);
    });
    Ok((capture, completion, closer))
}

async fn write_web_socket_capture(
    file: File,
    path: TempPath,
    mut receiver: mpsc::Receiver<RecordedWebSocketMessage>,
    mut closed_at: watch::Receiver<Option<Instant>>,
) -> Result<WebSocketArtifact, BoxError> {
    let mut writer = BufWriter::new(file);
    let mut has_messages = false;
    let mut cancelled = false;
    let mut last_activity_at = None;
    loop {
        let message = if cancelled {
            receiver.recv().await
        } else {
            tokio::select! {
                message = receiver.recv() => message,
                changed = closed_at.changed() => {
                    if changed.is_err() || closed_at.borrow().is_some() {
                        receiver.close();
                        cancelled = true;
                    }
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
                .context("write WebSocket HAR separator")?;
        }
        let encoded =
            serde_json::to_vec(&message.message).context("serialize WebSocket HAR message")?;
        writer
            .write_all(&encoded)
            .await
            .context("write WebSocket HAR message")?;
        has_messages = true;
        last_activity_at = Some(message.observed_at);
    }
    writer
        .flush()
        .await
        .context("flush WebSocket HAR artifact")?;
    drop(writer);
    Ok(WebSocketArtifact {
        path,
        last_activity_at,
        closed_at: closed_at.borrow().unwrap_or_else(Instant::now),
    })
}

async fn capture_http_entry(
    request: HttpRequestCapture,
    mut rx: mpsc::Receiver<CaptureWorkerMessage>,
    dir: PathBuf,
    temp_cleanup: TempPathCleanup,
    mut cancel: watch::Receiver<bool>,
    web_socket: Option<(WebSocketCaptureCloseHandle, WebSocketCaptureCompletion)>,
) -> Result<TempPath, BoxError> {
    let HttpRequestCapture {
        started_date_time,
        begin,
        request,
        body_mime_type,
        body: request_body,
        web_socket: _,
    } = request;
    let request_capture = spool_body(
        request_body,
        dir.clone(),
        temp_cleanup.clone(),
        cancel.clone(),
    );
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
    let (request_artifact, response, mut completed_at) = match command {
        CaptureWorkerMessage::Response {
            response,
            headers_at,
        } => {
            let HttpResponseCapture { response, body } = *response;
            let response_capture =
                spool_body(body, dir.clone(), temp_cleanup.clone(), cancel.clone());
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
            let (artifact, stopped) =
                await_web_socket_capture(closer, completion, cancel.clone()).await?;
            completed_at = if stopped {
                artifact.last_activity_at.unwrap_or(completed_at)
            } else {
                artifact.closed_at.max(completed_at)
            };
            Some(artifact)
        }
        None => None,
    };

    build_entry_artifact(
        dir,
        started_date_time,
        elapsed_millis(begin, completed_at),
        request,
        body_mime_type,
        request_artifact,
        response,
        web_socket,
        temp_cleanup,
    )
    .await
}

async fn await_web_socket_capture(
    closer: WebSocketCaptureCloseHandle,
    mut completion: WebSocketCaptureCompletion,
    mut cancel: watch::Receiver<bool>,
) -> Result<(WebSocketArtifact, bool), BoxError> {
    if *cancel.borrow() {
        closer.close();
    } else {
        tokio::select! {
            biased;
            result = &mut completion => {
                return result
                    .context("WebSocket HAR capture completion dropped")?
                    .map(|artifact| (artifact, false));
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
        .map(|artifact| (artifact, true))
}

async fn spool_body(
    mut stream: BodyCaptureStream,
    dir: PathBuf,
    temp_cleanup: TempPathCleanup,
    mut cancel: watch::Receiver<bool>,
) -> Result<BodyArtifact, BoxError> {
    let (path, file) = create_temp_file(dir, "body", temp_cleanup).await?;
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

async fn create_temp_file(
    dir: PathBuf,
    kind: &'static str,
    temp_cleanup: TempPathCleanup,
) -> Result<(TempPath, File), BoxError> {
    // Keep the path guard first so destructuring callers drop the file before
    // the guard queues its removal, including while unwinding an error.
    let file_name = format!(".rama-har-{kind}-{}", Uuid::new_v4().as_simple());
    let path = dir.join(&file_name);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .created_file_permissions(CreatedFilePermissions::OwnerReadWrite)
        .jail(&dir)
        .open(file_name)
        .await
        .context("create private HAR artifact")?;
    Ok((TempPath::new(path, temp_cleanup), file))
}

fn create_temp_file_sync(
    dir: &Path,
    kind: &'static str,
    temp_cleanup: TempPathCleanup,
) -> Result<(TempPath, std::fs::File), BoxError> {
    // Keep the same drop order for blocking serializer tasks.
    let file_name = format!(".rama-har-{kind}-{}", Uuid::new_v4().as_simple());
    let path = dir.join(&file_name);
    let file = OpenOptionsSync::new()
        .write(true)
        .create_new(true)
        .created_file_permissions(CreatedFilePermissions::OwnerReadWrite)
        .jail(dir)
        .open(file_name)
        .context("create private HAR artifact")?;
    Ok((TempPath::new(path, temp_cleanup), file))
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
    temp_cleanup: TempPathCleanup,
) -> Result<TempPath, BoxError> {
    tokio::task::spawn_blocking(move || {
        // Keep the body-bearing fields present as null placeholders. The
        // streaming JSON writer below replaces their serialized values with
        // spooled body data without materializing those bodies in memory.
        request.body_size = request_body.size;
        let form_urlencoded = request_mime_type
            .as_ref()
            .is_some_and(|mime| mime.subtype() == crate::mime::WWW_FORM_URLENCODED);
        request.post_data = (request_body.size > 0).then(|| spec::PostData {
            mime_type: request_mime_type,
            params: form_urlencoded.then(Vec::new),
            text: None,
            comment: None,
        });

        let (response, response_body) = match response {
            Some((mut response, body)) => {
                response.body_size = body.size;
                response.content.size = body.size;
                response.content.text = None;
                response.content.encoding = None;
                (response, Some(body))
            }
            None => (
                spec::Response {
                    status: 0,
                    status_text: Some("".into()),
                    http_version: request.http_version.clone(),
                    cookies: Vec::new(),
                    headers: Vec::new(),
                    content: spec::Content {
                        size: 0,
                        compression: None,
                        mime_type: Some(crate::mime::APPLICATION_OCTET_STREAM),
                        text: None,
                        encoding: None,
                        comment: None,
                    },
                    redirect_url: Some("".into()),
                    headers_size: -1,
                    body_size: -1,
                    comment: None,
                },
                None,
            ),
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
            resource_type: web_socket.as_ref().map(|_| "websocket".into()),
            web_socket_messages: web_socket.as_ref().map(|_| Vec::new()),
        };

        let (path, mut file) = create_temp_file_sync(&dir, "entry", temp_cleanup)
            .context("create private HAR entry artifact")?;
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
            write_json_object(writer, value, |writer, key, _| match key {
                "params" if value["params"].is_array() => {
                    write_form_params(writer, body)?;
                    Ok(true)
                }
                "text" => {
                    write_body_text(writer, body)?;
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

fn write_form_params(writer: &mut impl Write, body: &BodyArtifact) -> Result<(), BoxError> {
    let file = safe_open_sync(&body.path).context("open form-encoded HAR body artifact")?;
    let mut reader = std::io::BufReader::new(file);
    let mut segment = Vec::new();
    let mut first = true;
    writer.write_all(b"[")?;
    loop {
        segment.clear();
        let read = reader
            .read_until(b'&', &mut segment)
            .context("read form-encoded HAR body")?;
        if read == 0 {
            break;
        }
        if segment.last() == Some(&b'&') {
            segment.pop();
        }
        let pairs: Vec<(String, String)> = serde_html_form::from_bytes(&segment)
            .context("decode form-encoded HAR body parameter")?;
        for (name, value) in pairs {
            if !first {
                writer.write_all(b",")?;
            }
            serde_json::to_writer(
                &mut *writer,
                &spec::PostParam {
                    name: name.into(),
                    value: Some(value.into()),
                    file_name: None,
                    content_type: None,
                    comment: None,
                },
            )?;
            first = false;
        }
    }
    writer.write_all(b"]")?;
    Ok(())
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
        Self::new_with_log_meta_info(dir, prefix, LogMetaInfo::default())
    }

    /// Create a recorder that writes to one exact file path.
    ///
    /// The parent directory is created when recording starts. Starting a new
    /// recording after [`Recorder::stop_record`] replaces the same file.
    pub fn try_new_at(path: impl AsRef<Path>) -> Result<Self, BoxError> {
        Self::try_new_at_with_log_meta_info(path, LogMetaInfo::default())
    }

    /// Create an exact-path recorder with explicit HAR log metadata.
    pub fn try_new_at_with_log_meta_info(
        path: impl AsRef<Path>,
        log_meta_info: LogMetaInfo,
    ) -> Result<Self, BoxError> {
        let path = path.as_ref();
        let file_name = path
            .file_name()
            .filter(|file_name| !file_name.is_empty())
            .ok_or_else(|| std::io::Error::other("HAR file path has no file name"))?
            .to_owned();
        let dir = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_owned();
        Ok(Self::new_with_output(
            dir,
            FileRecorderOutput::Exact { file_name },
            log_meta_info,
        ))
    }

    /// Create a recorder with explicit HAR log metadata.
    ///
    /// Construction does not require an active Tokio runtime. The recorder's
    /// worker starts lazily when its first asynchronous operation is polled.
    #[must_use]
    pub fn new_with_log_meta_info(
        dir: PathBuf,
        prefix: String,
        log_meta_info: LogMetaInfo,
    ) -> Self {
        Self::new_with_output(dir, FileRecorderOutput::Generated { prefix }, log_meta_info)
    }

    fn new_with_output(
        dir: PathBuf,
        output: FileRecorderOutput,
        log_meta_info: LogMetaInfo,
    ) -> Self {
        let (tx, rx) = mpsc::channel(match std::thread::available_parallelism() {
            Ok(parallelism) => parallelism.get(),
            Err(_) => 1,
        });
        Self {
            tx,
            task: Arc::new(FileRecorderTaskStarter {
                once: Once::new(),
                task: Mutex::new(Some(FileRecorderTask::new(rx, dir, output, log_meta_info))),
            }),
        }
    }

    fn start_task(&self) {
        self.task.once.call_once(|| {
            let task = self.task.task.lock().take();
            if let Some(task) = task {
                rama_core::rt::spawn(task.run());
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
    async fn stop_before_any_recording_is_a_no_op() {
        let dir = rama_utils::fs::tempdir().unwrap();
        let recorder = FileRecorder::new(dir.path().to_owned(), "unused".to_owned());

        tokio::time::timeout(std::time::Duration::from_secs(2), recorder.stop_record())
            .await
            .unwrap();

        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn exact_path_recorder_writes_the_requested_file() {
        let dir = rama_utils::fs::tempdir().unwrap();
        let path = dir.path().join("nested").join("capture.har");
        let recorder = FileRecorder::try_new_at(path.clone()).unwrap();

        let extensions = recorder.record(spec::Log::default()).await.unwrap();
        assert_eq!(extensions.get_ref::<HarFilePath>().unwrap().as_ref(), path);
        recorder.stop_record().await;

        let bytes = tokio::fs::read(&path).await.unwrap();
        serde_json::from_slice::<spec::LogFile>(&bytes).unwrap();
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
    }

    #[tokio::test]
    async fn dropping_temp_path_defers_file_io_to_cleanup_worker() {
        let dir = rama_utils::fs::tempdir().unwrap();
        let path = dir.path().join("artifact");
        tokio::fs::write(&path, b"temporary").await.unwrap();
        let (temp_cleanup, temp_cleanup_worker) = TempPathCleanup::new();

        drop(TempPath::new(path.clone(), temp_cleanup.clone()));
        assert!(path.exists(), "TempPath::drop must not perform file I/O");

        let temp_cleanup_task = tokio::spawn(temp_cleanup_worker.run());
        temp_cleanup.flush().await;
        assert!(!path.exists());
        drop(temp_cleanup);
        temp_cleanup_task.await.unwrap();
    }

    #[tokio::test]
    async fn stop_record_waits_until_the_har_file_is_complete() {
        let dir = rama_utils::fs::tempdir().unwrap();
        let recorder = FileRecorder::new(dir.path().to_owned(), "recording".to_owned());

        let extensions = recorder.record(spec::Log::default()).await.unwrap();
        let path = extensions.get_ref::<HarFilePath>().unwrap().to_owned();

        recorder.stop_record().await;

        let bytes = tokio::fs::read(path.as_ref()).await.unwrap();
        serde_json::from_slice::<spec::LogFile>(&bytes).unwrap();
    }

    #[tokio::test]
    async fn rollback_keeps_the_last_complete_har_entry_valid() {
        let dir = rama_utils::fs::tempdir().unwrap();
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

    #[tokio::test]
    async fn completed_workers_are_written_in_request_start_order() {
        let dir = rama_utils::fs::tempdir().unwrap();
        let (temp_cleanup, temp_cleanup_worker) = TempPathCleanup::new();
        let temp_cleanup_task = tokio::spawn(temp_cleanup_worker.run());
        let path = dir.path().join("ordered.har");
        let mut storage = Some(
            Storage::try_new(path.clone(), &spec::Log::default())
                .await
                .unwrap(),
        );
        let mut completed = BTreeMap::new();
        let mut next_sequence_to_write = 0;

        let (first_path, mut first) =
            create_temp_file_sync(dir.path(), "first", temp_cleanup.clone()).unwrap();
        first.write_all(br#"{"sequence":0}"#).unwrap();
        first.flush().unwrap();
        drop(first);
        let (second_path, mut second) =
            create_temp_file_sync(dir.path(), "second", temp_cleanup.clone()).unwrap();
        second.write_all(br#"{"sequence":1}"#).unwrap();
        second.flush().unwrap();
        drop(second);

        assert!(
            !handle_worker(
                Some(Ok((1, Ok(second_path)))),
                &mut storage,
                &mut completed,
                &mut next_sequence_to_write,
            )
            .await
        );
        assert!(
            !storage.as_ref().unwrap().has_entries,
            "a later capture must wait for the earlier capture"
        );
        assert!(
            !handle_worker(
                Some(Ok((0, Ok(first_path)))),
                &mut storage,
                &mut completed,
                &mut next_sequence_to_write,
            )
            .await
        );
        assert!(completed.is_empty());
        assert_eq!(next_sequence_to_write, 2);

        finish_storage(storage.take().unwrap()).await;
        temp_cleanup.flush().await;
        let value: Value = serde_json::from_slice(&tokio::fs::read(path).await.unwrap()).unwrap();
        assert_eq!(
            value["log"]["entries"],
            serde_json::json!([{"sequence": 0}, {"sequence": 1}])
        );
        drop(temp_cleanup);
        temp_cleanup_task.await.unwrap();
    }

    #[tokio::test]
    async fn failed_storage_generation_discards_its_remaining_workers() {
        let dir = rama_utils::fs::tempdir().unwrap();
        let (temp_cleanup, temp_cleanup_worker) = TempPathCleanup::new();
        let temp_cleanup_task = tokio::spawn(temp_cleanup_worker.run());
        let old_path = dir.path().join("old.har");
        let fresh_path = dir.path().join("fresh.har");
        let mut storage = Some(
            Storage::try_new(old_path.clone(), &spec::Log::default())
                .await
                .unwrap(),
        );
        let missing_artifact =
            TempPath::new(dir.path().join("missing-entry.json"), temp_cleanup.clone());
        let mut completed = BTreeMap::new();
        let mut next_sequence_to_write = 0;

        assert!(
            handle_worker(
                Some(Ok((0, Ok(missing_artifact)))),
                &mut storage,
                &mut completed,
                &mut next_sequence_to_write,
            )
            .await,
            "an append failure invalidates the active generation"
        );

        let (artifact_path, mut artifact) =
            create_temp_file_sync(dir.path(), "late-entry", temp_cleanup.clone()).unwrap();
        artifact.write_all(br#"{"late":true}"#).unwrap();
        artifact.flush().unwrap();
        drop(artifact);
        let artifact_path_copy = artifact_path.to_path_buf();
        let mut workers = JoinSet::new();
        workers.spawn(async move { (1, Ok::<_, BoxError>(artifact_path)) });
        let (cancel, _) = watch::channel(false);

        reset_failed_generation(
            &cancel,
            &mut workers,
            &mut storage,
            &mut completed,
            2,
            &mut next_sequence_to_write,
        )
        .await;
        temp_cleanup.flush().await;

        assert!(storage.is_none());
        assert!(workers.is_empty());
        assert!(completed.is_empty());
        assert_eq!(next_sequence_to_write, 2);
        assert!(!artifact_path_copy.exists());

        finish_storage(
            Storage::try_new(fresh_path.clone(), &spec::Log::default())
                .await
                .unwrap(),
        )
        .await;
        for path in [old_path, fresh_path] {
            let log: spec::LogFile =
                serde_json::from_slice(&tokio::fs::read(path).await.unwrap()).unwrap();
            assert!(
                log.log.entries.is_empty(),
                "a worker from the failed generation must not reach another HAR file"
            );
        }
        drop(temp_cleanup);
        temp_cleanup_task.await.unwrap();
    }
}
