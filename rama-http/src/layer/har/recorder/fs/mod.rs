use super::{
    HttpRequestCapture, HttpResponseCapture, LogMetaInfo, Recorder, RecorderSession,
    StreamingRecorder, WebSocketCapture,
};
use crate::{CaptureOutcome, layer::har::spec};
use parking_lot::Mutex;
use rama_core::{
    error::{BoxError, ErrorContext},
    extensions::{Extension, Extensions},
    telemetry::tracing,
};
use rama_utils::{
    fs::{CreatedFilePermissions, OpenOptions, TempPath, TempPathCleanup, safe_open},
    time::now_unix,
};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    io::{SeekFrom, Write},
    ops::Deref,
    path::{Path, PathBuf},
    sync::{Arc, Once},
};
use tokio::{
    fs::File,
    io::{AsyncSeekExt, AsyncWriteExt},
    sync::{mpsc, oneshot, watch},
    task::JoinSet,
    time::Instant,
};

mod artifact;
use artifact::{create_temp_file, create_temp_file_sync};
mod capture;
use capture::{capture_http_entry, create_web_socket_capture};
mod entry;
use entry::build_entry_artifact;

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

fn elapsed_millis(begin: Instant, completed_at: Instant) -> i64 {
    completed_at
        .saturating_duration_since(begin)
        .as_millis()
        .min(i64::MAX as u128) as i64
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
mod tests;
