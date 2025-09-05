use super::Recorder;
use crate::layer::har::spec;
use rama_core::telemetry::tracing;
use rama_error::{ErrorContext, OpaqueError};
use rama_http_types::dep::http;
use std::io::Write;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

/// Recorder that can create a file-per-session
/// for actual HAR Recording.
#[derive(Debug, Clone)]
pub struct FileRecorder {
    tx: mpsc::Sender<FileRecorderMessage>,
}

#[derive(Debug, Clone)]
/// Path to (HAR) file that the [`FileRecorder`] is recording into.
///
/// Inserted into the response extensions.
pub struct HarFilePath(Arc<PathBuf>);

impl AsRef<std::path::Path> for HarFilePath {
    fn as_ref(&self) -> &std::path::Path {
        self.0.as_ref()
    }
}

impl Deref for HarFilePath {
    type Target = std::path::Path;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

#[derive(Debug)]
enum FileRecorderMessage {
    Record {
        log: Box<spec::Log>,
        ext: oneshot::Sender<http::Extensions>,
    },
    Stop,
}

#[derive(Debug)]
struct FileRecorderTask {
    rx: mpsc::Receiver<FileRecorderMessage>,

    dir: PathBuf,
    prefix: String,
    start: Instant,
    start_epoch: u64,
}

impl FileRecorderTask {
    fn new(rx: mpsc::Receiver<FileRecorderMessage>, dir: PathBuf, prefix: String) -> Self {
        Self {
            rx,
            dir,
            prefix,
            start: Instant::now(),
            start_epoch: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    async fn run(mut self) {
        #[derive(Debug)]
        struct Storage {
            file: File,
            path: PathBuf,
            has_entries: bool,
        }

        impl Storage {
            async fn new(path: PathBuf) -> Result<Self, OpaqueError> {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)
                        .await
                        .context("create HAR file parent dir")?;
                }
                let file = File::options()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&path)
                    .await
                    .context("create HAR file")?;
                Ok(Self {
                    file,
                    path,
                    has_entries: false,
                })
            }
        }

        let mut storage: Option<Storage> = None;
        let mut counter = 0;
        let mut buf = Vec::new();

        'msg_loop: while let Some(msg) = self.rx.recv().await {
            match msg {
                FileRecorderMessage::Record { log, ext } => {
                    let storage_ref = if let Some(sr) = storage.as_mut() {
                        sr
                    } else {
                        storage = Some(
                            match Storage::new(self.dir.join(format!(
                                "{}_{}_{}_{}.har",
                                self.prefix,
                                self.start_epoch,
                                {
                                    let i = counter;
                                    counter += 1;
                                    i
                                },
                                self.start.elapsed().as_secs()
                            )))
                            .await
                            {
                                Err(err) => {
                                    tracing::debug!(
                                        "failed to create file for HAR recording: {err} (ignore log entry)"
                                    );
                                    continue 'msg_loop;
                                }
                                Ok(storage) => storage,
                            },
                        );
                        let storage_ref = storage.as_mut().unwrap();

                        buf.clear();
                        let header = serde_json::json!({
                            "log": {
                                "version": log.version,
                                "creator": log.creator,
                                "browser": log.browser,
                                "comment": log.comment,
                                "pages": [], // pages is required, even if we do not support it
                            },
                        });
                        if let Err(err) = serde_json::to_writer(&mut buf, &header) {
                            tracing::debug!(
                                "failed to serialize initial json content for HAR log: {err} (drop file)"
                            );
                            storage = None;
                            continue 'msg_loop;
                        }
                        buf.truncate(buf.len() - 2); // '}}'
                        let _ = write!(buf, ",\"entries\":["); // cannot fail (unless something like OOM)
                        if let Err(err) = storage_ref.file.write_all(&buf).await {
                            tracing::debug!(
                                "failed to write initial json content for HAR log: {err} (drop file)"
                            );
                            storage = None;
                            continue 'msg_loop;
                        }

                        storage_ref
                    };

                    if log.pages.map(|p| !p.is_empty()).unwrap_or_default() {
                        tracing::debug!(
                            "log contains pages which are not supported by the har recorder!"
                        );
                    }

                    for entry in log.entries.iter() {
                        tracing::trace!("har log file writer: write entry: {entry:?}");
                        buf.clear();
                        match serde_json::to_writer(&mut buf, entry) {
                            Ok(_) => {
                                if storage_ref.has_entries
                                    && let Err(err) = storage_ref.file.write_u8(b',').await
                                {
                                    tracing::debug!("failed to write entry separator: {err}");
                                    finish_file(storage.take().unwrap().file).await;
                                    continue 'msg_loop;
                                } else if let Err(err) = storage_ref.file.write_all(&buf).await {
                                    tracing::debug!("failed to write serialized entry: {err}");
                                    finish_file(storage.take().unwrap().file).await;
                                    continue 'msg_loop;
                                } else {
                                    storage_ref.has_entries = true;
                                }
                            }
                            Err(err) => {
                                tracing::debug!(
                                    "failed entry ({entry:?}) due to json serialize error: {err}"
                                );
                                finish_file(storage.take().unwrap().file).await;
                                continue 'msg_loop;
                            }
                        }
                    }

                    let mut extensions = http::Extensions::new();
                    extensions.insert(HarFilePath(storage_ref.path.clone().into()));
                    if ext.send(extensions).is_err() {
                        tracing::debug!(
                            "failed to send http extensions w/ har file path back to recorder callee"
                        );
                    }
                }
                FileRecorderMessage::Stop => {
                    if let Some(storage) = storage.take() {
                        tracing::trace!(
                            "FileRecorderMessage::Stop recieved: finish file {:?}",
                            storage.path
                        );
                        finish_file(storage.file).await;
                    } else {
                        tracing::debug!(
                            "FileRecorderMessage::Stop received while no session active: ignore"
                        );
                    }
                }
            }
        }
        if let Some(storage) = storage {
            tracing::trace!(
                "FileRecorder task exiting: file '{:?}' was still active: finish file",
                storage.path
            );
            finish_file(storage.file).await;
        }
    }
}

async fn finish_file(mut file: File) {
    // ] entries > } log > } root
    if let Err(err) = file.write_all(b"]}}").await {
        tracing::debug!("failed to write trailing characters for finished har file: {err}");
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
    /// Create a new [`FileRecorder`] for the given dir and prefix.
    ///
    /// Use [`FileRecorder::default`] if you wish to use a temporary
    /// directory for it using the default rama-version based prefix.
    #[must_use]
    pub fn new(dir: PathBuf, prefix: String) -> Self {
        let (tx, rx) = mpsc::channel(match std::thread::available_parallelism() {
            Ok(n) => n.get(),
            Err(_) => 1,
        });

        let task = FileRecorderTask::new(rx, dir, prefix);
        tokio::spawn(task.run());

        Self { tx }
    }
}

impl Recorder for FileRecorder {
    async fn record(&self, log: spec::Log) -> Option<http::Extensions> {
        let (tx, rx) = oneshot::channel();
        if let Err(err) = self
            .tx
            .send(FileRecorderMessage::Record {
                log: Box::new(log),
                ext: tx,
            })
            .await
        {
            tracing::debug!("FileRecorder: failed to send log for recording to task: {err}");
        }
        rx.await
            .inspect_err(|err| {
                tracing::debug!("file recorder: record oneshot reply await error: {err}");
            })
            .ok()
    }

    async fn stop_record(&self) {
        if let Err(err) = self.tx.send(FileRecorderMessage::Stop).await {
            tracing::debug!("FileRecorder: failed to send stop record msg to task: {err}");
        }
    }
}
