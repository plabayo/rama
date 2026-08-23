use arc_swap::ArcSwapOption;
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
    fmt,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, ReadBuf},
    sync::Mutex,
};

#[derive(Debug, Clone, Serialize)]
pub(super) struct HarStatus {
    pub active: bool,
    pub path: Option<String>,
    pub started_at: Option<String>,
}

#[derive(Debug)]
struct ActiveHar {
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

#[derive(Clone)]
pub(super) struct HarController {
    // Proxied requests only load this pointer. Starting and stopping remain
    // serialized separately because both transitions perform asynchronous I/O.
    active: Arc<ArcSwapOption<ActiveHar>>,
    transition: Arc<Mutex<()>>,
}

impl Default for HarController {
    fn default() -> Self {
        Self {
            active: Arc::new(ArcSwapOption::empty()),
            transition: Arc::new(Mutex::new(())),
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
        let _transition = self.transition.lock().await;
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
            recorder,
            path,
            display_path,
            started_at: jiff::Timestamp::now().to_string(),
            staging: SyncMutex::new(staging),
        };
        let status = HarStatus {
            active: true,
            path: Some(active.display_path.clone()),
            started_at: Some(active.started_at.clone()),
        };
        self.active.store(Some(Arc::new(active)));
        Ok(status)
    }

    /// Stop a browser-backed recording and stream its staged HAR to the client.
    pub(super) async fn stop_browser(&self) -> Result<HarDownload, BoxError> {
        let _transition = self.transition.lock().await;
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
            },
        })
    }

    pub(super) async fn stop(&self) -> HarStatus {
        let _transition = self.transition.lock().await;
        let active = self.active.swap(None);
        if let Some(active) = active {
            active.recorder.stop_record().await;
            HarStatus {
                active: false,
                path: Some(active.display_path.clone()),
                started_at: Some(active.started_at.clone()),
            }
        } else {
            HarStatus {
                active: false,
                path: None,
                started_at: None,
            }
        }
    }

    pub(super) fn status(&self) -> HarStatus {
        let state = self.active.load();
        HarStatus {
            active: state.is_some(),
            path: state.as_deref().map(|active| active.display_path.clone()),
            started_at: state.as_deref().map(|active| active.started_at.clone()),
        }
    }

    fn recorder(&self) -> Option<FileRecorder> {
        self.active
            .load()
            .as_deref()
            .map(|active| active.recorder.clone())
    }
}

impl Toggle for HarController {
    async fn status(&self) -> bool {
        self.active.load().is_some()
    }
}

impl Recorder for HarController {
    async fn record(&self, log: spec::Log) -> Option<Extensions> {
        match self.recorder() {
            Some(recorder) => recorder.record(log).await,
            None => None,
        }
    }

    async fn stop_record(&self) {
        _ = self.stop().await;
    }
}

impl StreamingRecorder for HarController {
    type Session = FileRecorderSession;

    async fn start_http_recording(&self, request: HttpRequestCapture) -> Option<Self::Session> {
        match self.recorder() {
            Some(recorder) => recorder.start_http_recording(request).await,
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt as _;

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
}
