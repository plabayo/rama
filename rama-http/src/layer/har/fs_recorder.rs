use crate::layer::har::{HarLog, Recorder};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

/// Recorder that writes HAR logs to a file.
#[derive(Clone)]
pub struct FsRecorder {
    path: Arc<PathBuf>,
}

impl FsRecorder {
    /// Create a new file recorder that appends HAR entries to `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: Arc::new(path.into()),
        }
    }
}

impl Recorder for FsRecorder {
    async fn record(&self, line: HarLog) {
        // Serialize the HAR log entry to JSON
        let json = match serde_json::to_string(&line) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("FsRecorder serialization error: {e}");
                return;
            }
        };

        // Open file in append mode
        let mut file = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&*self.path)
            .await
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!("FsRecorder file open error: {e}");
                return;
            }
        };

        // Write JSON + newline
        if let Err(e) = file.write_all(json.as_bytes()).await {
            eprintln!("FsRecorder write error: {e}");
        }
        file.write_all(b"\n").await.unwrap();
    }
}
