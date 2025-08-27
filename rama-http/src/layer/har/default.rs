use crate::layer::har::{HarLog, Recorder};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct InMemoryRecorder {
    data: Arc<Mutex<Vec<HarLog>>>,
}

impl InMemoryRecorder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl Default for InMemoryRecorder {
    fn default() -> Self {
        Self::new()
    }
}

impl Recorder for InMemoryRecorder {
    async fn record(&self, line: HarLog) {
        let mut lock = self.data.lock().unwrap();
        lock.push(line);
    }
}
