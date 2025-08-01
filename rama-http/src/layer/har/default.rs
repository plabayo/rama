use crate::layer::har::{HarLog, Recorder};
use std::sync::{Arc, Mutex};

// TODO probably to be moved to examples at some point

#[derive(Clone)]
pub struct InMemoryRecorder {
    data: Arc<Mutex<Vec<HarLog>>>,
}

impl InMemoryRecorder {
    pub fn new() -> Self {
        InMemoryRecorder {
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
