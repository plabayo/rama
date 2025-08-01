use crate::layer::har::{HarLog, Recorder};
use crate::layer::har::toggle::Toggle;
use std::future::{Future, ready};
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

impl Recorder for InMemoryRecorder {
    async fn record(&self, line: HarLog) {
        let mut lock = self.data.lock().unwrap();
        lock.push(line);
    }

    fn data(&self) -> Vec<HarLog> {
        self.data.lock().unwrap().clone()
    }
}

#[derive(Clone)]
pub struct StaticToggle {
    value: bool,
}

impl StaticToggle {
    pub fn new(value: bool) -> Self {
        Self { value }
    }
}

impl Toggle for StaticToggle {
    fn status(&self) -> impl Future<Output = bool> + Send + '_ {
        ready(self.value)
    }
}
