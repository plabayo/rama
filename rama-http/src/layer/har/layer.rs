use crate::layer::har::Recorder;
use crate::layer::har::fs_recorder::FsRecorder;
use crate::layer::har::service::HARExportService;
use crate::layer::har::toggle::Toggle;
use rama_core::Layer;

pub struct HARExportLayer<R, T> {
    pub recorder: R,
    pub toggle: T,
}

impl<T: Toggle> HARExportLayer<FsRecorder, T> {
    pub fn new(fs_path: String, toggle: T) -> Self {
        Self {
            recorder: FsRecorder::new(fs_path),
            toggle,
        }
    }
}

impl<R: Recorder + Clone, T: Clone> Clone for HARExportLayer<R, T> {
    fn clone(&self) -> Self {
        Self {
            recorder: self.recorder.clone(),
            toggle: self.toggle.clone(),
        }
    }
}

impl<R, S, T> Layer<S> for HARExportLayer<R, T>
where
    R: Clone + Send + Sync + 'static,
    T: Toggle + Clone + Send + Sync + 'static,
{
    type Service = HARExportService<R, S, T>;

    fn layer(&self, service: S) -> Self::Service {
        HARExportService {
            service,
            toggle: self.toggle.clone(),
            recorder: self.recorder.clone(),
        }
    }

    fn into_layer(self, service: S) -> Self::Service {
        HARExportService {
            service,
            toggle: self.toggle,
            recorder: self.recorder,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::har::signal::signal_toggle;
    use crate::layer::har::{HarLog, Recorder};
    use std::sync::{Arc, Mutex, atomic::Ordering};

    // simple alternative implementation

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

    impl Recorder for InMemoryRecorder {
        async fn record(&self, line: HarLog) {
            let mut lock = self.data.lock().unwrap();
            lock.push(line);
        }
    }

    impl<T: Toggle> HARExportLayer<InMemoryRecorder, T> {
        pub fn new_test(toggle: T) -> Self {
            Self {
                recorder: InMemoryRecorder::new(),
                toggle,
            }
        }
    }

    #[tokio::test]
    // Test showing flag on/off working with a manual recorder
    async fn in_memory_recorder_records_logs() {
        let (flag, tx, _handle) = signal_toggle();
        let layer = HARExportLayer::new_test(flag.clone());
        // initially the flag is set false
        assert_eq!(flag.load(Ordering::Relaxed), false);

        // flip once
        tx.send(()).await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(flag.load(Ordering::Relaxed), true);

        layer.recorder.record(HarLog::default()).await;

        // flip it manually
        tx.send(()).await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(flag.load(Ordering::Relaxed), false);

        // Check that the recorder captured something
        let data = layer.recorder.data.lock().unwrap();
        assert!(
            !data.is_empty(),
            "Expected recorder to have recorded at least one HAR log"
        );
    }
}
