use std::fmt;

use crate::layer::har::service::HARExportService;
use crate::layer::har::toggle::Toggle;
use rama_core::Layer;

#[non_exhaustive]
pub struct HARExportLayer<R, T> {
    pub recorder: R,
    pub toggle: T,
}

impl<R, T> HARExportLayer<R, T> {
    pub fn new(recorder: R, toggle: T) -> Self {
        Self { recorder, toggle }
    }
}

impl<R: fmt::Debug, T: fmt::Debug> fmt::Debug for HARExportLayer<R, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HARExportLayer")
            .field("recorder", &self.recorder)
            .field("toggle", &self.toggle)
            .finish()
    }
}

impl<R: Clone, T: Clone> Clone for HARExportLayer<R, T> {
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
    use rama_http_types::dep::http;

    use super::*;
    use crate::layer::har::recorder::Recorder;
    use crate::layer::har::spec::Log;
    use crate::layer::har::toggle::mpsc_unbounded_toggle;
    use std::future::ready;
    use std::sync::{Arc, Mutex, atomic::Ordering};

    // simple alternative implementation

    #[derive(Clone, Default)]
    pub struct InMemoryRecorder {
        logs: Arc<Mutex<Vec<Log>>>,
    }

    impl InMemoryRecorder {
        #[must_use]
        #[inline]
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl Recorder for InMemoryRecorder {
        async fn record(&self, log: Log) -> Option<http::Extensions> {
            let mut lock = self.logs.lock().unwrap();
            lock.push(log);
            None
        }

        fn stop_record(&self) -> impl Future<Output = ()> + Send {
            ready(())
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
        let (flag, tx) = mpsc_unbounded_toggle(std::future::pending::<()>());
        let layer = HARExportLayer::new_test(flag.clone());
        // initially the flag is set false
        assert!(!flag.load(Ordering::Relaxed));

        // flip once
        tx.send(()).unwrap();
        tokio::task::yield_now().await;
        assert!(flag.load(Ordering::Relaxed));

        layer.recorder.record(Log::default()).await;

        // flip it manually
        tx.send(()).unwrap();
        tokio::task::yield_now().await;
        assert!(!flag.load(Ordering::Relaxed));

        // Check that the recorder captured something
        let data = layer.recorder.logs.lock().unwrap();
        assert!(
            !data.is_empty(),
            "Expected recorder to have recorded at least one HAR log"
        );
    }
}
