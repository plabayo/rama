use crate::layer::har::Recorder;
use crate::layer::har::default::InMemoryRecorder;
use crate::layer::har::service::HARExportService;
use crate::layer::har::toggle::Toggle;
use rama_core::Layer;

pub struct HARExportLayer<R, T> {
    pub recorder: R,
    pub toggle: T,
}

impl Default for HARExportLayer<InMemoryRecorder, bool> {
    fn default() -> Self {
        Self {
            recorder: InMemoryRecorder::new(),
            toggle: false,
        }
    }
}

impl<R: Recorder, T: Clone> Clone for HARExportLayer<R, T> {
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
