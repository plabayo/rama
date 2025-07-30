use crate::layer::har::service::{HARExportService, Recorder};
use crate::layer::har::{Comment, Toggle};
use rama_core::Layer;

pub struct HARExportLayer<R, T> {
    pub recorder: R,
    pub comments: Vec<Comment>,
    pub toggle: T,
}

impl<R: Recorder, T: Clone> Clone for HARExportLayer<R, T> {
    fn clone(&self) -> Self {
        HARExportLayer {
            recorder: self.recorder.clone(),
            comments: self.comments.clone(),
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

    fn layer(&self, inner: S) -> Self::Service {
        HARExportService {
            inner,
            toggle: self.toggle.clone(),
            recorder: self.recorder.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        HARExportService {
            inner,
            toggle: self.toggle,
            recorder: self.recorder,
        }
    }
}
