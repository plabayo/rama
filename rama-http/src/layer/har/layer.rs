use crate::layer::har::service::{HARExportService, Recorder};
use crate::layer::har::{Comment, ExportMode, Toggle};
use rama_core::Layer;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct HARExportLayer<T> {
    pub mode: ExportMode,
    pub comments: Vec<Comment>,
    pub toggle: T,
}

impl<S, T> Layer<S> for HARExportLayer<T>
where
    T: Toggle + Clone + Send + Sync + 'static,
{
    type Service = HARExportService<S, T>;

    fn layer(&self, inner: S) -> Self::Service {
        HARExportService {
            inner,
            toggle: self.toggle.clone(),
            recorder: Arc::new(Mutex::new(Recorder::default())),
        }
    }
}
