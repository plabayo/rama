use crate::layer::har::service::{HARExportService, Recorder};
use crate::layer::har::{Comment, StaticToggle, Toggle};
use rama_core::Layer;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone, Default)]
pub struct HARExportLayer<T> {
    pub comments: Vec<Comment>,
    pub toggle: T,
}

impl HARExportLayer<StaticToggle> {
    pub fn new() -> Self {
        Self {
            comments: vec![],
            toggle: StaticToggle::new(true),
        }
    }
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

    fn into_layer(self, inner: S) -> Self::Service {
        HARExportService {
            inner,
            toggle: self.toggle,
            recorder: Arc::new(Mutex::new(Recorder::default())),
        }
    }
}
