use crate::layer::har::service::{HARExportService, Recorder};
use crate::layer::har::{Comment, StaticToggle, Toggle};
use rama_core::Layer;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct HARExportLayer<T> {
    pub comments: Vec<Comment>,
    pub toggle: T,
}

impl<T: Clone> Clone for HARExportLayer<T> {
    fn clone(&self) -> Self {
        HARExportLayer {
            comments: self.comments.clone(),
            toggle: self.toggle.clone(),
        }
    }
}

impl Default for HARExportLayer<StaticToggle> {
    fn default() -> Self {
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
