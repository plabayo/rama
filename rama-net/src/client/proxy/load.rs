use std::{fmt, sync::Arc};

use rama_core::{error::BoxError, error_sink::ErrorSink};

#[derive(Clone)]
pub(super) struct CachedLoadError(Arc<BoxError>);

impl fmt::Debug for CachedLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for CachedLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl core::error::Error for CachedLoadError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(self.0.as_ref().as_ref())
    }
}

#[derive(Clone)]
pub(super) enum LoadErrorPolicy {
    Reject,
    Handle(Arc<dyn ErrorSink>),
}

impl LoadErrorPolicy {
    pub(super) fn handle(&self, error: BoxError) -> Result<(), BoxError> {
        match self {
            Self::Reject => Err(error),
            Self::Handle(sink) => {
                sink.sink_error(error);
                Ok(())
            }
        }
    }

    pub(super) fn handle_cached<T>(
        &self,
        error: BoxError,
        fallback: T,
    ) -> Result<T, CachedLoadError> {
        match self {
            Self::Reject => Err(CachedLoadError(Arc::new(error))),
            Self::Handle(sink) => {
                sink.sink_error(error);
                Ok(fallback)
            }
        }
    }
}

impl fmt::Debug for LoadErrorPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reject => f.write_str("Reject"),
            Self::Handle(_) => f.write_str("Handle(_)"),
        }
    }
}
