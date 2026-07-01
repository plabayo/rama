//! A reusable sink for errors that occur in fire-and-forget contexts.
//!
//! Some work in rama cannot return its error to a caller — e.g. a spawned HTTP
//! upgrade handler or a background relay task. The error still matters (it
//! should at least be observable), but there is no `Result` left to bubble it
//! up through. [`ErrorSink`] is the shared abstraction for handing such an
//! error somewhere useful, so each call site does not reinvent its own ad-hoc
//! logging or routing.
//!
//! The provided [`TracingErrorSink`] emits the error via `tracing` at a
//! configurable [`level`](tracing::Level) (DEBUG by default), and is what rama
//! components fall back to when no custom sink is configured. Any
//! `Fn(E) + Send + Sync + 'static` is also an [`ErrorSink`], so a closure can
//! be used for custom routing (metrics, a channel, ...).
//!
//! # Example
//!
//! ```
//! use rama_core::error::{BoxError, BoxErrorExt as _};
//! use rama_core::error_sink::{ErrorSink, TracingErrorSink};
//!
//! // the default sink traces at DEBUG level
//! let sink = TracingErrorSink::default();
//! sink.sink_error(BoxError::from_static_str("something went wrong"));
//!
//! // a closure is a sink too
//! let sink = |err: BoxError| eprintln!("custom: {err}");
//! sink.sink_error(BoxError::from_static_str("boom"));
//! ```

use crate::error::BoxError;
use crate::std::sync::Arc;

/// A sink for errors produced in fire-and-forget contexts where the error
/// cannot be propagated back to a caller.
///
/// Implemented for any `Fn(E) + Send + Sync + 'static`, and by the provided
/// [`TracingErrorSink`]. Use it as a trait object (`Arc<dyn ErrorSink>`) when
/// the sink is configurable at runtime.
pub trait ErrorSink<E = BoxError>: Send + Sync + 'static {
    /// Consume (observe and/or route) an error.
    fn sink_error(&self, error: E);
}

impl<E, F> ErrorSink<E> for F
where
    F: Fn(E) + Send + Sync + 'static,
{
    fn sink_error(&self, error: E) {
        (self)(error)
    }
}

/// A shared (ref-counted) sink is itself an [`ErrorSink`], so an
/// `Arc<dyn ErrorSink>` can be handed around and reused.
impl<E, T> ErrorSink<E> for Arc<T>
where
    T: ErrorSink<E> + ?Sized,
{
    fn sink_error(&self, error: E) {
        (**self).sink_error(error)
    }
}

/// An [`ErrorSink`] that emits errors via `tracing` at a configurable level.
///
/// This is the fallback sink used by rama components that accept an
/// [`ErrorSink`]: when none is configured they use [`TracingErrorSink::default`],
/// which logs at [`tracing::Level::DEBUG`].
#[derive(Debug, Clone)]
pub struct TracingErrorSink {
    level: tracing::Level,
}

impl Default for TracingErrorSink {
    fn default() -> Self {
        Self::new(tracing::Level::DEBUG)
    }
}

impl TracingErrorSink {
    /// Create a [`TracingErrorSink`] emitting at the given [`tracing::Level`].
    #[must_use]
    pub const fn new(level: tracing::Level) -> Self {
        Self { level }
    }

    /// Emit at [`tracing::Level::TRACE`].
    #[must_use]
    pub const fn trace() -> Self {
        Self::new(tracing::Level::TRACE)
    }

    /// Emit at [`tracing::Level::DEBUG`] (the default).
    #[must_use]
    pub const fn debug() -> Self {
        Self::new(tracing::Level::DEBUG)
    }

    /// Emit at [`tracing::Level::INFO`].
    #[must_use]
    pub const fn info() -> Self {
        Self::new(tracing::Level::INFO)
    }

    /// Emit at [`tracing::Level::WARN`].
    #[must_use]
    pub const fn warn() -> Self {
        Self::new(tracing::Level::WARN)
    }

    /// Emit at [`tracing::Level::ERROR`].
    #[must_use]
    pub const fn error() -> Self {
        Self::new(tracing::Level::ERROR)
    }
}

impl<E> ErrorSink<E> for TracingErrorSink
where
    E: Into<BoxError>,
{
    fn sink_error(&self, error: E) {
        const MESSAGE: &str = "error sink: unhandled error";
        let error = error.into();
        match self.level {
            tracing::Level::TRACE => tracing::trace!(?error, "{MESSAGE}"),
            tracing::Level::DEBUG => tracing::debug!(?error, "{MESSAGE}"),
            tracing::Level::INFO => tracing::info!(?error, "{MESSAGE}"),
            tracing::Level::WARN => tracing::warn!(?error, "{MESSAGE}"),
            tracing::Level::ERROR => tracing::error!(?error, "{MESSAGE}"),
        }
    }
}

/// An [`ErrorSink`] that silently drops every error, for any error type `E`.
///
/// Useful for fire-and-forget work whose errors are neither actionable nor
/// meaningfully traceable (e.g. an error type that doesn't implement the
/// `Into<BoxError>` bound [`TracingErrorSink`] needs). Prefer this over a
/// no-op closure so the intent ("errors are deliberately ignored here") is
/// explicit at the call site.
#[derive(Debug, Clone, Copy, Default)]
pub struct DropErrorSink;

impl DropErrorSink {
    /// Create a new [`DropErrorSink`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<E> ErrorSink<E> for DropErrorSink {
    fn sink_error(&self, _error: E) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BoxErrorExt as _;
    use crate::std::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn closure_is_error_sink() {
        let count = Arc::new(AtomicUsize::new(0));
        let sink = {
            let count = count.clone();
            move |_err: BoxError| {
                count.fetch_add(1, Ordering::SeqCst);
            }
        };
        sink.sink_error(BoxError::from_static_str("boom"));
        sink.sink_error(BoxError::from_static_str("boom again"));
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn tracing_sink_is_object_safe_and_callable() {
        // ensure `dyn ErrorSink` works as a trait object and the default level is DEBUG.
        let sink: Arc<dyn ErrorSink> = Arc::new(TracingErrorSink::default());
        sink.sink_error(BoxError::from_static_str("observed"));

        // all constructors yield a usable sink
        for sink in [
            TracingErrorSink::trace(),
            TracingErrorSink::debug(),
            TracingErrorSink::info(),
            TracingErrorSink::warn(),
            TracingErrorSink::error(),
        ] {
            sink.sink_error(BoxError::from_static_str("level"));
        }
    }

    #[test]
    fn drop_error_sink_ignores_any_error_type() {
        // a non-`Into<BoxError>` error type: only a sink without that bound works.
        struct NotAnError;

        let sink = DropErrorSink::new();
        sink.sink_error(NotAnError);
        sink.sink_error(BoxError::from_static_str("ignored"));
        sink.sink_error(42_u32);

        // also usable as the default `dyn ErrorSink` (E = BoxError).
        let sink: Arc<dyn ErrorSink> = Arc::new(DropErrorSink::new());
        sink.sink_error(BoxError::from_static_str("ignored"));
    }

    #[test]
    fn custom_closure_sink_as_trait_object() {
        let count = Arc::new(AtomicUsize::new(0));
        let sink: Arc<dyn ErrorSink> = {
            let count = count.clone();
            Arc::new(move |_err: BoxError| {
                count.fetch_add(1, Ordering::SeqCst);
            })
        };
        sink.sink_error(BoxError::from_static_str("routed"));
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}
