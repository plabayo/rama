//! Tracing core rexport and utilities, for your conveneince

#[doc(inline)]
pub use tracing::*;

/// Re-export of [`tracing_appender`] plus rama utilities that go with it.
///
/// Open out as a module rather than a `pub use … as` so we can hang
/// rama-specific helpers (e.g. [`appender::rolling_dedicated_thread`])
/// next to the upstream API without forcing callers to import a second
/// crate.
pub mod appender {
    #[doc(inline)]
    pub use ::tracing_appender::*;

    // Hoist the most commonly used names from nested submodules to
    // the top of the `appender` namespace so callers don't have to
    // remember which sub-path each one lives under.
    #[doc(inline)]
    pub use ::tracing_appender::{
        non_blocking::{NonBlocking, NonBlockingBuilder, WorkerGuard},
        rolling::{RollingFileAppender, Rotation},
    };

    use std::path::Path;

    /// Build a rolling-file appender that writes on a dedicated OS thread.
    ///
    /// Wraps a [`RollingFileAppender`] in [`NonBlocking`] so that all
    /// file I/O — including the rotation work that runs when a new file
    /// is rolled over — happens on the appender's worker thread, not on
    /// whichever runtime/application thread emitted the event. This is
    /// the recommended setup for production logging: log volume is
    /// often bursty, and a synchronous rotation on a hot path can stall
    /// it for the duration of the rename + create.
    ///
    /// The returned [`WorkerGuard`] **must be kept alive** for the
    /// lifetime of the program. Dropping it stops the worker thread and
    /// prevents further writes from being flushed. Drop it intentionally
    /// just before the program exits to flush pending records.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// use rama_core::telemetry::tracing::appender::{
    ///     Rotation, rolling_dedicated_thread,
    /// };
    /// use tracing_subscriber::{prelude::*, fmt};
    ///
    /// let (writer, _guard) = rolling_dedicated_thread(
    ///     Rotation::DAILY,
    ///     "/var/log/myapp",
    ///     "myapp.log",
    /// );
    /// tracing_subscriber::registry()
    ///     .with(fmt::layer().with_writer(writer))
    ///     .init();
    /// // keep `_guard` alive until program shutdown
    /// ```
    pub fn rolling_dedicated_thread(
        rotation: Rotation,
        directory: impl AsRef<Path>,
        file_name_prefix: impl AsRef<Path>,
    ) -> (NonBlocking, WorkerGuard) {
        let appender = RollingFileAppender::new(rotation, directory, file_name_prefix);
        rolling_dedicated_thread_with_builder(NonBlockingBuilder::default(), appender)
    }

    /// Variant of [`rolling_dedicated_thread`] that lets the caller
    /// drive the [`NonBlockingBuilder`] (custom buffer limit, lossy
    /// vs. blocking back-pressure, thread name, …).
    ///
    /// The default `NonBlockingBuilder` is lossy under saturation.
    /// Switch to `lossy(false)` if losing log lines is unacceptable for
    /// your use case — be aware that this exerts back-pressure on the
    /// thread that emits the event.
    pub fn rolling_dedicated_thread_with_builder(
        builder: NonBlockingBuilder,
        appender: RollingFileAppender,
    ) -> (NonBlocking, WorkerGuard) {
        builder.finish(appender)
    }
}

#[cfg(feature = "opentelemetry")]
#[cfg_attr(docsrs, doc(cfg(feature = "opentelemetry")))]
#[doc(inline)]
pub use tracing_opentelemetry::*;

// NOTE: once <https://github.com/tokio-rs/tracing/issues/3310>
// is resolved (if ever) we should be able to remove these utility macros again

#[doc(hidden)]
pub mod __private {
    pub use tracing::span as __og_span;
}

#[cfg(not(feature = "opentelemetry"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __span {
    ($lvl:expr, $name:expr) => {
        $crate::telemetry::tracing::span!(target: module_path!(), $lvl, $name, )
    };
    ($lvl:expr, $name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::span!(target: module_path!(), $lvl, $name, $($fields)*)
    };
    (target: $target:expr, $lvl:expr, $name:expr, $($fields:tt)*) => {
        {
            $crate::telemetry::tracing::__private::__og_span!(
                target: $target,
                $lvl,
                $name,
                $($fields)*
            )
        }
    };
    (target: $target:expr, parent: $parent:expr, $lvl:expr, $name:expr, $($fields:tt)*) => {
        {
            $crate::telemetry::tracing::__private::__og_span!(
                target: $target,
                parent: $parent,
                $lvl,
                $name,
                $($fields)*
            )
        }
    };
}

#[cfg(feature = "opentelemetry")]
#[macro_export]
#[doc(hidden)]
macro_rules! __span {
    ($lvl:expr, $name:expr) => {
        $crate::telemetry::tracing::span!(target: module_path!(), $lvl, $name, )
    };
    ($lvl:expr, $name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::span!(target: module_path!(), $lvl, $name, $($fields)*)
    };
    (target: $target:expr, $lvl:expr, $name:expr, $($fields:tt)*) => {
        {
            use $crate::telemetry::tracing::{OpenTelemetrySpanExt as _, field};
            use $crate::telemetry::opentelemetry::trace::TraceContextExt as _;
            use $crate::telemetry::opentelemetry::{SpanId, TraceId};

            let span = $crate::telemetry::tracing::__private::__og_span!(
                target: $target,
                $lvl,
                $name,
                span.id = field::Empty,
                trace.id = field::Empty,
                $($fields)*
            );

            let otel_ctx = span.context();
            let span_ref = otel_ctx.span();
            let span_ctx = span_ref.span_context();

            let span_id = span_ctx.span_id();
            if span_id != SpanId::INVALID {
                span.record("span.id", span_id.to_string());
            }

            let trace_id = span_ctx.trace_id();
            if trace_id != TraceId::INVALID {
                span.record("trace.id", trace_id.to_string());
            }

            span
        }
    };
    (target: $target:expr, parent: $parent:expr, $lvl:expr, $name:expr, $($fields:tt)*) => {
        {
            use $crate::telemetry::tracing::{OpenTelemetrySpanExt as _, field};
            use $crate::telemetry::opentelemetry::trace::TraceContextExt as _;
            use $crate::telemetry::opentelemetry::{SpanId, TraceId};

            let src_span = $crate::telemetry::tracing::Span::current();

            let span = $crate::telemetry::tracing::__private::__og_span!(
                target: $target,
                parent: $parent,
                $lvl,
                $name,
                span.id = field::Empty,
                trace.id = field::Empty,
                $($fields)*
            );

            let otel_ctx = span.context();
            let span_ref = otel_ctx.span();
            let span_ctx = span_ref.span_context();

            let span_id = span_ctx.span_id();
            if span_id != SpanId::INVALID {
                span.record("span.id", span_id.to_string());
            }

            let trace_id = span_ctx.trace_id();
            if trace_id != TraceId::INVALID {
                span.record("trace.id", trace_id.to_string());
            }

            span
        }
    };
}

#[doc(inline)]
pub use crate::__span as span;

#[macro_export]
#[doc(hidden)]
macro_rules! __trace_span {
    ($name:expr) => {
        $crate::telemetry::tracing::span!($crate::telemetry::tracing::Level::TRACE, $name)
    };
    ($name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::span!($crate::telemetry::tracing::Level::TRACE, $name, $($fields)*)
    };
    (target: $target:expr, $name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::span!(target: $target, $crate::telemetry::tracing::Level::TRACE, $name, $($fields)*)
    }
}

#[doc(inline)]
pub use crate::__trace_span as trace_span;

#[macro_export]
#[doc(hidden)]
macro_rules! __debug_span {
    ($name:expr) => {
        $crate::telemetry::tracing::span!($crate::telemetry::tracing::Level::DEBUG, $name)
    };
    ($name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::span!($crate::telemetry::tracing::Level::DEBUG, $name, $($fields)*)
    };
    (target: $target:expr, $name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::span!(target: $target, $crate::telemetry::tracing::Level::DEBUG, $name, $($fields)*)
    }
}

#[doc(inline)]
pub use crate::__debug_span as debug_span;

#[macro_export]
#[doc(hidden)]
macro_rules! __info_span {
    ($name:expr) => {
        $crate::telemetry::tracing::span!($crate::telemetry::tracing::Level::INFO, $name)
    };
    ($name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::span!($crate::telemetry::tracing::Level::INFO, $name, $($fields)*)
    };
    (target: $target:expr, $name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::span!(target: $target, $crate::telemetry::tracing::Level::INFO, $name, $($fields)*)
    }
}

#[doc(inline)]
pub use crate::__info_span as info_span;

#[cfg(not(feature = "opentelemetry"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __root_span {
    ($lvl:expr, $name:expr) => {
        $crate::telemetry::tracing::root_span!(target: module_path!(), $lvl, $name,)
    };
    ($lvl:expr, $name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::root_span!(target: module_path!(), $lvl, $name, $($fields)*)
    };
    (target: $target:expr, $lvl:expr, $name:expr, $($fields:tt)*) => {
        {
            let src_span = $crate::telemetry::tracing::Span::current();

            let span = $crate::telemetry::tracing::span!(
                target: $target,
                parent: None,
                $lvl,
                $name,
                $($fields)*
            );

            span.follows_from(src_span);

            span
        }
    };
}

#[cfg(feature = "opentelemetry")]
#[macro_export]
#[doc(hidden)]
macro_rules! __root_span {
    ($lvl:expr, $name:expr) => {
        $crate::telemetry::tracing::root_span!(target: module_path!(), $lvl, $name,)
    };
    ($lvl:expr, $name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::root_span!(target: module_path!(), $lvl, $name, $($fields)*)
    };
    (target: $target:expr, $lvl:expr, $name:expr, $($fields:tt)*) => {
        {
            use $crate::telemetry::tracing::OpenTelemetrySpanExt as _;
            use $crate::telemetry::opentelemetry::{trace::{get_active_span, TraceContextExt}, KeyValue};

            let src_span = $crate::telemetry::tracing::Span::current();

            let span = $crate::telemetry::tracing::span!(
                target: $target,
                parent: None,
                $lvl,
                $name,
                $($fields)*
            );

            src_span.add_link_with_attributes(
                span.context().span().span_context().clone(),
                vec![KeyValue::new("opentracing.ref_type", "child_of")],
            );

            span.follows_from(src_span);
            span.add_link_with_attributes(
                get_active_span(|span| span.span_context().clone()),
                vec![KeyValue::new("opentracing.ref_type", "follows_from")],
            );

            span
        }
    };
}

#[doc(inline)]
pub use crate::__root_span as root_span;

#[macro_export]
#[doc(hidden)]
macro_rules! __trace_root_span {
    ($name:expr) => {
        $crate::telemetry::tracing::root_span!($crate::telemetry::tracing::Level::TRACE, $name,)
    };
    ($name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::root_span!($crate::telemetry::tracing::Level::TRACE, $name, $($fields)*)
    };
    (target: $target:expr, $name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::root_span!(target: $target, $crate::telemetry::tracing::Level::TRACE, $name, $($fields)*)
    }
}

#[doc(inline)]
pub use crate::__trace_root_span as trace_root_span;

#[macro_export]
#[doc(hidden)]
macro_rules! __debug_root_span {
    ($name:expr) => {
        $crate::telemetry::tracing::root_span!($crate::telemetry::tracing::Level::DEBUG, $name,)
    };
    ($name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::root_span!($crate::telemetry::tracing::Level::DEBUG, $name, $($fields)*)
    };
    (target: $target:expr, $name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::root_span!(target: $target, $crate::telemetry::tracing::Level::DEBUG, $name, $($fields)*)
    }
}

#[doc(inline)]
pub use crate::__debug_root_span as debug_root_span;

#[macro_export]
#[doc(hidden)]
macro_rules! __info_root_span {
    ($name:expr) => {
        $crate::telemetry::tracing::root_span!($crate::telemetry::tracing::Level::INFO, $name,)
    };
    ($name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::root_span!($crate::telemetry::tracing::Level::INFO, $name, $($fields)*)
    };
    (target: $target:expr, $name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::root_span!(target: $target, $crate::telemetry::tracing::Level::INFO, $name, $($fields)*)
    }
}

#[doc(inline)]
pub use crate::__info_root_span as info_root_span;
