//! Tracing core rexport and utilities, for your conveneince

#[doc(inline)]
pub use tracing::*;

#[cfg(feature = "opentelemetry")]
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
            use $crate::telemetry::opentelemetry::{trace::{get_active_span}, KeyValue};

            let src_span = $crate::telemetry::tracing::Span::current();

            let span = $crate::telemetry::tracing::span!(
                target: $target,
                parent: None,
                $lvl,
                $name,
                $($fields)*
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
