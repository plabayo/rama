//! Tracing core rexport and utilities, for your conveneince

#[doc(inline)]
pub use ::tracing::*;
#[doc(inline)]
pub use ::tracing_opentelemetry::*;

// NOTE: once <https://github.com/tokio-rs/tracing/issues/3310>
// is resolved (if ever) we should be able to remove these utility macros again

#[macro_export]
#[doc(hidden)]
macro_rules! __root_span {
    ($lvl:expr, $name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::root_span!(target: module_path!(), $lvl, $name, $($fields)*)
    };
    (target: $target:expr, $lvl:expr, $name:expr, $($fields:tt)*) => {
        {
            use $crate::telemetry::tracing::__macro_support::Callsite as _;
            use $crate::telemetry::tracing::OpenTelemetrySpanExt as _;
            use $crate::telemetry::opentelemetry::trace::get_active_span;

            static __CALLSITE: $crate::telemetry::tracing::__macro_support::MacroCallsite = $crate::telemetry::tracing::callsite2! {
                name: $name,
                kind: $crate::telemetry::tracing::metadata::Kind::SPAN,
                target: $target,
                level: $lvl,
                fields: $($fields)*
            };

            let mut interest = $crate::telemetry::tracing::subscriber::Interest::never();
            let span = if $crate::telemetry::tracing::level_enabled!($lvl)
                && { interest = __CALLSITE.interest(); !interest.is_never() }
                && $crate::telemetry::tracing::__macro_support::__is_enabled(__CALLSITE.metadata(), interest)
            {
                let meta = __CALLSITE.metadata();
                $crate::telemetry::tracing::Span::new_root(
                    meta,
                    &$crate::telemetry::tracing::valueset!(meta.fields(), $($fields)*))
            } else {
                let span = $crate::telemetry::tracing::__macro_support::__disabled_span(__CALLSITE.metadata());
                $crate::telemetry::tracing::if_log_enabled! { $lvl, {
                    span.record_all(&$crate::valueset!(__CALLSITE.metadata().fields(), $($fields)*));
                }};
                span
            };
            span.add_link(get_active_span(|span| span.span_context().clone()));
            span
        }
    };
}

#[doc(inline)]
pub use crate::__root_span as root_span;

#[macro_export]
#[doc(hidden)]
macro_rules! __trace_root_span {
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
    ($name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::root_span!($crate::telemetry::tracing::Level::INFO, $name, $($fields)*)
    };
    (target: $target:expr, $name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::root_span!(target: $target, $crate::telemetry::tracing::Level::INFO, $name, $($fields)*)
    }
}

#[doc(inline)]
pub use crate::__info_root_span as info_root_span;
