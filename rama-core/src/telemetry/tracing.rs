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
