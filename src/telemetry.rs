//! Rama telemetry modules.

#[cfg(feature = "opentelemetry")]
pub mod opentelemetry {
    //! openelemetry module re-exports
    //!
    //! This module re-exports the crates supported and used by rama for (open) telemetry,
    //! such that you can make use of it for custom metrics, registries and more.

    pub use ::rama_core::telemetry::opentelemetry::*;

    pub use ::opentelemetry_otlp as collector;
}

pub mod tracing {
    //! Tracing core rexport and utilities, for your conveneince

    pub use ::rama_core::telemetry::tracing::*;

    pub use ::tracing_subscriber as subscriber;
}
