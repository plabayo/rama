//! Rama telemetry modules.

#[cfg(feature = "dial9")]
#[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
pub mod dial9 {
    //! dial9 runtime telemetry re-exports.

    pub use ::rama_core::telemetry::dial9::*;
}

#[cfg(feature = "opentelemetry")]
#[cfg_attr(docsrs, doc(cfg(feature = "opentelemetry")))]
pub mod opentelemetry {
    //! openelemetry module re-exports
    //!
    //! This module re-exports the crates supported and used by rama for (open) telemetry,
    //! such that you can make use of it for custom metrics, registries and more.

    pub use ::rama_core::telemetry::opentelemetry::*;

    #[cfg(feature = "grpc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "grpc")))]
    pub mod collector {
        //! OTLP exporter integrations supported by rama.

        pub use ::rama_grpc::service::opentelemetry::OtelExporter;
    }
}

pub mod tracing;
