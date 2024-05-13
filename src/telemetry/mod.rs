//! Rama telemetry modules.

pub mod opentelemetry;

pub mod prometheus {
    //! prometheus module re-exports

    pub use ::opentelemetry_prometheus::*;
    pub use ::prometheus::*;
}
