//! Rama telemetry modules.

#[cfg(feature = "dial9")]
#[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
pub mod dial9 {
    //! dial9 runtime telemetry re-exports.

    #[doc(inline)]
    pub use ::dial9::*;
    #[doc(inline)]
    pub use ::dial9_trace_format as trace_format;
}

#[cfg(feature = "opentelemetry")]
#[cfg_attr(docsrs, doc(cfg(feature = "opentelemetry")))]
pub mod opentelemetry;

#[macro_use]
pub mod tracing;
