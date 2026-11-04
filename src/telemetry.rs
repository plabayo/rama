//! Rama telemetry modules.

#[cfg(feature = "dial9")]
#[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
pub mod dial9 {
    //! dial9 runtime telemetry re-exports.

    pub use ::rama_core::telemetry::dial9::*;
}

pub mod event {
    //! Typed events and spans, explained in the book: <https://ramaproxy.org/book/intro/events.html>.

    pub use ::rama_core::telemetry::event::*;
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

/// The span adapters every enabled rama crate ships, per tool.
#[derive(Debug, Clone, Copy)]
pub struct DefaultSpanAdapters;

impl DefaultSpanAdapters {
    /// Tracing spans for the spans rama defines.
    #[must_use]
    pub fn tracing(span_adapters: event::SpanAdapters) -> event::SpanAdapters {
        let groups: &[fn(event::SpanAdapters) -> event::SpanAdapters] = &[
            #[cfg(all(feature = "std", feature = "tcp"))]
            crate::tcp::telemetry::DefaultSpanAdapters::tracing,
        ];
        groups
            .iter()
            .fold(span_adapters, |span_adapters, group| group(span_adapters))
    }

    /// dial9 operations for the spans rama defines.
    #[cfg(feature = "dial9")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
    #[must_use]
    pub fn dial9(span_adapters: event::SpanAdapters) -> event::SpanAdapters {
        let groups: &[fn(event::SpanAdapters) -> event::SpanAdapters] = &[
            #[cfg(all(feature = "std", feature = "tcp"))]
            crate::tcp::telemetry::DefaultSpanAdapters::dial9,
        ];
        groups
            .iter()
            .fold(span_adapters, |span_adapters, group| group(span_adapters))
    }
}

/// The listeners every enabled rama crate ships, per tool.
#[derive(Debug, Clone, Copy)]
pub struct DefaultListeners;

impl DefaultListeners {
    /// Tracing logs for the events rama emits.
    #[must_use]
    pub fn tracing(listeners: event::Listeners) -> event::Listeners {
        let groups: &[fn(event::Listeners) -> event::Listeners] = &[];
        groups
            .iter()
            .fold(listeners, |listeners, group| group(listeners))
    }
}
