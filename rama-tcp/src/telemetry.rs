//! Everything rama-tcp ships to observe it: its events, and what turns them
//! into tracing and dial9.

use rama_core::telemetry::event::SpanAdapters;

pub use crate::server::{TcpServerConnectionClosed, TcpServerConnectionOpened};

/// The span adapters rama-tcp ships, per tool.
#[derive(Debug, Clone, Copy)]
pub struct DefaultSpanAdapters;

impl DefaultSpanAdapters {
    /// Tracing spans for the spans rama-tcp defines.
    #[must_use]
    pub fn tracing(span_adapters: SpanAdapters) -> SpanAdapters {
        span_adapters.with(TcpServerConnectionOpened::tracing_spans())
    }

    /// dial9 operations for the spans rama-tcp defines.
    #[cfg(feature = "dial9")]
    #[must_use]
    pub fn dial9(span_adapters: SpanAdapters) -> SpanAdapters {
        span_adapters.with(TcpServerConnectionOpened::dial9_operations())
    }
}
