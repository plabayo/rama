//! Typed QUIC diagnostics with optional async recording.
//!
//! Configure [`QlogConfig`] with a writer, call [`QlogConfig::start`] inside a Tokio runtime,
//! and attach the recorder through [`TransportConfig::with_qlog_recorder`](crate::TransportConfig::with_qlog_recorder).
//! Output uses qlog JSON text sequences; [`EncodedWriter`] supports custom encoders.
//! For direct observation, attach a [`QlogSink`]: events borrow connection data and callbacks must finish promptly.
//!
//! Use [`QlogConfig::with_executor`] for graceful draining and flushing, or await
//! [`QlogRecorder::shutdown`] explicitly. Dropping handles does not wait for output.
//! Recording failures go to the configured [`QlogConfig::with_error_sink`]; explicit completion
//! checks are optional. Keep the runtime alive until recording finishes.
//!
//! [`HistoryConfig`] retains a bounded recent window for [`QlogRecorder::dump_recent`].
//! [`ConnectionQlogControl`] provides per-connection toggles and triggers. Disabled observations
//! are not retained; enabling later produces a partial trace.

mod config;
pub mod event;
mod output;
mod recorder;
mod sink;
pub use sink::{Filtered, QlogFilter, QlogSink};

pub use config::{HistoryConfig, QlogConfig, QueueLimits};
pub use output::{EncodedWriter, JsonSeqEncoder, QlogEncoder, QlogOutput, TraceInfo};
pub use recorder::{ConnectionQlogControl, QlogRecorder, RecorderState, RecorderStats};

use std::time::Instant;

/// A typed observation whose variable-length fields may borrow from the connection.
#[derive(Debug)]
pub struct QlogEventView<'a> {
    /// Stable connection group identifier, also available through `Connection::trace_id`.
    pub group_id: crate::ConnectionId,
    /// Monotonic observation time; encoders choose its representation relative to the trace epoch.
    pub time: Instant,
    /// Schema-defined fields, including optional path scope.
    pub fields: event::EventFieldsView<'a>,
}

/// An event that owns all variable-length data and can cross a worker boundary.
pub type QlogEvent = QlogEventView<'static>;

impl QlogEventView<'_> {
    /// Explicitly copy borrowed fields into independently owned storage.
    pub fn to_owned(&self) -> QlogEvent {
        QlogEvent {
            group_id: self.group_id,
            time: self.time,
            fields: self.fields.to_owned(),
        }
    }
}

#[cfg(test)]
pub(crate) use output::reference::ReferenceJsonEncoder;
