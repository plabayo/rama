//! Pre-defined [dial9] events for proxy bridge lifecycle.
//!
//! [dial9]: https://github.com/dial9-rs/dial9-tokio-telemetry

use crate::dial9::{io_error_kind_code, io_error_raw_os_code};
use dial9_tokio_telemetry::telemetry::{TelemetryHandle, clock_monotonic_ns, record_event};
use dial9_trace_format::TraceEvent;

/// Bridge lifecycle: the copy loop is about to start.
#[derive(TraceEvent)]
pub struct IoForwardBridgeOpened {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    /// Idle timeout in milliseconds, or 0 if disabled.
    pub idle_timeout_ms: u64,
    /// Whether the bridge was constructed with a graceful `Executor`.
    pub graceful: bool,
}

/// Bridge lifecycle: the copy loop has ended.
#[derive(TraceEvent)]
pub struct IoForwardBridgeClosed {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    /// Structured close reason.
    pub reason: super::BridgeCloseReason,
    /// Wall-clock age of the bridge at close time, in milliseconds.
    pub age_ms: u64,
    /// Bytes copied left → right (typically client → server).
    pub bytes_l_to_r: u64,
    /// Bytes copied right → left (typically server → client).
    pub bytes_r_to_l: u64,
    /// Encoded `std::io::ErrorKind`, if a fatal I/O error closed the bridge.
    pub error_kind: Option<u32>,
    /// Raw OS error code, if available.
    pub error_raw_os: Option<i64>,
}

#[inline]
pub(super) fn record_bridge_opened(idle_timeout_ms: u64, graceful: bool) {
    let handle = TelemetryHandle::current();
    if handle.is_enabled() {
        record_event(
            IoForwardBridgeOpened {
                timestamp_ns: clock_monotonic_ns(),
                idle_timeout_ms,
                graceful,
            },
            &handle,
        );
    }
}

#[inline]
pub(super) fn record_bridge_closed(
    reason: super::BridgeCloseReason,
    age_ms: u64,
    bytes_l_to_r: u64,
    bytes_r_to_l: u64,
    error: Option<&std::io::Error>,
) {
    let handle = TelemetryHandle::current();
    if handle.is_enabled() {
        record_event(
            IoForwardBridgeClosed {
                timestamp_ns: clock_monotonic_ns(),
                reason,
                age_ms,
                bytes_l_to_r,
                bytes_r_to_l,
                error_kind: error.map(|e| io_error_kind_code(e.kind())),
                error_raw_os: error.and_then(io_error_raw_os_code),
            },
            &handle,
        );
    }
}
