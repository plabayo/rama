//! Pre-defined [dial9] events for the transparent proxy engine, plus
//! tiny recording helpers that emit them when a
//! `dial9-tokio-telemetry::TracedRuntime` is active.
//!
//! Mirrors the structured `tracing` events emitted by the engine
//! (`open` / `close` / `handler-deadline`), encoded for fast offline
//! analysis with `dial9-viewer` and friends.
//!
//! Enabled with the `dial9` cargo feature on this crate. Emission is a
//! no-op when no `TracedRuntime` is in effect.
//!
//! [dial9]: https://github.com/dial9-rs/dial9-tokio-telemetry

use dial9_tokio_telemetry::telemetry::{TelemetryHandle, clock_monotonic_ns, record_event};
use dial9_trace_format::TraceEvent;

/// Emitted right after the engine has assigned a `flow_id` to a new
/// transparent-proxy flow and decided how to handle it.
#[derive(TraceEvent)]
pub struct TproxyFlowOpened {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    /// Per-process monotonic flow id.
    pub flow_id: u64,
    /// `1` for TCP, `2` for UDP. See `TransparentProxyFlowProtocol`.
    pub protocol: u32,
    /// Source-app PID, when the system reported one.
    pub pid: i64,
}

/// Emitted from the bridge close path with per-direction byte counts.
#[derive(TraceEvent)]
pub struct TproxyFlowClosed {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub flow_id: u64,
    /// Wall-clock age of the flow at close time, in milliseconds.
    pub age_ms: u64,
    /// Bytes carried in the client → server / "in" direction.
    pub bytes_in: u64,
    /// Bytes carried in the server → client / "out" direction.
    pub bytes_out: u64,
}

/// Emitted when the configured decision deadline elapsed before the flow
/// handler returned a decision.
#[derive(TraceEvent)]
pub struct TproxyHandlerDeadline {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub flow_id: u64,
    /// Configured deadline that elapsed, in milliseconds.
    pub deadline_ms: u64,
}

#[inline]
pub(crate) fn record_flow_opened(flow_id: u64, protocol: u32, pid: Option<i32>) {
    let handle = TelemetryHandle::current();
    if handle.is_enabled() {
        record_event(
            TproxyFlowOpened {
                timestamp_ns: clock_monotonic_ns(),
                flow_id,
                protocol,
                pid: pid.map(i64::from).unwrap_or(0),
            },
            &handle,
        );
    }
}

#[inline]
pub(crate) fn record_flow_closed(flow_id: u64, age_ms: u64, bytes_in: u64, bytes_out: u64) {
    let handle = TelemetryHandle::current();
    if handle.is_enabled() {
        record_event(
            TproxyFlowClosed {
                timestamp_ns: clock_monotonic_ns(),
                flow_id,
                age_ms,
                bytes_in,
                bytes_out,
            },
            &handle,
        );
    }
}

#[inline]
pub(crate) fn record_handler_deadline(flow_id: u64, deadline_ms: u64) {
    let handle = TelemetryHandle::current();
    if handle.is_enabled() {
        record_event(
            TproxyHandlerDeadline {
                timestamp_ns: clock_monotonic_ns(),
                flow_id,
                deadline_ms,
            },
            &handle,
        );
    }
}
