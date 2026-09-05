//! Pre-defined [dial9] events for the transparent proxy engine, plus
//! tiny recording helpers that emit them when a
//! `dial9` recorder is attached to the runtime.
//!
//! Mirrors the structured `tracing` events emitted by the engine
//! (`open` / `close` / `handler-deadline`), encoded for fast offline
//! analysis with `dial9-viewer` and friends.
//!
//! Enabled with the `dial9` cargo feature on this crate. Emission is a
//! no-op when no recorder is attached.
//!
//! [dial9]: https://github.com/dial9-rs/dial9

use dial9::Dial9Handle;
use dial9::core::clock_monotonic_ns;
use dial9_trace_format::TraceEvent;
use rama_net::proxy::BridgeCloseReason;

/// Emitted right after the engine has assigned a `flow_id` to a new
/// transparent-proxy flow and decided how to handle it.
#[derive(TraceEvent)]
pub struct TproxyFlowOpened {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    /// PID of the Network Extension provider process.
    pub provider_pid: u32,
    /// Process-local immutable engine-generation identity.
    pub provider_generation: u64,
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
    pub provider_pid: u32,
    pub provider_generation: u64,
    pub flow_id: u64,
    /// `1` for TCP, `2` for UDP. See `TransparentProxyFlowProtocol`.
    pub protocol: u32,
    /// Source-app PID, when the system reported one.
    pub pid: i64,
    /// Structured close reason. For TCP this is the first normalized terminal
    /// reason observed across both bridge directions; flow-wide shutdown,
    /// idle-timeout, and service-panic outcomes override it.
    pub reason: BridgeCloseReason,
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
pub(crate) fn record_flow_opened(
    provider_pid: u32,
    provider_generation: u64,
    flow_id: u64,
    protocol: u32,
    pid: Option<i32>,
) {
    let handle = Dial9Handle::current();
    if handle.is_enabled() {
        handle.record_event(TproxyFlowOpened {
            timestamp_ns: clock_monotonic_ns(),
            provider_pid,
            provider_generation,
            flow_id,
            protocol,
            pid: pid.map(i64::from).unwrap_or(0),
        });
    }
}

#[inline]
pub(crate) fn record_flow_closed(
    provider_pid: u32,
    provider_generation: u64,
    meta: &super::TransparentProxyFlowMeta,
    reason: BridgeCloseReason,
    age_ms: u64,
    bytes_in: u64,
    bytes_out: u64,
) {
    let handle = Dial9Handle::current();
    if handle.is_enabled() {
        handle.record_event(TproxyFlowClosed {
            timestamp_ns: clock_monotonic_ns(),
            provider_pid,
            provider_generation,
            flow_id: meta.flow_id,
            protocol: meta.protocol.as_u32(),
            pid: meta.source_app_pid.map(i64::from).unwrap_or(0),
            reason,
            age_ms,
            bytes_in,
            bytes_out,
        });
    }
}

#[inline]
pub(crate) fn record_handler_deadline(flow_id: u64, deadline_ms: u64) {
    let handle = Dial9Handle::current();
    if handle.is_enabled() {
        handle.record_event(TproxyHandlerDeadline {
            timestamp_ns: clock_monotonic_ns(),
            flow_id,
            deadline_ms,
        });
    }
}
