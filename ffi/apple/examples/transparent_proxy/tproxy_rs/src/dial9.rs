//! Optional dial9 runtime telemetry integration.
//!
//! This module is gated behind the `dial9` cargo feature. When enabled, custom
//! flow lifecycle events (open / close / handler-deadline) are emitted into
//! the dial9 trace alongside whatever runtime events
//! [`dial9-tokio-telemetry`] is recording.
//!
//! Wiring the dial9 runtime itself (i.e. swapping the example's
//! [`tokio::runtime::Runtime`] for a `TracedRuntime`) is left to the
//! consumer — see the README for guidance. The current rama
//! [`TransparentProxyAsyncRuntimeFactory`] returns a plain
//! `tokio::runtime::Runtime`; users who want deep dial9 instrumentation
//! should provide a custom factory that constructs the runtime via
//! `TracedRuntime::try_new` and exposes its underlying tokio handle.
//!
//! [`dial9-tokio-telemetry`]: https://crates.io/crates/dial9-tokio-telemetry

#![cfg(feature = "dial9")]
// These event types are public reference-implementation building blocks for
// consumers wiring dial9 into a transparent proxy. They are intentionally not
// emitted from the example's own code paths; users are expected to instantiate
// them at the corresponding lifecycle points after constructing a
// `dial9_tokio_telemetry::TracedRuntime` (see this crate's README).
#![allow(dead_code)]

use dial9_trace_format::TraceEvent;

/// Flow opened — emitted right after the engine assigns a flow_id.
#[derive(TraceEvent)]
pub struct TproxyFlowOpened {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub flow_id: u64,
    pub protocol: u32,
    pub pid: i64,
}

/// Flow closed — emitted from the bridge close path.
#[derive(TraceEvent)]
pub struct TproxyFlowClosed {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub flow_id: u64,
    pub age_ms: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// Flow handler exceeded the configured decision deadline.
#[derive(TraceEvent)]
pub struct TproxyHandlerDeadline {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub flow_id: u64,
    pub elapsed_ms: u64,
}
