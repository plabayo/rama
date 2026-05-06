//! Pre-defined [dial9] runtime-telemetry events for DNS lookup
//! lifecycle, plus tiny recording helpers that emit them when a
//! `dial9-tokio-telemetry::TracedRuntime` is active.
//!
//! Two events:
//!
//! - [`DnsLookupStarted`] — emitted at the entry to a lookup operation.
//! - [`DnsLookupResolved`] — emitted on completion, carrying the
//!   queried domain, query family (4 / 6), and outcome flags.
//!
//! [dial9]: https://github.com/dial9-rs/dial9-tokio-telemetry

use dial9_tokio_telemetry::telemetry::{TelemetryHandle, clock_monotonic_ns, record_event};
use dial9_trace_format::TraceEvent;

/// DNS lookup initiation.
#[derive(TraceEvent)]
pub struct DnsLookupStarted {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub domain: String,
    /// `4` for A records, `6` for AAAA records, `0` for combined.
    pub query_family: u32,
}

/// DNS lookup resolution outcome.
#[derive(TraceEvent)]
pub struct DnsLookupResolved {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub domain: String,
    pub query_family: u32,
    /// Wall-clock duration of the lookup, in milliseconds.
    pub elapsed_ms: u64,
    /// Whether at least one record was returned.
    pub success: bool,
}

#[inline]
pub(crate) fn record_lookup_started(domain: &str, query_family: u8) {
    let handle = TelemetryHandle::current();
    if handle.is_enabled() {
        record_event(
            DnsLookupStarted {
                timestamp_ns: clock_monotonic_ns(),
                domain: domain.to_owned(),
                query_family: query_family as u32,
            },
            &handle,
        );
    }
}

#[inline]
pub(crate) fn record_lookup_resolved(
    domain: &str,
    query_family: u8,
    elapsed_ms: u64,
    success: bool,
) {
    let handle = TelemetryHandle::current();
    if handle.is_enabled() {
        record_event(
            DnsLookupResolved {
                timestamp_ns: clock_monotonic_ns(),
                domain: domain.to_owned(),
                query_family: query_family as u32,
                elapsed_ms,
                success,
            },
            &handle,
        );
    }
}
