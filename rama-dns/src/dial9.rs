//! Pre-defined [dial9] events for DNS lookups.
//!
//! [dial9]: https://github.com/dial9-rs/dial9-tokio-telemetry

use dial9_tokio_telemetry::telemetry::{TelemetryHandle, clock_monotonic_ns, record_event};
use dial9_trace_format::TraceEvent;
use rama_net::address::Domain;

/// DNS lookup initiation.
#[derive(TraceEvent)]
pub struct DnsLookupStarted {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub domain: Domain,
    /// `4` for A records, `6` for AAAA records, `0` for combined.
    pub query_family: u32,
}

/// DNS lookup resolution outcome.
#[derive(TraceEvent)]
pub struct DnsLookupResolved {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub domain: Domain,
    pub query_family: u32,
    /// Wall-clock duration of the lookup, in milliseconds.
    pub elapsed_ms: u64,
    /// Whether at least one record was returned.
    pub success: bool,
}

#[inline]
pub(crate) fn record_lookup_started(domain: Domain, query_family: u8) {
    let handle = TelemetryHandle::current();
    if handle.is_enabled() {
        record_event(
            DnsLookupStarted {
                timestamp_ns: clock_monotonic_ns(),
                domain,
                query_family: query_family as u32,
            },
            &handle,
        );
    }
}

#[inline]
pub(crate) fn record_lookup_resolved(
    domain: Domain,
    query_family: u8,
    elapsed_ms: u64,
    success: bool,
) {
    let handle = TelemetryHandle::current();
    if handle.is_enabled() {
        record_event(
            DnsLookupResolved {
                timestamp_ns: clock_monotonic_ns(),
                domain,
                query_family: query_family as u32,
                elapsed_ms,
                success,
            },
            &handle,
        );
    }
}
