//! Connection diagnostics independent of qlog. Summaries reuse the transport's
//! existing counters; no packet or frame events are added to the hot path.

use crate::proto::{Connection, ConnectionError};
use dial9_trace_format::TraceEvent;
use rama_core::telemetry::dial9::{
    Dial9Handle, Operation, Outcome, TraceContext, core::clock_monotonic_ns,
};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(TraceEvent)]
pub struct QuicConnectionStarted {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub flow_id: u64,
    pub connection_id: u64,
    pub version: u32,
    pub server: bool,
}

#[derive(TraceEvent)]
pub struct QuicHandshakeCompleted {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub flow_id: u64,
    pub connection_id: u64,
    #[traceevent(unit = "ns")]
    pub duration_ns: u64,
    pub accepted_0rtt: bool,
}

/// Snapshot at the first terminal outcome, before the closing/draining period.
/// Byte totals are UDP payload bytes, not application bytes.
#[derive(TraceEvent)]
pub struct QuicConnectionClosed {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub flow_id: u64,
    pub connection_id: u64,
    /// 0 local close, 1 peer application close, 2 peer transport close,
    /// 3 transport error, 4 reset, 5 timeout, 6 version mismatch,
    /// 7 exhausted connection IDs, 8 driver/state dropped, 9 endpoint in use.
    pub reason: u32,
    /// Application or transport close code for reasons 1–3, zero otherwise.
    /// Application codes retain their protocol-specific meaning (for example HTTP/3).
    pub error_code: u64,
    pub handshake_completed: bool,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub datagrams_sent: u64,
    pub datagrams_received: u64,
    #[traceevent(unit = "ns")]
    pub rtt_ns: u64,
    pub congestion_window: u64,
    pub lost_packets: u64,
    pub lost_bytes: u64,
    pub congestion_events: u64,
    pub send_failures: u64,
    pub oversized_sends: u64,
}

#[derive(Debug)]
pub(crate) struct Lifecycle {
    operation: Option<Operation>,
}

impl Lifecycle {
    pub(crate) fn new(connection: &Connection) -> Self {
        let operation = Operation::new("quic.connection");
        operation.record_event_with(|context| QuicConnectionStarted {
            timestamp_ns: clock_monotonic_ns(),
            flow_id: context.flow_id(),
            connection_id: context.operation_id(),
            version: connection.version().into(),
            server: connection.side().is_server(),
        });
        Self {
            operation: operation.is_recorded().then_some(operation),
        }
    }

    pub(crate) fn context(&self) -> TraceContext {
        self.operation
            .as_ref()
            .map_or_else(TraceContext::default, Operation::context)
    }

    pub(crate) fn connected(&self, connection: &Connection) {
        if let Some(operation) = &self.operation {
            operation.record_event_with(|context| QuicHandshakeCompleted {
                timestamp_ns: clock_monotonic_ns(),
                flow_id: context.flow_id(),
                connection_id: context.operation_id(),
                duration_ns: u64::try_from(operation.elapsed().as_nanos()).unwrap_or(u64::MAX),
                accepted_0rtt: connection.accepted_0rtt(),
            });
        }
    }

    pub(crate) fn finish(
        &mut self,
        connection: &Connection,
        reason: Option<&ConnectionError>,
        connected: bool,
        send_failures: u64,
        oversized_sends: u64,
    ) {
        let Some(operation) = self.operation.take() else {
            return;
        };
        let reason_code = close_reason_code(reason);
        let stats = connection.stats();
        operation.record_event_with(|context| QuicConnectionClosed {
            timestamp_ns: clock_monotonic_ns(),
            flow_id: context.flow_id(),
            connection_id: context.operation_id(),
            reason: reason_code,
            error_code: match reason {
                Some(ConnectionError::ApplicationClosed(close)) => close.error_code.into_inner(),
                Some(ConnectionError::ConnectionClosed(close)) => close.error_code.into(),
                Some(ConnectionError::TransportError(error)) => error.code.into(),
                _ => 0,
            },
            handshake_completed: connected,
            bytes_sent: stats.udp_tx.bytes,
            bytes_received: stats.udp_rx.bytes,
            datagrams_sent: stats.udp_tx.datagrams,
            datagrams_received: stats.udp_rx.datagrams,
            rtt_ns: u64::try_from(stats.path.rtt.as_nanos()).unwrap_or(u64::MAX),
            congestion_window: stats.path.cwnd,
            lost_packets: stats.path.lost_packets,
            lost_bytes: stats.path.lost_bytes,
            congestion_events: stats.path.congestion_events,
            send_failures,
            oversized_sends,
        });
        operation.finish_with_bytes(
            match reason_code {
                0 | 1 if connected => Outcome::Success,
                5 => Outcome::Timeout,
                8 => Outcome::Cancelled,
                _ => Outcome::Error,
            },
            stats.udp_tx.bytes,
            stats.udp_rx.bytes,
        );
    }
}

/// Stable trace codes: append reasons without renumbering existing recordings.
fn close_reason_code(reason: Option<&ConnectionError>) -> u32 {
    match reason {
        Some(ConnectionError::LocallyClosed) => 0,
        Some(ConnectionError::ApplicationClosed(_)) => 1,
        Some(ConnectionError::ConnectionClosed(_)) => 2,
        Some(ConnectionError::TransportError(_)) => 3,
        Some(ConnectionError::Reset) => 4,
        Some(ConnectionError::TimedOut) => 5,
        Some(ConnectionError::VersionMismatch { .. }) => 6,
        Some(ConnectionError::CidsExhausted) => 7,
        None => 8,
        Some(ConnectionError::EndpointInUse) => 9,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_conflicts_have_their_own_close_reason() {
        assert_eq!(close_reason_code(Some(&ConnectionError::EndpointInUse)), 9);
        assert_eq!(close_reason_code(None), 8);
        assert_eq!(close_reason_code(Some(&ConnectionError::LocallyClosed)), 0);
        assert_eq!(close_reason_code(Some(&ConnectionError::TimedOut)), 5);
        assert_eq!(close_reason_code(Some(&ConnectionError::CidsExhausted)), 7);
    }
}

/// Control-plane routing counters for one directory. No addresses, CIDs or process identities
/// are recorded. Hits describe routing hints, not authenticated or validated migrations.
#[derive(TraceEvent)]
pub struct QuicRoutingSnapshot {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub resource_id: u64,
    pub flow_id: u64,
    pub operation_id: u64,
    pub reason: &'static str,
    pub registered_endpoints: u64,
    pub endpoint_limit: u64,
    pub endpoint_high_water: u64,
    pub routing_keys: u64,
    pub routing_keys_high_water: u64,
    pub registrations_rejected: u64,
    pub route_hits: u64,
    pub route_misses: u64,
    pub ambiguous_routes: u64,
}

/// Occupancy and pressure on a migration resource. Resource names and reasons are bounded
/// static strings; totals are cumulative within this resource's lifetime, not global gauges.
#[derive(TraceEvent)]
pub struct QuicMigrationCapacity {
    #[traceevent(timestamp)]
    pub timestamp_ns: u64,
    pub resource_id: u64,
    pub flow_id: u64,
    pub operation_id: u64,
    pub resource: &'static str,
    pub reason: &'static str,
    pub used: u64,
    pub limit: u64,
    pub high_water: u64,
    pub affected_total: u64,
}

#[cfg(feature = "boring")]
#[derive(Clone, Copy)]
pub(crate) struct CapacitySnapshot {
    pub resource: &'static str,
    pub reason: &'static str,
    pub used: usize,
    pub limit: usize,
    pub high_water: usize,
    pub affected_total: u64,
}

/// Allocate correlation only when an event is actually recorded, including when recording
/// starts after the registry was constructed. No recorder, clock or ID work on packet paths.
#[derive(Debug, Default)]
pub(crate) struct MigrationTelemetry {
    id: AtomicU64,
}

impl MigrationTelemetry {
    fn id(&self) -> u64 {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let current = self.id.load(Ordering::Relaxed);
        if current != 0 {
            return current;
        }
        let candidate = NEXT.fetch_add(1, Ordering::Relaxed);
        match self
            .id
            .compare_exchange(0, candidate, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => candidate,
            Err(existing) => existing,
        }
    }

    pub(crate) fn routing(&self, reason: &'static str, stats: crate::EndpointRouteStats) {
        Dial9Handle::current().record_event_with(|| {
            let context = TraceContext::current();
            QuicRoutingSnapshot {
                timestamp_ns: clock_monotonic_ns(),
                resource_id: self.id(),
                flow_id: context.flow_id(),
                operation_id: context.operation_id(),
                reason,
                registered_endpoints: stats.registered_endpoints as u64,
                endpoint_limit: stats.endpoint_limit as u64,
                endpoint_high_water: stats.endpoint_high_water as u64,
                routing_keys: stats.routing_keys as u64,
                routing_keys_high_water: stats.routing_keys_high_water as u64,
                registrations_rejected: stats.registrations_rejected,
                route_hits: stats.route_hits,
                route_misses: stats.route_misses,
                ambiguous_routes: stats.ambiguous_routes,
            }
        });
    }

    #[cfg(feature = "boring")]
    pub(crate) fn capacity(&self, stats: CapacitySnapshot) {
        Dial9Handle::current().record_event_with(|| {
            let context = TraceContext::current();
            QuicMigrationCapacity {
                timestamp_ns: clock_monotonic_ns(),
                resource_id: self.id(),
                flow_id: context.flow_id(),
                operation_id: context.operation_id(),
                resource: stats.resource,
                reason: stats.reason,
                used: stats.used as u64,
                limit: stats.limit as u64,
                high_water: stats.high_water as u64,
                affected_total: stats.affected_total,
            }
        });
    }
}

#[cfg(test)]
mod migration_tests {
    use super::*;

    #[test]
    fn disabled_recorder_does_not_allocate_resource_identity() {
        let telemetry = MigrationTelemetry::default();
        telemetry.routing("test", crate::EndpointRouteStats::default());
        assert_eq!(telemetry.id.load(Ordering::Relaxed), 0);
    }
}
