//! Audit events and metrics of the tunnels a [`ConnectUdpService`](super::ConnectUdpService)
//! opens.

use std::sync::atomic::{AtomicU64, Ordering};

use rama_core::{extensions::Extensions, telemetry::tracing};
use rama_http::headers::ProxyErrorType;
use rama_net::address::SocketAddress;
use tokio::time::Instant;

use super::{ConnectUdpClose, ConnectUdpStats, ConnectUdpTarget};

#[cfg(feature = "opentelemetry")]
mod metrics;
#[cfg(feature = "opentelemetry")]
pub use metrics::ConnectUdpMetrics;
#[cfg(feature = "opentelemetry")]
use rama_core::telemetry::opentelemetry::KeyValue;

#[cfg(test)]
pub(crate) mod tests;

/// The tracing target of audit events.
pub(crate) const AUDIT_TARGET: &str = "rama_masque::connect_udp::audit";

/// Why a tunnel ended, as audit events and metrics name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TunnelEnd {
    Closed,
    Idle,
    Failed,
    Capacity,
    UpgradeFailed,
    RelayFailed,
    Cancelled,
}

impl TunnelEnd {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Idle => "idle",
            Self::Failed => "failed",
            Self::Capacity => "capacity",
            Self::UpgradeFailed => "upgrade_failed",
            Self::RelayFailed => "relay_failed",
            Self::Cancelled => "cancelled",
        }
    }
}

impl From<ConnectUdpClose> for TunnelEnd {
    fn from(close: ConnectUdpClose) -> Self {
        match close {
            ConnectUdpClose::Closed => Self::Closed,
            ConnectUdpClose::Idle => Self::Idle,
            ConnectUdpClose::Failed => Self::Failed,
            ConnectUdpClose::Capacity => Self::Capacity,
        }
    }
}

/// A refusal's `Proxy-Status` error type, from the bounded set the service answers with.
pub(crate) fn refusal_reason(error: &ProxyErrorType) -> &'static str {
    match error {
        ProxyErrorType::HttpRequestError => "http_request_error",
        ProxyErrorType::HttpRequestDenied => "http_request_denied",
        ProxyErrorType::ConnectionLimitReached => "connection_limit_reached",
        ProxyErrorType::ProxyInternalError => "proxy_internal_error",
        ProxyErrorType::DnsError => "dns_error",
        ProxyErrorType::DnsTimeout => "dns_timeout",
        ProxyErrorType::DestinationIpProhibited => "destination_ip_prohibited",
        ProxyErrorType::DestinationIpUnroutable => "destination_ip_unroutable",
        _ => "other",
    }
}

/// What a service records about its tunnels: audit events always, metrics when set.
#[derive(Debug, Clone, Default)]
pub(crate) struct TunnelTelemetry {
    #[cfg(feature = "opentelemetry")]
    pub(crate) metrics: Option<ConnectUdpMetrics>,
}

/// A refused tunnel, as its audit event and metrics see it.
pub(crate) struct Refused<'a> {
    pub(crate) reason: &'static str,
    pub(crate) target: Option<&'a ConnectUdpTarget>,
    pub(crate) address: Option<SocketAddress>,
    pub(crate) client: Option<SocketAddress>,
    pub(crate) principal: Option<&'static str>,
    /// The request's, for metric attributes only.
    #[cfg_attr(
        not(feature = "opentelemetry"),
        expect(dead_code, reason = "only metrics read the request's extensions")
    )]
    pub(crate) extensions: &'a Extensions,
}

impl TunnelTelemetry {
    /// Record a refused tunnel: one audit event and one count.
    #[cfg_attr(
        not(feature = "opentelemetry"),
        expect(
            clippy::unused_self,
            reason = "only metrics read the telemetry's state"
        )
    )]
    pub(crate) fn refused(&self, refused: &Refused<'_>) {
        tracing::info!(
            target: AUDIT_TARGET,
            event = "tunnel_refused",
            reason = refused.reason,
            tunnel.target = refused.target.map(tracing::field::display),
            tunnel.address = refused.address.map(tracing::field::display),
            client.address = refused.client.map(tracing::field::display),
            principal.kind = refused.principal,
            "connect-udp tunnel refused",
        );
        #[cfg(feature = "opentelemetry")]
        if let Some(metrics) = &self.metrics {
            metrics.refused(refused.reason, refused.principal, refused.extensions);
        }
    }

    /// Record an opened tunnel; the observer records its end, once.
    #[cfg_attr(
        not(feature = "opentelemetry"),
        expect(
            clippy::unused_self,
            reason = "only metrics read the telemetry's state"
        )
    )]
    pub(crate) fn opened(
        &self,
        target: &ConnectUdpTarget,
        address: SocketAddress,
        client: Option<SocketAddress>,
        principal: Option<&'static str>,
        extensions: &Extensions,
    ) -> TunnelObserver {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            target: AUDIT_TARGET,
            event = "tunnel_opened",
            tunnel.id = id,
            tunnel.target = %target,
            tunnel.address = %address,
            client.address = client.map(tracing::field::display),
            principal.kind = principal,
            "connect-udp tunnel opened",
        );
        #[cfg(not(feature = "opentelemetry"))]
        let _ = extensions;
        TunnelObserver {
            id,
            started: Instant::now(),
            principal,
            #[cfg(feature = "opentelemetry")]
            metrics: self.metrics.as_ref().map(|metrics| {
                let attributes = metrics.opened(principal, extensions);
                (metrics.clone(), attributes)
            }),
            finished: false,
        }
    }
}

/// One opened tunnel's record, finished exactly once: by [`TunnelObserver::finish`], or as
/// [`TunnelEnd::Cancelled`] when dropped unfinished.
#[derive(Debug)]
pub(crate) struct TunnelObserver {
    id: u64,
    started: Instant,
    principal: Option<&'static str>,
    /// The metrics and the attributes of this tunnel's series.
    #[cfg(feature = "opentelemetry")]
    metrics: Option<(ConnectUdpMetrics, Box<[KeyValue]>)>,
    finished: bool,
}

impl TunnelObserver {
    /// Record the tunnel's end with what it moved.
    pub(crate) fn finish(mut self, end: TunnelEnd, stats: &ConnectUdpStats) {
        self.record(end, stats);
    }

    fn record(&mut self, end: TunnelEnd, stats: &ConnectUdpStats) {
        if std::mem::replace(&mut self.finished, true) {
            return;
        }
        let duration = self.started.elapsed();
        tracing::info!(
            target: AUDIT_TARGET,
            event = "tunnel_closed",
            tunnel.id = self.id,
            reason = end.as_str(),
            duration_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
            principal.kind = self.principal,
            received = stats.received,
            received_bytes = stats.received_bytes,
            oversize_declared_bytes = stats.oversize_declared_bytes,
            forwarded = stats.forwarded,
            forwarded_bytes = stats.forwarded_bytes,
            returned = stats.returned,
            returned_bytes = stats.returned_bytes,
            returned_dropped_bytes = stats.returned_dropped_bytes,
            "connect-udp tunnel closed",
        );
        #[cfg(feature = "opentelemetry")]
        if let Some((metrics, attributes)) = &self.metrics {
            metrics.closed(end, attributes, duration, stats);
        }
    }
}

impl Drop for TunnelObserver {
    fn drop(&mut self) {
        self.record(TunnelEnd::Cancelled, &ConnectUdpStats::default());
    }
}
