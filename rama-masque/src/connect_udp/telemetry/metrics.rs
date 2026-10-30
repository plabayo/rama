use std::{borrow::Cow, fmt, sync::Arc, time::Duration};

use rama_core::{
    extensions::Extensions,
    telemetry::opentelemetry::{
        AttributesFactory, InstrumentationScope, KeyValue, MeterOptions, global,
        metrics::{Counter, Histogram, Meter, UpDownCounter},
        semantic_conventions,
    },
};

use super::{ConnectUdpStats, TunnelEnd};

const DURATION_BOUNDS: &[f64] = &[
    0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 900.0, 1800.0, 3600.0, 14400.0, 86400.0,
];

/// Metrics of the tunnels of a [`ConnectUdpService`](crate::connect_udp::ConnectUdpService)
/// built [with them](crate::connect_udp::ConnectUdpService::with_metrics).
///
/// Every series carries `principal.kind` when the service tracks principals (a per-principal
/// limit or budget is set): `user`, `token`, `ip` or `anonymous` for the default keyer's
/// [`PrincipalKey`](crate::connect_udp::PrincipalKey), `ip` for an IP address key, `custom` for
/// any other key type. A principal's key itself is never exported.
///
/// - `connect_udp.tunnels.active`: tunnels opened and not yet ended;
/// - `connect_udp.tunnel.refused` {`reason`}: requests refused, by their `Proxy-Status` error
///   type;
/// - `connect_udp.tunnel.closed` and `connect_udp.tunnel.duration` {`reason` = `closed`,
///   `idle`, `failed`, `capacity`, `upgrade_failed`, `relay_failed`, `cancelled`}: tunnels
///   ended, once each, when their task ends: as the relay returns, or when the proxy drops the
///   task (`cancelled`), whatever handles of the tunnel the relay kept;
/// - `connect_udp.datagrams.from_client` {`outcome` = `forwarded`, `unknown_context`,
///   `oversize`, `rate_limited`, `over_quota`, `unanswered`} and
///   `connect_udp.datagrams.from_client.carrier` {`carrier` = `native`, `capsule`}: each sums
///   to the HTTP Datagrams received;
/// - `connect_udp.datagrams.to_client` {`outcome` = `returned`, `rate_limited`, `over_quota`,
///   `too_large`, `unsent`}: sums to the datagrams accepted to send to the client;
/// - `connect_udp.bytes.received`, `.oversize_declared`, `.forwarded`, `.returned` and
///   `.returned_dropped`: the byte counts of [`ConnectUdpStats`]; `oversize_declared` is what
///   oversized capsules announced, not what arrived.
///
/// Datagram and byte counts are recorded as they are when a tunnel's task ends; what a send
/// handle the relay kept moves after that is not. [`ConnectUdpMetrics::with_attributes`] adds
/// attributes of each request to its series. Cheap to clone; clones report into the same series.
#[derive(Clone)]
pub struct ConnectUdpMetrics {
    inner: Arc<Instruments>,
    factory: Option<Arc<dyn AttributesFactory>>,
}

impl fmt::Debug for ConnectUdpMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectUdpMetrics")
            .field("inner", &self.inner)
            .field("factory", &self.factory.is_some())
            .finish()
    }
}

#[derive(Debug)]
struct Instruments {
    base: Box<[KeyValue]>,
    active: UpDownCounter<i64>,
    refused: Counter<u64>,
    closed: Counter<u64>,
    duration: Histogram<f64>,
    from_client: Counter<u64>,
    carrier: Counter<u64>,
    to_client: Counter<u64>,
    received_bytes: Counter<u64>,
    oversize_declared_bytes: Counter<u64>,
    forwarded_bytes: Counter<u64>,
    returned_bytes: Counter<u64>,
    returned_dropped_bytes: Counter<u64>,
}

impl ConnectUdpMetrics {
    /// Metrics recorded with the global meter provider.
    #[must_use]
    pub fn new(options: MeterOptions) -> Self {
        Self::new_with_meter(&versioned_meter(), options)
    }

    /// Metrics recorded with `meter`.
    #[must_use]
    pub fn new_with_meter(meter: &Meter, options: MeterOptions) -> Self {
        let prefix = options.metric_prefix.as_deref();
        let datagrams = |name, description| {
            meter
                .u64_counter(self::name(prefix, name))
                .with_unit("{datagram}")
                .with_description(description)
                .build()
        };
        let bytes = |name, description| {
            meter
                .u64_counter(self::name(prefix, name))
                .with_unit("By")
                .with_description(description)
                .build()
        };
        Self {
            inner: Arc::new(Instruments {
                active: meter
                    .i64_up_down_counter(name(prefix, "connect_udp.tunnels.active"))
                    .with_unit("{tunnel}")
                    .with_description("Tunnels opened and not yet ended")
                    .build(),
                refused: meter
                    .u64_counter(name(prefix, "connect_udp.tunnel.refused"))
                    .with_unit("{tunnel}")
                    .with_description("CONNECT-UDP requests refused, by Proxy-Status error type")
                    .build(),
                closed: meter
                    .u64_counter(name(prefix, "connect_udp.tunnel.closed"))
                    .with_unit("{tunnel}")
                    .with_description("Tunnels ended, by reason")
                    .build(),
                duration: meter
                    .f64_histogram(name(prefix, "connect_udp.tunnel.duration"))
                    .with_unit("s")
                    .with_boundaries(DURATION_BOUNDS.to_vec())
                    .with_description("Time from a tunnel's opening to its end")
                    .build(),
                from_client: datagrams(
                    "connect_udp.datagrams.from_client",
                    "HTTP Datagrams received from clients, by what became of them",
                ),
                carrier: datagrams(
                    "connect_udp.datagrams.from_client.carrier",
                    "HTTP Datagrams received from clients, by the carrier they arrived on",
                ),
                to_client: datagrams(
                    "connect_udp.datagrams.to_client",
                    "Datagrams taken to send to clients, by what became of them",
                ),
                received_bytes: bytes(
                    "connect_udp.bytes.received",
                    "Bytes after the Context ID of HTTP Datagrams received from clients",
                ),
                oversize_declared_bytes: bytes(
                    "connect_udp.bytes.oversize_declared",
                    "Bytes oversized DATAGRAM capsules from clients declared after their Context ID",
                ),
                forwarded_bytes: bytes(
                    "connect_udp.bytes.forwarded",
                    "UDP payload bytes forwarded toward targets",
                ),
                returned_bytes: bytes(
                    "connect_udp.bytes.returned",
                    "UDP payload bytes sent on to clients",
                ),
                returned_dropped_bytes: bytes(
                    "connect_udp.bytes.returned_dropped",
                    "UDP payload bytes from targets dropped before reaching clients",
                ),
                base: options.attributes.unwrap_or_default().into(),
            }),
            factory: None,
        }
    }

    /// Add attributes of each CONNECT-UDP request to the series it records into: `factory` is
    /// asked once per refused or opened tunnel, with the request's extensions. Its attributes are
    /// exported as given, so they must stay few in values.
    #[must_use]
    pub fn with_attributes<F: AttributesFactory>(mut self, factory: F) -> Self {
        self.factory = Some(Arc::new(factory));
        self
    }

    fn attributes(
        &self,
        principal: Option<&'static str>,
        extensions: &Extensions,
        extra: usize,
    ) -> Vec<KeyValue> {
        let hint = self.inner.base.len() + 1 + extra;
        let mut attributes = match &self.factory {
            Some(factory) => factory.attributes(hint, extensions),
            None => Vec::with_capacity(hint),
        };
        attributes.extend_from_slice(&self.inner.base);
        if let Some(kind) = principal {
            attributes.push(KeyValue::new("principal.kind", kind));
        }
        attributes
    }

    pub(super) fn refused(
        &self,
        reason: &'static str,
        principal: Option<&'static str>,
        extensions: &Extensions,
    ) {
        let mut attributes = self.attributes(principal, extensions, 1);
        attributes.push(KeyValue::new("reason", reason));
        self.inner.refused.add(1, &attributes);
    }

    /// Count an opened tunnel; answers the attributes its series carry.
    pub(super) fn opened(
        &self,
        principal: Option<&'static str>,
        extensions: &Extensions,
    ) -> Box<[KeyValue]> {
        let attributes = self.attributes(principal, extensions, 1);
        self.inner.active.add(1, &attributes);
        attributes.into()
    }

    pub(super) fn closed(
        &self,
        end: TunnelEnd,
        tunnel: &[KeyValue],
        duration: Duration,
        stats: &ConnectUdpStats,
    ) {
        let instruments = &self.inner;
        let mut attributes = Vec::with_capacity(tunnel.len() + 1);
        attributes.extend_from_slice(tunnel);
        instruments.active.add(-1, &attributes);
        let plain = attributes.len();

        let ConnectUdpStats {
            received: _,
            native,
            capsule,
            forwarded,
            dropped_unknown_context,
            dropped_oversize,
            dropped_rate_limited,
            dropped_over_quota,
            dropped_unanswered,
            returned,
            returned_dropped_rate_limited,
            returned_dropped_over_quota,
            returned_dropped_too_large,
            returned_dropped_unsent,
            received_bytes,
            oversize_declared_bytes,
            forwarded_bytes,
            returned_bytes,
            returned_dropped_bytes,
        } = *stats;
        for (counter, value) in [
            (&instruments.received_bytes, received_bytes),
            (
                &instruments.oversize_declared_bytes,
                oversize_declared_bytes,
            ),
            (&instruments.forwarded_bytes, forwarded_bytes),
            (&instruments.returned_bytes, returned_bytes),
            (&instruments.returned_dropped_bytes, returned_dropped_bytes),
        ] {
            if value > 0 {
                counter.add(value, &attributes);
            }
        }

        let mut partition =
            |counter: &Counter<u64>, key: &'static str, parts: &[(&'static str, u64)]| {
                for &(name, value) in parts {
                    if value == 0 {
                        continue;
                    }
                    attributes.truncate(plain);
                    attributes.push(KeyValue::new(key, name));
                    counter.add(value, &attributes);
                }
            };
        partition(
            &instruments.from_client,
            "outcome",
            &[
                ("forwarded", forwarded),
                ("unknown_context", dropped_unknown_context),
                ("oversize", dropped_oversize),
                ("rate_limited", dropped_rate_limited),
                ("over_quota", dropped_over_quota),
                ("unanswered", dropped_unanswered),
            ],
        );
        partition(
            &instruments.carrier,
            "carrier",
            &[("native", native), ("capsule", capsule)],
        );
        partition(
            &instruments.to_client,
            "outcome",
            &[
                ("returned", returned),
                ("rate_limited", returned_dropped_rate_limited),
                ("over_quota", returned_dropped_over_quota),
                ("too_large", returned_dropped_too_large),
                ("unsent", returned_dropped_unsent),
            ],
        );

        attributes.truncate(plain);
        attributes.push(KeyValue::new("reason", end.as_str()));
        instruments.closed.add(1, &attributes);
        instruments
            .duration
            .record(duration.as_secs_f64(), &attributes);
    }
}

fn versioned_meter() -> Meter {
    global::meter_with_scope(
        InstrumentationScope::builder("rama-masque")
            .with_version(rama_utils::info::VERSION)
            .with_schema_url(semantic_conventions::SCHEMA_URL)
            .build(),
    )
}

fn name<'a>(prefix: Option<&str>, name: &'a str) -> Cow<'a, str> {
    match prefix {
        Some(prefix) => Cow::Owned(format!("{prefix}.{name}")),
        None => Cow::Borrowed(name),
    }
}
