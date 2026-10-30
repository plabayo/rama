use super::*;

#[test]
fn ends_and_refusals_have_bounded_names() {
    assert_eq!(TunnelEnd::from(ConnectUdpClose::Idle).as_str(), "idle");
    assert_eq!(
        TunnelEnd::from(ConnectUdpClose::Capacity).as_str(),
        "capacity"
    );
    assert_eq!(TunnelEnd::Cancelled.as_str(), "cancelled");
    assert_eq!(
        refusal_reason(&ProxyErrorType::DestinationIpProhibited),
        "destination_ip_prohibited"
    );
    assert_eq!(
        refusal_reason(&ProxyErrorType::Other("caller-chosen".into())),
        "other"
    );
}

#[cfg(feature = "opentelemetry")]
pub(crate) mod metrics {
    use std::{
        num::NonZeroU16,
        sync::{Arc, atomic::AtomicUsize},
        time::Duration,
    };

    use parking_lot::Mutex;
    use rama_core::telemetry::opentelemetry::{
        KeyValue, MeterOptions,
        metrics::MeterProvider as _,
        sdk::{
            error::OTelSdkResult,
            metrics::{
                PeriodicReader, SdkMeterProvider, Temporality,
                data::{AggregatedMetrics, MetricData, ResourceMetrics},
                exporter::PushMetricExporter,
            },
        },
    };
    use rama_net::address::Host;

    use super::*;

    /// One exported point: its metric, attributes, value (a sum's, or a histogram's count) and,
    /// for a histogram, the sum of its samples.
    #[derive(Debug, Clone)]
    pub(crate) struct Point {
        name: String,
        attributes: Vec<KeyValue>,
        value: i64,
        sum: f64,
    }

    /// Keeps the points of the latest export; cumulative, so they are the whole state.
    #[derive(Debug, Clone, Default)]
    pub(crate) struct Capture(Arc<Mutex<Vec<Point>>>);

    impl PushMetricExporter for Capture {
        async fn export(&self, metrics: &ResourceMetrics) -> OTelSdkResult {
            let mut points = Vec::new();
            for metric in metrics.scope_metrics().flat_map(|scope| scope.metrics()) {
                let name = metric.name();
                let point = |attributes: Vec<KeyValue>, value: i64, sum: f64| Point {
                    name: name.to_owned(),
                    attributes,
                    value,
                    sum,
                };
                match metric.data() {
                    AggregatedMetrics::U64(MetricData::Sum(data)) => {
                        points.extend(data.data_points().map(|p| {
                            point(p.attributes().cloned().collect(), p.value() as i64, 0.0)
                        }));
                    }
                    AggregatedMetrics::I64(MetricData::Sum(data)) => {
                        points.extend(
                            data.data_points()
                                .map(|p| point(p.attributes().cloned().collect(), p.value(), 0.0)),
                        );
                    }
                    AggregatedMetrics::F64(MetricData::Histogram(data)) => {
                        points.extend(data.data_points().map(|p| {
                            point(p.attributes().cloned().collect(), p.count() as i64, p.sum())
                        }));
                    }
                    // Anything else exports no points, which the exact expectations reject.
                    _ => {}
                }
            }
            *self.0.lock() = points;
            Ok(())
        }

        fn force_flush(&self) -> OTelSdkResult {
            Ok(())
        }

        fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
            Ok(())
        }

        fn temporality(&self) -> Temporality {
            Temporality::Cumulative
        }
    }

    pub(crate) struct Collector {
        provider: SdkMeterProvider,
        capture: Capture,
        telemetry: TunnelTelemetry,
    }

    impl Collector {
        pub(crate) fn new() -> Self {
            let capture = Capture::default();
            let provider = SdkMeterProvider::builder()
                .with_reader(PeriodicReader::builder(capture.clone()).build())
                .build();
            let metrics = ConnectUdpMetrics::new_with_meter(
                &provider.meter("rama-masque-test"),
                MeterOptions::default(),
            );
            Self {
                provider,
                capture,
                telemetry: TunnelTelemetry {
                    metrics: Some(metrics),
                },
            }
        }

        /// Every exported point of `name`.
        fn exported(&self, name: &str) -> Vec<Point> {
            self.provider.force_flush().unwrap();
            self.capture
                .0
                .lock()
                .iter()
                .filter(|point| point.name == name)
                .cloned()
                .collect()
        }

        /// Every exported point of `name`: a sum's value, or a histogram's count.
        pub(crate) fn points(&self, name: &str) -> Vec<(Vec<KeyValue>, i64)> {
            self.exported(name)
                .into_iter()
                .map(|point| (point.attributes, point.value))
                .collect()
        }

        /// The sum of every sample of the histogram `name`.
        pub(crate) fn histogram_sum(&self, name: &str) -> f64 {
            self.exported(name).iter().map(|point| point.sum).sum()
        }

        pub(crate) fn metrics(&self) -> ConnectUdpMetrics {
            self.telemetry.metrics.clone().unwrap()
        }

        /// The sum of the points carrying every attribute in `filter`.
        pub(crate) fn value(&self, name: &str, filter: &[KeyValue]) -> i64 {
            self.points(name)
                .iter()
                .filter(|(attributes, _)| filter.iter().all(|kv| attributes.contains(kv)))
                .map(|(_, value)| value)
                .sum()
        }
    }

    fn target() -> ConnectUdpTarget {
        ConnectUdpTarget::new(Host::LOCALHOST_IPV4, NonZeroU16::MIN)
    }

    fn opened(collector: &Collector, principal: Option<&'static str>) -> TunnelObserver {
        collector.telemetry.opened(
            &target(),
            SocketAddress::local_ipv4(9),
            Some(SocketAddress::local_ipv4(10)),
            principal,
            &Extensions::new(),
        )
    }

    pub(crate) fn kv(key: &'static str, value: &'static str) -> KeyValue {
        KeyValue::new(key, value)
    }

    #[tokio::test(start_paused = true)]
    async fn an_ended_tunnel_records_its_partitions_and_bytes_once() {
        let collector = Collector::new();
        let observer = opened(&collector, Some("user"));
        assert_eq!(collector.value("connect_udp.tunnels.active", &[]), 1);
        tokio::time::advance(Duration::from_secs(3)).await;
        let stats = ConnectUdpStats {
            received: 9,
            native: 6,
            capsule: 3,
            forwarded: 4,
            dropped_unknown_context: 1,
            dropped_oversize: 1,
            dropped_rate_limited: 1,
            dropped_over_quota: 1,
            dropped_unanswered: 1,
            returned: 5,
            returned_dropped_rate_limited: 1,
            returned_dropped_over_quota: 0,
            returned_dropped_too_large: 2,
            returned_dropped_unsent: 1,
            received_bytes: 900,
            oversize_declared_bytes: 70_000,
            forwarded_bytes: 400,
            returned_bytes: 500,
            returned_dropped_bytes: 40,
        };
        observer.finish(TunnelEnd::Idle, &stats);

        let user = kv("principal.kind", "user");
        assert_eq!(collector.value("connect_udp.tunnels.active", &[]), 0);
        let ended = [user.clone(), kv("reason", "idle")];
        assert_eq!(collector.value("connect_udp.tunnel.closed", &ended), 1);
        assert_eq!(collector.value("connect_udp.tunnel.duration", &ended), 1);
        let from_client = "connect_udp.datagrams.from_client";
        for (outcome, count) in [
            ("forwarded", 4),
            ("unknown_context", 1),
            ("oversize", 1),
            ("rate_limited", 1),
            ("over_quota", 1),
            ("unanswered", 1),
        ] {
            assert_eq!(
                collector.value(from_client, &[user.clone(), kv("outcome", outcome)]),
                count,
                "{outcome}"
            );
        }
        assert_eq!(collector.value(from_client, &[]), 9, "sums to received");
        let carrier = "connect_udp.datagrams.from_client.carrier";
        assert_eq!(collector.value(carrier, &[kv("carrier", "native")]), 6);
        assert_eq!(collector.value(carrier, &[kv("carrier", "capsule")]), 3);
        let to_client = "connect_udp.datagrams.to_client";
        assert_eq!(collector.value(to_client, &[kv("outcome", "returned")]), 5);
        assert_eq!(collector.value(to_client, &[kv("outcome", "too_large")]), 2);
        assert_eq!(collector.value(to_client, &[kv("outcome", "unsent")]), 1);
        assert_eq!(collector.value(to_client, &[]), 9);
        assert!(
            collector
                .points(to_client)
                .iter()
                .all(|(attributes, _)| !attributes.contains(&kv("outcome", "over_quota"))),
            "a reason with nothing dropped is not recorded"
        );
        for (name, bytes) in [
            ("connect_udp.bytes.received", 900),
            ("connect_udp.bytes.oversize_declared", 70_000),
            ("connect_udp.bytes.forwarded", 400),
            ("connect_udp.bytes.returned", 500),
            ("connect_udp.bytes.returned_dropped", 40),
        ] {
            assert_eq!(
                collector.value(name, std::slice::from_ref(&user)),
                bytes,
                "{name}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_duration_runs_from_opening_to_the_end() {
        let collector = Collector::new();
        let observer = opened(&collector, None);
        tokio::time::advance(Duration::from_secs(3)).await;
        observer.finish(TunnelEnd::Closed, &ConnectUdpStats::default());
        let sum = collector.histogram_sum("connect_udp.tunnel.duration");
        assert!((sum - 3.0).abs() < 1e-9, "{sum}");
    }

    #[tokio::test]
    async fn a_tunnel_dropped_unfinished_is_cancelled_and_untracked_ones_carry_no_kind() {
        let collector = Collector::new();
        drop(opened(&collector, None));
        assert_eq!(collector.value("connect_udp.tunnels.active", &[]), 0);
        let closed = collector.points("connect_udp.tunnel.closed");
        assert_eq!(closed, vec![(vec![kv("reason", "cancelled")], 1)]);
        assert!(
            collector
                .points("connect_udp.datagrams.from_client")
                .is_empty()
        );
        assert!(collector.points("connect_udp.bytes.received").is_empty());
    }

    #[tokio::test]
    async fn refusals_count_by_reason() {
        let collector = Collector::new();
        let target = target();
        for reason in ["dns_error", "dns_error", "connection_limit_reached"] {
            collector.telemetry.refused(&Refused {
                reason,
                target: Some(&target),
                address: None,
                client: None,
                principal: Some("ip"),
                extensions: &Extensions::new(),
            });
        }
        let refused = "connect_udp.tunnel.refused";
        assert_eq!(collector.value(refused, &[kv("reason", "dns_error")]), 2);
        assert_eq!(
            collector.value(
                refused,
                &[
                    kv("reason", "connection_limit_reached"),
                    kv("principal.kind", "ip")
                ]
            ),
            1
        );
        assert!(collector.points("connect_udp.tunnels.active").is_empty());
    }

    #[derive(Debug, Clone, rama_core::extensions::Extension)]
    struct Tier(&'static str);

    #[tokio::test]
    async fn request_attributes_label_every_series_of_their_tunnel() {
        let collector = Collector::new();
        let telemetry = TunnelTelemetry {
            metrics: Some(collector.metrics().with_attributes(
                |hint: usize, extensions: &Extensions| {
                    let mut attributes = Vec::with_capacity(hint + 1);
                    if let Some(Tier(tier)) = extensions.get_ref::<Tier>() {
                        attributes.push(KeyValue::new("tier", *tier));
                    }
                    attributes
                },
            )),
        };
        let gold = Extensions::new();
        gold.insert(Tier("gold"));
        let observer = telemetry.opened(
            &target(),
            SocketAddress::local_ipv4(9),
            None,
            Some("user"),
            &gold,
        );
        let tier = kv("tier", "gold");
        assert_eq!(
            collector.value("connect_udp.tunnels.active", std::slice::from_ref(&tier)),
            1
        );
        let stats = ConnectUdpStats {
            received: 1,
            capsule: 1,
            forwarded: 1,
            ..ConnectUdpStats::default()
        };
        observer.finish(TunnelEnd::Closed, &stats);
        telemetry.refused(&Refused {
            reason: "dns_error",
            target: None,
            address: None,
            client: None,
            principal: None,
            extensions: &gold,
        });
        for name in [
            "connect_udp.tunnel.closed",
            "connect_udp.tunnel.duration",
            "connect_udp.datagrams.from_client",
            "connect_udp.datagrams.from_client.carrier",
            "connect_udp.tunnel.refused",
        ] {
            assert_eq!(
                collector.value(name, std::slice::from_ref(&tier)),
                1,
                "{name}"
            );
        }
        assert_eq!(collector.value("connect_udp.tunnels.active", &[]), 0);
    }

    /// The factory is asked once per opened tunnel and once per refusal, with that request's
    /// extensions; a tunnel's end reuses what its opening got, whatever the factory says later.
    #[tokio::test]
    async fn the_factory_is_asked_once_per_tunnel_and_per_refusal() {
        let collector = Collector::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let telemetry = TunnelTelemetry {
            metrics: Some(collector.metrics().with_attributes({
                let calls = calls.clone();
                move |hint: usize, extensions: &Extensions| {
                    let call = calls.fetch_add(1, Ordering::Relaxed);
                    let mut attributes = Vec::with_capacity(hint + 2);
                    attributes.push(KeyValue::new(
                        "call",
                        if call == 0 { "first" } else { "later" },
                    ));
                    if let Some(Tier(tier)) = extensions.get_ref::<Tier>() {
                        attributes.push(KeyValue::new("tier", *tier));
                    }
                    attributes
                }
            })),
        };
        let gold = Extensions::new();
        gold.insert(Tier("gold"));
        let observer = telemetry.opened(&target(), SocketAddress::local_ipv4(9), None, None, &gold);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        observer.finish(TunnelEnd::Closed, &ConnectUdpStats::default());
        assert_eq!(calls.load(Ordering::Relaxed), 1, "the end asks nothing");
        let opening = [kv("call", "first"), kv("tier", "gold")];
        assert_eq!(collector.value("connect_udp.tunnel.closed", &opening), 1);
        assert_eq!(collector.value("connect_udp.tunnels.active", &opening), 0);
        assert_eq!(collector.value("connect_udp.tunnels.active", &[]), 0);

        let silver = Extensions::new();
        silver.insert(Tier("silver"));
        telemetry.refused(&Refused {
            reason: "dns_error",
            target: None,
            address: None,
            client: None,
            principal: None,
            extensions: &silver,
        });
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(
            collector.value(
                "connect_udp.tunnel.refused",
                &[kv("call", "later"), kv("tier", "silver")]
            ),
            1
        );

        // A service without metrics never asks it.
        let unconfigured = TunnelTelemetry::default();
        drop(unconfigured.opened(&target(), SocketAddress::local_ipv4(9), None, None, &gold));
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn without_a_collector_recording_is_a_no_op() {
        let telemetry = TunnelTelemetry {
            metrics: Some(ConnectUdpMetrics::new(MeterOptions::default())),
        };
        let observer = telemetry.opened(
            &target(),
            SocketAddress::local_ipv4(9),
            None,
            None,
            &Extensions::new(),
        );
        observer.finish(TunnelEnd::Closed, &ConnectUdpStats::default());
    }
}
