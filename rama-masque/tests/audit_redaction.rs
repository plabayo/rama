//! Audit events name a tunnel's principal by kind only: no username, token or custom key
//! reaches the logs, nor, with metrics, any exported attribute.
//! In a test binary of its own, as tracing's callsite interest is shared by a whole process.

#![expect(clippy::unwrap_used, reason = "integration fixture setup")]

use std::{convert::Infallible, num::NonZeroU16, sync::Arc, time::Duration};

use parking_lot::Mutex;
use rama_core::{
    Service, ServiceInput, bytes::Bytes, error::BoxError, extensions::ExtensionsRef as _,
    rt::Executor, telemetry::tracing,
};
use rama_http::{
    Request, Response, StatusCode, Version,
    datagram::HttpDatagramSession,
    io::upgrade::{self, Upgraded},
};
use rama_masque::connect_udp::{
    ConnectUdpLimits, ConnectUdpService, ConnectUdpTarget, DestinationScopePolicy,
    connect_udp_request, session_config,
};
use rama_net::{
    address::{Host, ProxyAddress},
    rate::RateKey,
    user::UserId,
};
use tokio::{io::DuplexStream, net::UdpSocket};

const USERNAME: &str = "sentinel-username-7f3a";
const TOKEN: &str = "sentinel-token-9c1e";
const TENANT: &str = "sentinel-tenant-2b6d";
const SENTINELS: [&str; 3] = [USERNAME, TOKEN, TENANT];

/// Captures what a `fmt` subscriber writes.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn logs(&self) -> String {
        String::from_utf8_lossy(&self.0.lock()).into_owned()
    }
}

/// A key of its own, which prints and exports the tenant it names.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct Tenant(String);

impl RateKey for Tenant {
    #[cfg(feature = "opentelemetry")]
    fn attributes(
        &self,
    ) -> impl Iterator<Item = rama_core::telemetry::opentelemetry::KeyValue> + '_ {
        std::iter::once(rama_core::telemetry::opentelemetry::KeyValue::new(
            "tenant",
            self.0.clone(),
        ))
    }
}

type Client = HttpDatagramSession<ServiceInput<DuplexStream>>;

/// Serve a tunnel request to `target` as `user`, or with a tenant header; upgraded over an
/// in-memory stream when accepted.
async fn request(
    service: &impl Service<Request, Output = Response, Error = Infallible>,
    target: std::net::SocketAddr,
    user: Option<UserId>,
) -> (StatusCode, Option<Client>) {
    let proxy = ProxyAddress::try_from("masque://proxy.example:443").unwrap();
    let target = ConnectUdpTarget::new(
        Host::Address(target.ip()),
        NonZeroU16::new(target.port()).unwrap(),
    );
    let mut request = connect_udp_request(&proxy, &target, Version::HTTP_2).unwrap();
    if let Some(user) = user {
        request.extensions().insert(user);
    }
    request
        .headers_mut()
        .insert("x-tenant", TENANT.parse().unwrap());
    let (pending, on_upgrade) = upgrade::pending();
    request.extensions().insert(on_upgrade);
    let response = service.serve(request).await.unwrap();
    if response.status() != StatusCode::OK {
        return (response.status(), None);
    }
    let (proxy_end, client_end) = tokio::io::duplex(64 * 1024);
    pending.fulfill(Upgraded::new(ServiceInput::new(proxy_end), Bytes::new()));
    let client = HttpDatagramSession::with_config(ServiceInput::new(client_end), session_config());
    (response.status(), Some(client))
}

fn proxy() -> ConnectUdpService {
    ConnectUdpService::try_new(Executor::default(), None)
        .unwrap()
        .with_policy(DestinationScopePolicy::allow_private())
}

#[cfg(feature = "opentelemetry")]
mod metrics {
    use std::{sync::Arc, time::Duration};

    use parking_lot::Mutex;
    use rama_core::telemetry::opentelemetry::{
        MeterOptions,
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
    use rama_masque::connect_udp::ConnectUdpMetrics;

    /// Every metric name and point attribute of the latest export, rendered.
    #[derive(Debug, Clone, Default)]
    struct Capture(Arc<Mutex<String>>);

    impl PushMetricExporter for Capture {
        async fn export(&self, metrics: &ResourceMetrics) -> OTelSdkResult {
            let mut rendered = String::new();
            for metric in metrics.scope_metrics().flat_map(|scope| scope.metrics()) {
                rendered.push_str(metric.name());
                let attributes: Vec<_> = match metric.data() {
                    AggregatedMetrics::U64(MetricData::Sum(data)) => data
                        .data_points()
                        .flat_map(|point| point.attributes().cloned())
                        .collect(),
                    AggregatedMetrics::I64(MetricData::Sum(data)) => data
                        .data_points()
                        .flat_map(|point| point.attributes().cloned())
                        .collect(),
                    AggregatedMetrics::F64(MetricData::Histogram(data)) => data
                        .data_points()
                        .flat_map(|point| point.attributes().cloned())
                        .collect(),
                    _ => Vec::new(),
                };
                rendered.push_str(&format!(" {attributes:?}\n"));
            }
            *self.0.lock() = rendered;
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
        pub(crate) metrics: ConnectUdpMetrics,
    }

    impl Collector {
        pub(crate) fn new() -> Self {
            let capture = Capture::default();
            let provider = SdkMeterProvider::builder()
                .with_reader(PeriodicReader::builder(capture.clone()).build())
                .build();
            let metrics = ConnectUdpMetrics::new_with_meter(
                &provider.meter("rama-masque-redaction"),
                MeterOptions::default(),
            );
            Self {
                provider,
                capture,
                metrics,
            }
        }

        /// Every exported metric name and attribute, rendered.
        pub(crate) fn attributes(&self) -> String {
            self.provider.force_flush().unwrap();
            self.capture.0.lock().clone()
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn audit_events_and_metrics_never_name_a_principal() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    // Process-wide, before any callsite registers: no other test runs in this binary.
    tracing::subscriber::set_global_default(subscriber).unwrap();
    #[cfg(feature = "opentelemetry")]
    let collector = metrics::Collector::new();
    let with_metrics = |service: ConnectUdpService| {
        #[cfg(feature = "opentelemetry")]
        let service = service.with_metrics(collector.metrics.clone());
        service
    };

    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = target.local_addr().unwrap();
    let users = with_metrics(
        proxy().with_limits(ConnectUdpLimits::new().with_max_tunnels_per_principal(1)),
    );
    let tenants = with_metrics(
        proxy().with_limits(
            ConnectUdpLimits::new()
                .with_max_tunnels_per_principal(1)
                .with_keyer(|request: &Request| {
                    let tenant = request.headers().get("x-tenant").unwrap().to_str()?;
                    Ok::<_, BoxError>(Some(Tenant(tenant.to_owned())))
                }),
        ),
    );

    let username = || Some(UserId::Username(USERNAME.to_owned()));
    let token = || Some(UserId::Token(TOKEN.as_bytes().to_vec()));
    let mut clients = Vec::new();
    for (service, user) in [(&users, username()), (&users, token()), (&tenants, None)] {
        let (status, client) = request(service, target, user.clone()).await;
        assert_eq!(status, StatusCode::OK);
        clients.push(client.unwrap());
        // The principal's second tunnel is refused: the refusal names its kind too.
        let (status, _) = request(service, target, user).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }
    for mut client in clients {
        client.close().await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        while captured.logs().matches("connect-udp tunnel closed").count() < 3 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("every tunnel ends");

    let logs = captured.logs();
    for event in ["tunnel_opened", "tunnel_refused", "tunnel_closed"] {
        assert_eq!(logs.matches(event).count(), 3, "{event}: {logs}");
    }
    for kind in ["user", "token", "custom"] {
        assert!(
            logs.contains(&format!("principal.kind=\"{kind}\"")),
            "{kind}: {logs}"
        );
    }
    for sentinel in SENTINELS {
        assert!(!logs.contains(sentinel), "{sentinel}: {logs}");
    }

    #[cfg(feature = "opentelemetry")]
    {
        let attributes = collector.attributes();
        assert!(attributes.contains("custom"), "{attributes}");
        for sentinel in SENTINELS {
            assert!(!attributes.contains(sentinel), "{sentinel}: {attributes}");
        }
        assert!(!attributes.contains("tenant"), "{attributes}");
    }
}
