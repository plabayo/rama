//! Http OpenTelemetry [`Layer`] Support for Rama.
//!
//! [`Layer`]: crate::service::Layer

use crate::telemetry::opentelemetry::{
    global,
    metrics::{Histogram, Meter, Unit, UpDownCounter},
    semantic_conventions, KeyValue,
};
use crate::{
    service::{Context, Layer, Service},
    stream::SocketInfo,
};
use std::{fmt, sync::Arc, time::SystemTime};

use semantic_conventions::trace::{CLIENT_ADDRESS, CLIENT_PORT, NETWORK_TRANSPORT, NETWORK_TYPE};

const NETWORK_CONNECTION_DURATION: &str = "network.server.connection_duration";
const NETWORK_SERVER_ACTIVE_CONNECTIONS: &str = "network.server.active_connections";

/// Records network server metrics
#[derive(Clone, Debug)]
struct Metrics {
    network_connection_duration: Histogram<f64>,
    network_active_connections: UpDownCounter<i64>,
}

impl Metrics {
    /// Create a new [`NetworkMetrics`]
    fn new(meter: Meter) -> Self {
        let network_connection_duration = meter
            .f64_histogram(NETWORK_CONNECTION_DURATION)
            .with_description("Measures the duration of inbound network connections.")
            .with_unit(Unit::new("s"))
            .init();

        let network_active_connections = meter
            .i64_up_down_counter(NETWORK_SERVER_ACTIVE_CONNECTIONS)
            .with_description(
                "Measures the number of concurrent network connections that are currently in-flight.",
            )
            .init();

        Metrics {
            network_connection_duration,
            network_active_connections,
        }
    }
}

#[derive(Debug, Clone)]
/// A layer that records network server metrics using OpenTelemetry.
pub struct NetworkMetricsLayer {
    metrics: Arc<Metrics>,
}

impl NetworkMetricsLayer {
    /// Create a new [`NetworkMetricsLayer`] using the global [`Meter`] provider.
    pub fn new() -> Self {
        let meter = get_versioned_meter();
        let metrics = Metrics::new(meter);
        Self {
            metrics: Arc::new(metrics),
        }
    }
}

impl Default for NetworkMetricsLayer {
    fn default() -> Self {
        Self::new()
    }
}

/// construct meters for this crate
fn get_versioned_meter() -> Meter {
    global::meter_with_version(
        crate::utils::info::NAME,
        Some(crate::utils::info::VERSION),
        Some(semantic_conventions::SCHEMA_URL),
        None,
    )
}

impl<S> Layer<S> for NetworkMetricsLayer {
    type Service = NetworkMetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        NetworkMetricsService {
            inner,
            metrics: self.metrics.clone(),
        }
    }
}

/// A [`Service`] that records network server metrics using OpenTelemetry.
pub struct NetworkMetricsService<S> {
    inner: S,
    metrics: Arc<Metrics>,
}

impl<S: fmt::Debug> fmt::Debug for NetworkMetricsService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkMetricsService")
            .field("inner", &self.inner)
            .field("metrics", &self.metrics)
            .finish()
    }
}

impl<S, State, Stream> Service<State, Stream> for NetworkMetricsService<S>
where
    S: Service<State, Stream>,
    State: Send + Sync + 'static,
    Stream: crate::stream::Stream,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        stream: Stream,
    ) -> Result<Self::Response, Self::Error> {
        let attributes: Vec<KeyValue> = compute_attributes(&ctx);

        self.metrics.network_active_connections.add(1, &attributes);

        // used to compute the duration of the connection
        let timer = SystemTime::now();

        let result = self.inner.serve(ctx, stream).await;
        self.metrics.network_active_connections.add(-1, &attributes);

        match result {
            Ok(res) => {
                self.metrics.network_connection_duration.record(
                    timer.elapsed().map(|t| t.as_secs_f64()).unwrap_or_default(),
                    &attributes,
                );
                Ok(res)
            }
            Err(err) => Err(err),
        }
    }
}

fn compute_attributes<State>(ctx: &Context<State>) -> Vec<KeyValue> {
    let mut attributes = Vec::with_capacity(4);

    // client info
    if let Some(socket_info) = ctx.get::<SocketInfo>() {
        let peer_addr = socket_info.peer_addr();
        attributes.push(KeyValue::new(CLIENT_ADDRESS, peer_addr.ip().to_string()));
        attributes.push(KeyValue::new(
            NETWORK_TYPE,
            if peer_addr.is_ipv4() { "ipv4" } else { "ipv6" },
        ));
        attributes.push(KeyValue::new(CLIENT_PORT, peer_addr.port() as i64));
    }

    // connection info
    attributes.push(KeyValue::new(NETWORK_TRANSPORT, "tcp")); // TODO: do not hardcode this once we support UDP

    attributes
}
