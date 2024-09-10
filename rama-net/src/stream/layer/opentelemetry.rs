//! Http OpenTelemetry [`Layer`] Support for Rama.
//!
//! [`Layer`]: rama_core::Layer

use crate::stream::SocketInfo;
use rama_core::telemetry::opentelemetry::semantic_conventions::trace::{
    NETWORK_TRANSPORT, NETWORK_TYPE,
};
use rama_core::telemetry::opentelemetry::AttributesFactory;
use rama_core::telemetry::opentelemetry::{
    global,
    metrics::{Histogram, Meter, UpDownCounter},
    semantic_conventions, KeyValue,
};
use rama_core::{Context, Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use std::borrow::Cow;
use std::net::IpAddr;
use std::{fmt, sync::Arc, time::SystemTime};

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
            .with_unit("s")
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

/// A layer that records network server metrics using OpenTelemetry.
pub struct NetworkMetricsLayer<F = ()> {
    metrics: Arc<Metrics>,
    attributes_factory: F,
}

impl<F: fmt::Debug> fmt::Debug for NetworkMetricsLayer<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("NetworkMetricsLayer")
            .field("metrics", &self.metrics)
            .field("attributes_factory", &self.attributes_factory)
            .finish()
    }
}

impl<F: Clone> Clone for NetworkMetricsLayer<F> {
    fn clone(&self) -> Self {
        NetworkMetricsLayer {
            metrics: self.metrics.clone(),
            attributes_factory: self.attributes_factory.clone(),
        }
    }
}

impl NetworkMetricsLayer {
    /// Create a new [`NetworkMetricsLayer`] using the global [`Meter`] provider,
    /// with the default name and version.
    pub fn new() -> Self {
        Self::custom(rama_utils::info::NAME, rama_utils::info::VERSION)
    }

    /// Create a new [`NetworkMetricsLayer`] using the global [`Meter`] provider,
    /// with a custom name and version.
    pub fn custom(
        name: impl Into<Cow<'static, str>>,
        version: impl Into<Cow<'static, str>>,
    ) -> Self {
        let meter = get_versioned_meter(name, version);
        let metrics = Metrics::new(meter);
        Self {
            metrics: Arc::new(metrics),
            attributes_factory: (),
        }
    }

    /// Attach an [`AttributesFactory`] to this [`NetworkMetricsLayer`], allowing
    /// you to inject custom attributes.
    pub fn with_attributes<F>(self, attributes: F) -> NetworkMetricsLayer<F> {
        NetworkMetricsLayer {
            metrics: self.metrics,
            attributes_factory: attributes,
        }
    }
}

impl Default for NetworkMetricsLayer {
    fn default() -> Self {
        Self::new()
    }
}

/// construct meters for this crate
fn get_versioned_meter(
    name: impl Into<Cow<'static, str>>,
    version: impl Into<Cow<'static, str>>,
) -> Meter {
    global::meter_with_version(
        name,
        Some(version),
        Some(semantic_conventions::SCHEMA_URL),
        None,
    )
}

impl<S, F: Clone> Layer<S> for NetworkMetricsLayer<F> {
    type Service = NetworkMetricsService<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        NetworkMetricsService {
            inner,
            metrics: self.metrics.clone(),
            attributes_factory: self.attributes_factory.clone(),
        }
    }
}

/// A [`Service`] that records network server metrics using OpenTelemetry.
pub struct NetworkMetricsService<S, F = ()> {
    inner: S,
    metrics: Arc<Metrics>,
    attributes_factory: F,
}

impl<S> NetworkMetricsService<S, ()> {
    /// Create a new [`NetworkMetricsService`].
    pub fn new(inner: S) -> Self {
        NetworkMetricsLayer::new().layer(inner)
    }

    define_inner_service_accessors!();
}

impl<S: fmt::Debug, F: fmt::Debug> fmt::Debug for NetworkMetricsService<S, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkMetricsService")
            .field("inner", &self.inner)
            .field("metrics", &self.metrics)
            .field("attributes_factory", &self.attributes_factory)
            .finish()
    }
}

impl<S, F> NetworkMetricsService<S, F> {
    fn compute_attributes<State>(&self, ctx: &Context<State>) -> Vec<KeyValue>
    where
        F: AttributesFactory<State>,
    {
        let mut attributes = self.attributes_factory.attributes(2, ctx);

        // client info
        if let Some(socket_info) = ctx.get::<SocketInfo>() {
            let peer_addr = socket_info.peer_addr();
            attributes.push(KeyValue::new(
                NETWORK_TYPE,
                match peer_addr.ip() {
                    IpAddr::V4(_) => "ipv4",
                    IpAddr::V6(_) => "ipv6",
                },
            ));
        }

        // connection info
        attributes.push(KeyValue::new(NETWORK_TRANSPORT, "tcp")); // TODO: do not hardcode this once we support UDP

        attributes
    }
}

impl<S, F, State, Stream> Service<State, Stream> for NetworkMetricsService<S, F>
where
    S: Service<State, Stream>,
    F: AttributesFactory<State>,
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
        let attributes: Vec<KeyValue> = self.compute_attributes(&ctx);

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
