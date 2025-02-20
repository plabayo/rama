//! Http OpenTelemetry [`Layer`] Support for Rama.
//!
//! [`Layer`]: rama_core::Layer

use crate::stream::SocketInfo;
use rama_core::telemetry::opentelemetry::semantic_conventions::resource::{
    SERVICE_NAME, SERVICE_VERSION,
};
use rama_core::telemetry::opentelemetry::semantic_conventions::trace::{
    NETWORK_TRANSPORT, NETWORK_TYPE,
};
use rama_core::telemetry::opentelemetry::{AttributesFactory, MeterOptions, ServiceInfo};
use rama_core::telemetry::opentelemetry::{
    InstrumentationScope, KeyValue, global,
    metrics::{Counter, Histogram, Meter},
    semantic_conventions,
};
use rama_core::{Context, Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use std::borrow::Cow;
use std::net::IpAddr;
use std::{fmt, sync::Arc, time::SystemTime};

const NETWORK_CONNECTION_DURATION: &str = "network.server.connection_duration";
const NETWORK_SERVER_TOTAL_CONNECTIONS: &str = "network.server.total_connections";

/// Records network server metrics
#[derive(Clone, Debug)]
struct Metrics {
    network_connection_duration: Histogram<f64>,
    network_total_connections: Counter<u64>,
}

impl Metrics {
    /// Create a new [`NetworkMetrics`]
    fn new(meter: Meter, prefix: Option<String>) -> Self {
        let network_connection_duration = meter
            .f64_histogram(match &prefix {
                Some(prefix) => Cow::Owned(format!("{prefix}.{NETWORK_CONNECTION_DURATION}")),
                None => Cow::Borrowed(NETWORK_CONNECTION_DURATION),
            })
            .with_description("Measures the duration of inbound network connections.")
            .with_unit("s")
            .build();

        let network_total_connections = meter
            .u64_counter(match &prefix {
                Some(prefix) => Cow::Owned(format!("{prefix}.{NETWORK_SERVER_TOTAL_CONNECTIONS}")),
                None => Cow::Borrowed(NETWORK_SERVER_TOTAL_CONNECTIONS),
            })
            .with_description(
                "measures the number of total network connections that have been established so far",
            )
            .build();

        Metrics {
            network_connection_duration,
            network_total_connections,
        }
    }
}

/// A layer that records network server metrics using OpenTelemetry.
pub struct NetworkMetricsLayer<F = ()> {
    metrics: Arc<Metrics>,
    base_attributes: Vec<KeyValue>,
    attributes_factory: F,
}

impl<F: fmt::Debug> fmt::Debug for NetworkMetricsLayer<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("NetworkMetricsLayer")
            .field("metrics", &self.metrics)
            .field("base_attributes", &self.base_attributes)
            .field("attributes_factory", &self.attributes_factory)
            .finish()
    }
}

impl<F: Clone> Clone for NetworkMetricsLayer<F> {
    fn clone(&self) -> Self {
        NetworkMetricsLayer {
            metrics: self.metrics.clone(),
            base_attributes: self.base_attributes.clone(),
            attributes_factory: self.attributes_factory.clone(),
        }
    }
}

impl NetworkMetricsLayer {
    /// Create a new [`NetworkMetricsLayer`] using the global [`Meter`] provider,
    /// with the default name and version.
    pub fn new() -> Self {
        Self::custom(MeterOptions::default())
    }

    /// Create a new [`NetworkMetricsLayer`] using the global [`Meter`] provider,
    /// with a custom name and version.
    pub fn custom(opts: MeterOptions) -> Self {
        let service_info = opts.service.unwrap_or_else(|| ServiceInfo {
            name: rama_utils::info::NAME.to_owned(),
            version: rama_utils::info::VERSION.to_owned(),
        });

        let mut attributes = opts.attributes.unwrap_or_else(|| Vec::with_capacity(2));
        attributes.push(KeyValue::new(SERVICE_NAME, service_info.name.clone()));
        attributes.push(KeyValue::new(SERVICE_VERSION, service_info.version.clone()));

        let meter = get_versioned_meter();
        let metrics = Metrics::new(meter, opts.metric_prefix);

        Self {
            metrics: Arc::new(metrics),
            base_attributes: attributes,
            attributes_factory: (),
        }
    }

    /// Attach an [`AttributesFactory`] to this [`NetworkMetricsLayer`], allowing
    /// you to inject custom attributes.
    pub fn with_attributes<F>(self, attributes: F) -> NetworkMetricsLayer<F> {
        NetworkMetricsLayer {
            metrics: self.metrics,
            base_attributes: self.base_attributes,
            attributes_factory: attributes,
        }
    }
}

impl Default for NetworkMetricsLayer {
    fn default() -> Self {
        Self::new()
    }
}

fn get_versioned_meter() -> Meter {
    global::meter_with_scope(
        InstrumentationScope::builder(const_format::formatcp!(
            "{}-network-transport",
            rama_utils::info::NAME
        ))
        .with_version(rama_utils::info::VERSION)
        .with_schema_url(semantic_conventions::SCHEMA_URL)
        .build(),
    )
}

impl<S, F: Clone> Layer<S> for NetworkMetricsLayer<F> {
    type Service = NetworkMetricsService<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        NetworkMetricsService {
            inner,
            metrics: self.metrics.clone(),
            base_attributes: self.base_attributes.clone(),
            attributes_factory: self.attributes_factory.clone(),
        }
    }
}

/// A [`Service`] that records network server metrics using OpenTelemetry.
pub struct NetworkMetricsService<S, F = ()> {
    inner: S,
    metrics: Arc<Metrics>,
    base_attributes: Vec<KeyValue>,
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
            .field("base_attributes", &self.base_attributes)
            .field("attributes_factory", &self.attributes_factory)
            .finish()
    }
}

impl<S: Clone, F: Clone> Clone for NetworkMetricsService<S, F> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            metrics: self.metrics.clone(),
            base_attributes: self.base_attributes.clone(),
            attributes_factory: self.attributes_factory.clone(),
        }
    }
}

impl<S, F> NetworkMetricsService<S, F> {
    fn compute_attributes<State>(&self, ctx: &Context<State>) -> Vec<KeyValue>
    where
        F: AttributesFactory<State>,
    {
        let mut attributes = self
            .attributes_factory
            .attributes(2 + self.base_attributes.len(), ctx);
        attributes.extend(self.base_attributes.iter().cloned());

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
    State: Clone + Send + Sync + 'static,
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

        self.metrics.network_total_connections.add(1, &attributes);

        // used to compute the duration of the connection
        let timer = SystemTime::now();

        let result = self.inner.serve(ctx, stream).await;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_svc_compute_attributes_default() {
        let svc = NetworkMetricsService::new(());
        let attributes = svc.compute_attributes(&Context::default());
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == SERVICE_NAME)
        );
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == SERVICE_VERSION)
        );
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == NETWORK_TRANSPORT)
        );
    }

    #[test]
    fn test_custom_svc_compute_attributes_default() {
        let svc = NetworkMetricsLayer::custom(MeterOptions {
            service: Some(ServiceInfo {
                name: "test".to_owned(),
                version: "42".to_owned(),
            }),
            metric_prefix: Some("foo".to_owned()),
            ..Default::default()
        })
        .layer(());

        let attributes = svc.compute_attributes(&Context::default());
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == SERVICE_NAME && attr.value.as_str() == "test")
        );
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == SERVICE_VERSION && attr.value.as_str() == "42")
        );
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == NETWORK_TRANSPORT)
        );
    }

    #[test]
    fn test_custom_svc_compute_attributes_attributes_vec() {
        let svc = NetworkMetricsLayer::custom(MeterOptions {
            service: Some(ServiceInfo {
                name: "test".to_owned(),
                version: "42".to_owned(),
            }),
            metric_prefix: Some("foo".to_owned()),
            ..Default::default()
        })
        .with_attributes(vec![KeyValue::new("test", "attribute_fn")])
        .layer(());

        let attributes = svc.compute_attributes(&Context::default());
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == SERVICE_NAME && attr.value.as_str() == "test")
        );
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == SERVICE_VERSION && attr.value.as_str() == "42")
        );
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == NETWORK_TRANSPORT)
        );
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == "test" && attr.value.as_str() == "attribute_fn")
        );
    }

    #[test]
    fn test_custom_svc_compute_attributes_attribute_fn() {
        let svc = NetworkMetricsLayer::custom(MeterOptions {
            service: Some(ServiceInfo {
                name: "test".to_owned(),
                version: "42".to_owned(),
            }),
            metric_prefix: Some("foo".to_owned()),
            ..Default::default()
        })
        .with_attributes(|size_hint: usize, _ctx: &Context<()>| {
            let mut attributes = Vec::with_capacity(size_hint + 1);
            attributes.push(KeyValue::new("test", "attribute_fn"));
            attributes
        })
        .layer(());

        let attributes = svc.compute_attributes(&Context::default());
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == SERVICE_NAME && attr.value.as_str() == "test")
        );
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == SERVICE_VERSION && attr.value.as_str() == "42")
        );
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == NETWORK_TRANSPORT)
        );
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == "test" && attr.value.as_str() == "attribute_fn")
        );
    }
}
