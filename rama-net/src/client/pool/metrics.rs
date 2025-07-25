use std::borrow::Cow;

use rama_core::telemetry::opentelemetry::{
    InstrumentationScope, KeyValue, MeterOptions, ServiceInfo, global,
    metrics::{Counter, Histogram, Meter},
    semantic_conventions::{
        self,
        resource::{SERVICE_NAME, SERVICE_VERSION},
    },
};

/// The [`PoolMetrics`] struct contains the shared metrics definitions for a
/// connection pool. Multiple connection pools can share the same `PoolMetrics`
/// instance.
#[derive(Clone, Debug)]
pub struct PoolMetrics {
    base_attributes: Vec<KeyValue>,
    pub(super) total_connections: Counter<u64>,
    pub(super) created_connections: Counter<u64>,
    pub(super) reused_connections: Counter<u64>,
    pub(super) evicted_connections: Counter<u64>,
    pub(super) reused_connection_pos: Histogram<u64>,
    pub(super) active_connection_delay_nanoseconds: Histogram<f64>,
    // _available_active_connections: ObservableGauge<u64>,
    // _available_total_connections: ObservableGauge<u64>,
}

const CONNPOOL_CONNECTIONS: &str = "connpool.connections";
const CONNPOOL_CREATED_CONNECTIONS: &str = "connpool.created_connections";
const CONNPOOL_REUSED_CONNECTIONS: &str = "connpool.reused_connections";
const CONNPOOL_EVICTED_CONNECTIONS: &str = "connpool.evicted_connections";
const CONNPOOL_REUSED_CONNECTION_POS: &str = "connpool.reused_connection_pos";
const CONNPOOL_ACTIVE_CONNECTION_DELAY: &str = "connpool.active_connection_delay";

fn prefix_metric<'a>(prefix: Option<&str>, name: &'a str) -> Cow<'a, str> {
    match prefix {
        Some(prefix) => Cow::Owned(format!("{prefix}.{name}")),
        None => Cow::Borrowed(name),
    }
}

fn get_versioned_meter() -> Meter {
    global::meter_with_scope(
        InstrumentationScope::builder(const_format::formatcp!(
            "{}-connpool",
            rama_utils::info::NAME
        ))
        .with_version(rama_utils::info::VERSION)
        .with_schema_url(semantic_conventions::SCHEMA_URL)
        .build(),
    )
}

impl PoolMetrics {
    pub fn new(opts: MeterOptions) -> Self {
        Self::new_with_meter(get_versioned_meter(), opts)
    }

    pub fn new_with_meter(meter: Meter, opts: MeterOptions) -> Self {
        let service_info = opts.service.unwrap_or_else(|| ServiceInfo {
            name: rama_utils::info::NAME.to_owned(),
            version: rama_utils::info::VERSION.to_owned(),
        });

        let mut attributes = opts.attributes.unwrap_or_else(|| Vec::with_capacity(2));
        attributes.push(KeyValue::new(SERVICE_NAME, service_info.name.clone()));
        attributes.push(KeyValue::new(SERVICE_VERSION, service_info.version.clone()));

        let prefix = opts.metric_prefix.as_deref();

        Self {
            base_attributes: attributes,
            total_connections: meter
                .u64_counter(prefix_metric(prefix, CONNPOOL_CONNECTIONS))
                .with_description("Connection pool total connections")
                .build(),
            created_connections: meter
                .u64_counter(prefix_metric(prefix, CONNPOOL_CREATED_CONNECTIONS))
                .with_description("Connection pool created connections")
                .build(),
            reused_connections: meter
                .u64_counter(prefix_metric(prefix, CONNPOOL_REUSED_CONNECTIONS))
                .with_description("Connection pool reused connections")
                .build(),
            evicted_connections: meter
                .u64_counter(prefix_metric(prefix, CONNPOOL_EVICTED_CONNECTIONS))
                .with_description("Connection pool evicted connections")
                .build(),
            reused_connection_pos: meter
                .u64_histogram(prefix_metric(prefix, CONNPOOL_REUSED_CONNECTION_POS))
                .with_description("Connection pool reused connection position in pool")
                .with_boundaries(vec![0_f64, 1_f64, 2_f64, 3_f64, 4_f64, 5_f64, 6_f64])
                .build(),
            // TODO: migrate to exponentional histogram once fully supported in otel (probably once version 1 is release)
            // https://github.com/open-telemetry/opentelemetry-rust/issues/2111
            active_connection_delay_nanoseconds: meter
                .f64_histogram(prefix_metric(prefix, CONNPOOL_ACTIVE_CONNECTION_DELAY))
                .with_unit("ns")
                .with_boundaries(vec![
                    0_f64,
                    5_f64,
                    200_f64,
                    500_f64,
                    1_000_f64,
                    10_000_f64,
                    20_000_f64,
                    100_000_f64,
                    500_000_f64,
                    2_000_000_f64,
                    5_000_000_f64,
                    10_000_000_f64,
                ])
                .with_description("Time spent waiting for an active connection slot")
                .build(),
        }
    }

    pub(super) fn attributes<ID: super::ConnID>(&self, id: &ID) -> Vec<KeyValue> {
        self.base_attributes
            .iter()
            .cloned()
            .chain(id.attributes())
            .collect()
    }
}
