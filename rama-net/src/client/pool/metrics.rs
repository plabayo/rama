use std::borrow::Cow;

use rama_core::telemetry::opentelemetry::{
    InstrumentationScope, KeyValue, MeterOptions, global,
    metrics::{Counter, Histogram, Meter},
    semantic_conventions,
};
use rama_utils::macros::generate_set_and_with;

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
    pub(super) active_connection_delay_nanoseconds: Histogram<f64>,
    // _available_active_connections: ObservableGauge<u64>,
    // _available_total_connections: ObservableGauge<u64>,
}

#[derive(Debug)]
pub struct PoolMetricsOpts {
    active_connection_delay_nanoseconds_bounds: Vec<f64>,
}

const CONNPOOL_CONNECTIONS: &str = "connpool.connections";
const CONNPOOL_CREATED_CONNECTIONS: &str = "connpool.created_connections";
const CONNPOOL_REUSED_CONNECTIONS: &str = "connpool.reused_connections";
const CONNPOOL_EVICTED_CONNECTIONS: &str = "connpool.evicted_connections";
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
    #[must_use]
    pub fn new(meter_opts: MeterOptions, metric_opts: PoolMetricsOpts) -> Self {
        Self::new_with_meter(&get_versioned_meter(), meter_opts, metric_opts)
    }

    #[must_use]
    pub fn new_with_meter(
        meter: &Meter,
        meter_opts: MeterOptions,
        metric_opts: PoolMetricsOpts,
    ) -> Self {
        let attributes = meter_opts.attributes.unwrap_or_default();
        let prefix = meter_opts.metric_prefix.as_deref();

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
            // TODO: migrate to exponentional histogram once fully supported in otel (probably once version 1 is release)
            // https://github.com/open-telemetry/opentelemetry-rust/issues/2111
            active_connection_delay_nanoseconds: meter
                .f64_histogram(prefix_metric(prefix, CONNPOOL_ACTIVE_CONNECTION_DELAY))
                .with_unit("ns")
                .with_boundaries(metric_opts.active_connection_delay_nanoseconds_bounds)
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

impl Default for PoolMetricsOpts {
    fn default() -> Self {
        Self {
            active_connection_delay_nanoseconds_bounds: vec![
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
            ],
        }
    }
}

impl PoolMetricsOpts {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    generate_set_and_with! {
        /// Manually specify bounds for the `active_connection_delay_nanoseconds` metric.
        pub fn active_connection_delay_nanoseconds_bounds(mut self, bounds: Vec<f64>) -> Self {
            self.active_connection_delay_nanoseconds_bounds = bounds;
            self
        }
    }

    generate_set_and_with! {
        /// Calculate exponentially-spaced bounds for the `active_connection_delay_nanoseconds` metric.
        pub fn active_connection_delay_nanoseconds_parametrized_bounds(mut self, max: f64, nbounds: usize) -> Self {
            self.active_connection_delay_nanoseconds_bounds = (0..nbounds)
                .map(|i| max.powf(i as f64 / (nbounds - 1) as f64).round())
                .collect();
            self
        }
    }
}
