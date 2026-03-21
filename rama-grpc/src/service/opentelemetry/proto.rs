//! Generated protobuf types for OTLP gRPC services.
//!
//! These types are compiled from the vendored OpenTelemetry proto files
//! in `rama-grpc/proto/opentelemetry/proto/`.

#[doc(hidden)]
#[allow(
    dead_code,
    unreachable_pub,
    missing_docs,
    clippy::default_trait_access,
    clippy::derive_partial_eq_without_eq,
    clippy::enum_variant_names,
    clippy::trivially_copy_pass_by_ref
)]
pub mod opentelemetry {
    pub mod proto {
        pub mod common {
            pub mod v1 {
                include!(concat!(
                    env!("OUT_DIR"),
                    "/opentelemetry.proto.common.v1.rs"
                ));
            }
        }

        pub mod resource {
            pub mod v1 {
                include!(concat!(
                    env!("OUT_DIR"),
                    "/opentelemetry.proto.resource.v1.rs"
                ));
            }
        }

        pub mod trace {
            pub mod v1 {
                include!(concat!(env!("OUT_DIR"), "/opentelemetry.proto.trace.v1.rs"));
            }
        }

        pub mod metrics {
            pub mod v1 {
                include!(concat!(
                    env!("OUT_DIR"),
                    "/opentelemetry.proto.metrics.v1.rs"
                ));
            }
        }

        pub mod collector {
            pub mod trace {
                pub mod v1 {
                    include!(concat!(
                        env!("OUT_DIR"),
                        "/opentelemetry.proto.collector.trace.v1.rs"
                    ));
                }
            }

            pub mod metrics {
                pub mod v1 {
                    include!(concat!(
                        env!("OUT_DIR"),
                        "/opentelemetry.proto.collector.metrics.v1.rs"
                    ));
                }
            }
        }
    }
}

// Re-export commonly used types at the module level for convenience.
pub(crate) use opentelemetry::proto::{
    collector::{
        metrics::v1::{ExportMetricsServiceRequest, ExportMetricsServiceResponse},
        trace::v1::{ExportTraceServiceRequest, ExportTraceServiceResponse},
    },
    common::v1::{AnyValue, ArrayValue, InstrumentationScope, KeyValue, any_value},
    metrics::v1::{
        AggregationTemporality, DataPointFlags, Exemplar as ProtoExemplar,
        ExponentialHistogram as ProtoExponentialHistogram, ExponentialHistogramDataPoint,
        Gauge as ProtoGauge, Histogram as ProtoHistogram, HistogramDataPoint,
        Metric as ProtoMetric, NumberDataPoint, ResourceMetrics as ProtoResourceMetrics,
        ScopeMetrics as ProtoScopeMetrics, Sum as ProtoSum, exemplar,
        exponential_histogram_data_point, metric::Data as MetricData, number_data_point,
    },
    resource::v1::Resource as ProtoResource,
    trace::v1::{self as trace_proto, ResourceSpans, ScopeSpans, Span, Status},
};
