//! Conversions from OpenTelemetry SDK types to OTLP protobuf types.
//!
//! This module replaces the `opentelemetry-proto` crate's transform layer,
//! converting directly from `opentelemetry_sdk` data types to our vendored
//! proto types.

use super::proto::{
    self, AnyValue, ArrayValue, ExponentialHistogramDataPoint, ExportMetricsServiceRequest,
    HistogramDataPoint, InstrumentationScope as ProtoInstrumentationScope, KeyValue,
    NumberDataPoint, ProtoExemplar, ProtoExponentialHistogram, ProtoGauge, ProtoHistogram,
    ProtoMetric, ProtoResource, ProtoResourceMetrics, ProtoScopeMetrics, ProtoSum, ResourceSpans,
    ScopeSpans, Span, Status,
};
use opentelemetry::{Array, Value, trace as otrace};
use opentelemetry_sdk::{
    Resource,
    metrics::{
        Temporality,
        data::{
            AggregatedMetrics, Exemplar as SdkExemplar,
            ExponentialHistogram as SdkExponentialHistogram, Gauge as SdkGauge,
            Histogram as SdkHistogram, Metric as SdkMetric, MetricData as SdkMetricData,
            ResourceMetrics as SdkResourceMetrics, ScopeMetrics as SdkScopeMetrics, Sum as SdkSum,
        },
    },
    trace::SpanData,
};
use std::{
    collections::HashMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// ──────────────────────────────────────────────
// Time utilities
// ──────────────────────────────────────────────

fn to_nanos(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos() as u64
}

// ──────────────────────────────────────────────
// Common: attributes + values
// ──────────────────────────────────────────────

fn key_value_from(kv: ::opentelemetry::KeyValue) -> KeyValue {
    KeyValue {
        key: kv.key.as_str().to_owned(),
        value: Some(value_into_any(kv.value)),
    }
}

fn key_value_from_ref(key: &::opentelemetry::Key, value: &Value) -> KeyValue {
    KeyValue {
        key: key.as_str().to_owned(),
        value: Some(value_into_any(value.clone())),
    }
}

fn key_value_from_kv_ref(kv: &::opentelemetry::KeyValue) -> KeyValue {
    KeyValue {
        key: kv.key.as_str().to_owned(),
        value: Some(value_into_any(kv.value.clone())),
    }
}

fn value_into_any(value: Value) -> AnyValue {
    AnyValue {
        value: match value {
            Value::Bool(val) => Some(proto::any_value::Value::BoolValue(val)),
            Value::I64(val) => Some(proto::any_value::Value::IntValue(val)),
            Value::F64(val) => Some(proto::any_value::Value::DoubleValue(val)),
            Value::String(val) => Some(proto::any_value::Value::StringValue(val.to_string())),
            Value::Array(array) => Some(proto::any_value::Value::ArrayValue(match array {
                Array::Bool(vals) => array_into_proto(vals),
                Array::I64(vals) => array_into_proto(vals),
                Array::F64(vals) => array_into_proto(vals),
                Array::String(vals) => array_into_proto(vals),
                _ => unreachable!("nonexistent array type"),
            })),
            _ => unreachable!("nonexistent value type"),
        },
    }
}

fn array_into_proto<T>(vals: Vec<T>) -> ArrayValue
where
    Value: From<T>,
{
    let values = vals
        .into_iter()
        .map(|val| value_into_any(Value::from(val)))
        .collect();
    ArrayValue { values }
}

fn attributes_from_iter<I: IntoIterator<Item = ::opentelemetry::KeyValue>>(
    kvs: I,
) -> Vec<KeyValue> {
    kvs.into_iter().map(key_value_from).collect()
}

fn resource_attributes(resource: &Resource) -> Vec<KeyValue> {
    resource
        .iter()
        .map(|(k, v)| key_value_from(::opentelemetry::KeyValue::new(k.clone(), v.clone())))
        .collect()
}

fn instrumentation_scope_into(
    scope: &::opentelemetry::InstrumentationScope,
) -> ProtoInstrumentationScope {
    ProtoInstrumentationScope {
        name: scope.name().to_owned(),
        version: scope.version().map(ToOwned::to_owned).unwrap_or_default(),
        attributes: attributes_from_iter(scope.attributes().cloned()),
        ..Default::default()
    }
}

// ──────────────────────────────────────────────
// Resource wrapper (shared between traces & logs)
// ──────────────────────────────────────────────

/// Holds the proto-converted resource attributes and schema URL.
#[derive(Debug, Default)]
pub(crate) struct ResourceAttributesWithSchema {
    pub attributes: Vec<KeyValue>,
    pub schema_url: Option<String>,
}

impl From<&Resource> for ResourceAttributesWithSchema {
    fn from(resource: &Resource) -> Self {
        Self {
            attributes: resource_attributes(resource),
            schema_url: resource.schema_url().map(ToString::to_string),
        }
    }
}

// ──────────────────────────────────────────────
// Trace: SpanData → proto Span
// ──────────────────────────────────────────────

fn build_span_flags(parent_span_is_remote: bool, base_flags: u32) -> u32 {
    use proto::trace_proto::SpanFlags;
    let mut flags = base_flags;
    flags |= SpanFlags::ContextHasIsRemoteMask as u32;
    if parent_span_is_remote {
        flags |= SpanFlags::ContextIsRemoteMask as u32;
    }
    flags
}

fn span_kind_into(kind: &otrace::SpanKind) -> i32 {
    use proto::trace_proto::span::SpanKind;
    match kind {
        otrace::SpanKind::Client => SpanKind::Client as i32,
        otrace::SpanKind::Consumer => SpanKind::Consumer as i32,
        otrace::SpanKind::Internal => SpanKind::Internal as i32,
        otrace::SpanKind::Producer => SpanKind::Producer as i32,
        otrace::SpanKind::Server => SpanKind::Server as i32,
    }
}

fn status_code_from(status: &otrace::Status) -> i32 {
    use proto::trace_proto::status::StatusCode;
    match status {
        otrace::Status::Ok => StatusCode::Ok as i32,
        otrace::Status::Unset => StatusCode::Unset as i32,
        otrace::Status::Error { .. } => StatusCode::Error as i32,
    }
}

fn span_data_into(source: SpanData) -> Span {
    use otrace::SpanId;

    Span {
        trace_id: source.span_context.trace_id().to_bytes().to_vec(),
        span_id: source.span_context.span_id().to_bytes().to_vec(),
        trace_state: source.span_context.trace_state().header(),
        parent_span_id: if source.parent_span_id != SpanId::INVALID {
            source.parent_span_id.to_bytes().to_vec()
        } else {
            vec![]
        },
        flags: build_span_flags(
            source.parent_span_is_remote,
            source.span_context.trace_flags().to_u8() as u32,
        ),
        name: source.name.into_owned(),
        kind: span_kind_into(&source.span_kind),
        start_time_unix_nano: to_nanos(source.start_time),
        end_time_unix_nano: to_nanos(source.end_time),
        dropped_attributes_count: source.dropped_attributes_count,
        attributes: attributes_from_iter(source.attributes),
        dropped_events_count: source.events.dropped_count,
        events: source
            .events
            .into_iter()
            .map(|event| proto::trace_proto::span::Event {
                time_unix_nano: to_nanos(event.timestamp),
                name: event.name.into(),
                attributes: attributes_from_iter(event.attributes),
                dropped_attributes_count: event.dropped_attributes_count,
            })
            .collect(),
        dropped_links_count: source.links.dropped_count,
        links: source
            .links
            .into_iter()
            .map(|link| proto::trace_proto::span::Link {
                trace_id: link.span_context.trace_id().to_bytes().to_vec(),
                span_id: link.span_context.span_id().to_bytes().to_vec(),
                trace_state: link.span_context.trace_state().header(),
                attributes: attributes_from_iter(link.attributes),
                dropped_attributes_count: link.dropped_attributes_count,
                flags: build_span_flags(
                    link.span_context.is_remote(),
                    link.span_context.trace_flags().to_u8() as u32,
                ),
            })
            .collect(),
        status: Some(Status {
            code: status_code_from(&source.status),
            message: match source.status {
                otrace::Status::Error { description } => description.to_string(),
                _ => Default::default(),
            },
        }),
    }
}

/// Group a batch of `SpanData` into `ResourceSpans` by instrumentation scope.
pub(crate) fn group_spans_by_resource_and_scope(
    spans: &[SpanData],
    resource: &ResourceAttributesWithSchema,
) -> Vec<ResourceSpans> {
    // Group spans by their instrumentation scope.
    let scope_map = spans.iter().fold(
        HashMap::<&::opentelemetry::InstrumentationScope, Vec<&SpanData>>::new(),
        |mut scope_map, span| {
            scope_map
                .entry(&span.instrumentation_scope)
                .or_default()
                .push(span);
            scope_map
        },
    );

    let scope_spans: Vec<ScopeSpans> = scope_map
        .into_iter()
        .map(
            |(scope, span_records): (&::opentelemetry::InstrumentationScope, Vec<&SpanData>)| {
                ScopeSpans {
                    scope: Some(instrumentation_scope_into(scope)),
                    schema_url: scope
                        .schema_url()
                        .map(ToOwned::to_owned)
                        .unwrap_or_default(),
                    spans: span_records
                        .into_iter()
                        .map(|sd: &SpanData| span_data_into(sd.clone()))
                        .collect(),
                }
            },
        )
        .collect();

    vec![ResourceSpans {
        resource: Some(ProtoResource {
            attributes: resource.attributes.clone(),
            dropped_attributes_count: 0,
        }),
        scope_spans,
        schema_url: resource.schema_url.clone().unwrap_or_default(),
    }]
}

// ──────────────────────────────────────────────
// Metrics: SDK ResourceMetrics → proto
// ──────────────────────────────────────────────

pub(crate) fn resource_metrics_to_request(rm: &SdkResourceMetrics) -> ExportMetricsServiceRequest {
    ExportMetricsServiceRequest {
        resource_metrics: vec![ProtoResourceMetrics {
            resource: Some(sdk_resource_into(rm.resource())),
            scope_metrics: rm.scope_metrics().map(scope_metrics_into).collect(),
            schema_url: rm
                .resource()
                .schema_url()
                .map(Into::into)
                .unwrap_or_default(),
        }],
    }
}

fn sdk_resource_into(resource: &Resource) -> ProtoResource {
    ProtoResource {
        attributes: resource
            .iter()
            .map(|(k, v)| key_value_from_ref(k, v))
            .collect(),
        dropped_attributes_count: 0,
    }
}

fn scope_metrics_into(sm: &SdkScopeMetrics) -> ProtoScopeMetrics {
    ProtoScopeMetrics {
        scope: Some(instrumentation_scope_into(sm.scope())),
        metrics: sm.metrics().map(metric_into).collect(),
        schema_url: sm
            .scope()
            .schema_url()
            .map(ToOwned::to_owned)
            .unwrap_or_default(),
    }
}

fn metric_into(metric: &SdkMetric) -> ProtoMetric {
    ProtoMetric {
        name: metric.name().to_owned(),
        description: metric.description().to_owned(),
        unit: metric.unit().to_owned(),
        metadata: vec![],
        data: Some(match metric.data() {
            AggregatedMetrics::F64(data) => metric_data_into(data),
            AggregatedMetrics::U64(data) => metric_data_into(data),
            AggregatedMetrics::I64(data) => metric_data_into(data),
        }),
    }
}

trait Numeric: Copy {
    fn into_f64(self) -> f64;
    fn into_exemplar_value(self) -> proto::exemplar::Value;
    fn into_data_point_value(self) -> proto::number_data_point::Value;
}

impl Numeric for u64 {
    fn into_f64(self) -> f64 {
        self as f64
    }
    fn into_exemplar_value(self) -> proto::exemplar::Value {
        proto::exemplar::Value::AsInt(i64::try_from(self).unwrap_or_default())
    }
    fn into_data_point_value(self) -> proto::number_data_point::Value {
        proto::number_data_point::Value::AsInt(i64::try_from(self).unwrap_or_default())
    }
}

impl Numeric for i64 {
    fn into_f64(self) -> f64 {
        self as f64
    }
    fn into_exemplar_value(self) -> proto::exemplar::Value {
        proto::exemplar::Value::AsInt(self)
    }
    fn into_data_point_value(self) -> proto::number_data_point::Value {
        proto::number_data_point::Value::AsInt(self)
    }
}

impl Numeric for f64 {
    fn into_f64(self) -> f64 {
        self
    }
    fn into_exemplar_value(self) -> proto::exemplar::Value {
        proto::exemplar::Value::AsDouble(self)
    }
    fn into_data_point_value(self) -> proto::number_data_point::Value {
        proto::number_data_point::Value::AsDouble(self)
    }
}

fn metric_data_into<T: Numeric + std::fmt::Debug>(data: &SdkMetricData<T>) -> proto::MetricData {
    match data {
        SdkMetricData::Gauge(gauge) => proto::MetricData::Gauge(gauge_into(gauge)),
        SdkMetricData::Sum(sum) => proto::MetricData::Sum(sum_into(sum)),
        SdkMetricData::Histogram(hist) => proto::MetricData::Histogram(histogram_into(hist)),
        SdkMetricData::ExponentialHistogram(hist) => {
            proto::MetricData::ExponentialHistogram(exp_histogram_into(hist))
        }
    }
}

fn temporality_into(t: Temporality) -> i32 {
    use proto::AggregationTemporality;
    match t {
        Temporality::Delta => AggregationTemporality::Delta as i32,
        _ => AggregationTemporality::Cumulative as i32,
    }
}

fn gauge_into<T: Numeric>(gauge: &SdkGauge<T>) -> ProtoGauge {
    ProtoGauge {
        data_points: gauge
            .data_points()
            .map(|dp| NumberDataPoint {
                attributes: dp.attributes().map(key_value_from_kv_ref).collect(),
                start_time_unix_nano: gauge.start_time().map(to_nanos).unwrap_or_default(),
                time_unix_nano: to_nanos(gauge.time()),
                exemplars: dp.exemplars().map(exemplar_into).collect(),
                flags: proto::DataPointFlags::default() as u32,
                value: Some(dp.value().into_data_point_value()),
            })
            .collect(),
    }
}

fn sum_into<T: Numeric>(sum: &SdkSum<T>) -> ProtoSum {
    ProtoSum {
        data_points: sum
            .data_points()
            .map(|dp| NumberDataPoint {
                attributes: dp.attributes().map(key_value_from_kv_ref).collect(),
                start_time_unix_nano: to_nanos(sum.start_time()),
                time_unix_nano: to_nanos(sum.time()),
                exemplars: dp.exemplars().map(exemplar_into).collect(),
                flags: proto::DataPointFlags::default() as u32,
                value: Some(dp.value().into_data_point_value()),
            })
            .collect(),
        aggregation_temporality: temporality_into(sum.temporality()),
        is_monotonic: sum.is_monotonic(),
    }
}

fn histogram_into<T: Numeric>(hist: &SdkHistogram<T>) -> ProtoHistogram {
    ProtoHistogram {
        data_points: hist
            .data_points()
            .map(|dp| HistogramDataPoint {
                attributes: dp.attributes().map(key_value_from_kv_ref).collect(),
                start_time_unix_nano: to_nanos(hist.start_time()),
                time_unix_nano: to_nanos(hist.time()),
                count: dp.count(),
                sum: Some(dp.sum().into_f64()),
                bucket_counts: dp.bucket_counts().collect(),
                explicit_bounds: dp.bounds().collect(),
                exemplars: dp.exemplars().map(exemplar_into).collect(),
                flags: proto::DataPointFlags::default() as u32,
                min: dp.min().map(Numeric::into_f64),
                max: dp.max().map(Numeric::into_f64),
            })
            .collect(),
        aggregation_temporality: temporality_into(hist.temporality()),
    }
}

fn exp_histogram_into<T: Numeric>(hist: &SdkExponentialHistogram<T>) -> ProtoExponentialHistogram {
    ProtoExponentialHistogram {
        data_points: hist
            .data_points()
            .map(|dp| ExponentialHistogramDataPoint {
                attributes: dp.attributes().map(key_value_from_kv_ref).collect(),
                start_time_unix_nano: to_nanos(hist.start_time()),
                time_unix_nano: to_nanos(hist.time()),
                count: dp.count() as u64,
                sum: Some(dp.sum().into_f64()),
                scale: dp.scale().into(),
                zero_count: dp.zero_count(),
                positive: Some(proto::exponential_histogram_data_point::Buckets {
                    offset: dp.positive_bucket().offset(),
                    bucket_counts: dp.positive_bucket().counts().collect(),
                }),
                negative: Some(proto::exponential_histogram_data_point::Buckets {
                    offset: dp.negative_bucket().offset(),
                    bucket_counts: dp.negative_bucket().counts().collect(),
                }),
                flags: proto::DataPointFlags::default() as u32,
                exemplars: dp.exemplars().map(exemplar_into).collect(),
                min: dp.min().map(Numeric::into_f64),
                max: dp.max().map(Numeric::into_f64),
                zero_threshold: dp.zero_threshold(),
            })
            .collect(),
        aggregation_temporality: temporality_into(hist.temporality()),
    }
}

fn exemplar_into<T: Numeric>(ex: &SdkExemplar<T>) -> ProtoExemplar {
    ProtoExemplar {
        filtered_attributes: ex
            .filtered_attributes()
            .map(|kv| key_value_from_ref(&kv.key, &kv.value))
            .collect(),
        time_unix_nano: to_nanos(ex.time()),
        span_id: ex.span_id().into(),
        trace_id: ex.trace_id().into(),
        value: Some(ex.value.into_exemplar_value()),
    }
}
