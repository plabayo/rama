use crate::{
    Request,
    client::{Grpc, GrpcService},
    codec::CompressionEncoding,
    metadata::MetadataMap,
    protobuf::ProstCodec,
};
use parking_lot::RwLock;
use rama_core::error::BoxError;
use rama_core::telemetry::opentelemetry::{
    otel_debug, otel_warn,
    sdk::{
        self,
        error::{OTelSdkError, OTelSdkResult},
        metrics::exporter::PushMetricExporter,
        metrics::{Temporality, data::ResourceMetrics},
        trace::{SpanData, SpanExporter},
    },
};
use rama_http::{
    Body, StreamingBody,
    uri::{PathAndQuery, Uri},
};
use rama_net::uri::util::percent_encoding::percent_decode;
use rama_utils::macros::generate_set_and_with;
use std::{
    fmt,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

pub(crate) mod proto;
mod transform;

use proto::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse, ExportTraceServiceRequest,
    ExportTraceServiceResponse,
};
use transform::{ResourceAttributesWithSchema, group_spans_by_resource_and_scope};

const DEFAULT_OTLP_GRPC_ENDPOINT: &str = "http://localhost:4317";

const OTEL_EXPORTER_OTLP_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
const OTEL_EXPORTER_OTLP_TIMEOUT: &str = "OTEL_EXPORTER_OTLP_TIMEOUT";
const OTEL_EXPORTER_OTLP_HEADERS: &str = "OTEL_EXPORTER_OTLP_HEADERS";
const OTEL_EXPORTER_OTLP_COMPRESSION: &str = "OTEL_EXPORTER_OTLP_COMPRESSION";

const OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT";
const OTEL_EXPORTER_OTLP_TRACES_TIMEOUT: &str = "OTEL_EXPORTER_OTLP_TRACES_TIMEOUT";
const OTEL_EXPORTER_OTLP_TRACES_HEADERS: &str = "OTEL_EXPORTER_OTLP_TRACES_HEADERS";
const OTEL_EXPORTER_OTLP_TRACES_COMPRESSION: &str = "OTEL_EXPORTER_OTLP_TRACES_COMPRESSION";

const OTEL_EXPORTER_OTLP_METRICS_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT";
const OTEL_EXPORTER_OTLP_METRICS_TIMEOUT: &str = "OTEL_EXPORTER_OTLP_METRICS_TIMEOUT";
const OTEL_EXPORTER_OTLP_METRICS_HEADERS: &str = "OTEL_EXPORTER_OTLP_METRICS_HEADERS";
const OTEL_EXPORTER_OTLP_METRICS_COMPRESSION: &str = "OTEL_EXPORTER_OTLP_METRICS_COMPRESSION";

const TRACE_EXPORT_PATH: &str = "/opentelemetry.proto.collector.trace.v1.TraceService/Export";
const METRICS_EXPORT_PATH: &str = "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export";

/// Wrapper type which allows you to use a rama gRPC [`GrpcService`]
/// as a gRPC OTLP exporter for your OpenTelemetry setup.
///
/// [`GrpcService`]: crate::client::GrpcService
#[must_use]
#[derive(Debug, Clone)]
pub struct OtelExporter<S = ()> {
    service: S,
    handle: tokio::runtime::Handle,
    endpoint: Option<Uri>,
    timeout: Option<Duration>,
    compression: Option<CompressionEncoding>,
    metadata: MetadataMap,
    traces: SignalSettings,
    metrics: SignalSettings,
    env: EnvSettings,
    temporality: Temporality,
    resource: Arc<RwLock<ResourceAttributesWithSchema>>,
    shutdown: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
struct SignalSettings {
    endpoint: Option<Uri>,
    timeout: Option<Duration>,
    compression: Option<CompressionEncoding>,
    metadata: MetadataMap,
}

impl Default for SignalSettings {
    fn default() -> Self {
        Self {
            endpoint: None,
            timeout: None,
            compression: None,
            metadata: MetadataMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct EnvSettings {
    base: SignalSettings,
    traces: SignalSettings,
    metrics: SignalSettings,
}

#[derive(Debug)]
pub struct OtelExporterConfigError {
    message: String,
}

impl OtelExporterConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for OtelExporterConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for OtelExporterConfigError {}

impl<S> OtelExporter<S> {
    /// Create a new [`OtelExporter`] with default OTLP gRPC settings.
    ///
    /// Defaults to `http://localhost:4317` and no extra metadata or compression.
    pub fn new(service: S) -> Self {
        Self {
            service,
            handle: tokio::runtime::Handle::current(),
            endpoint: None,
            timeout: None,
            compression: None,
            metadata: MetadataMap::new(),
            traces: SignalSettings::default(),
            metrics: SignalSettings::default(),
            env: EnvSettings::default(),
            temporality: Temporality::Cumulative,
            resource: Arc::new(RwLock::new(ResourceAttributesWithSchema::default())),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Configure this exporter using the OTLP environment variables.
    pub fn from_env(service: S) -> Result<Self, OtelExporterConfigError> {
        let mut exporter = Self::new(service);
        exporter.apply_env()?;
        Ok(exporter)
    }

    generate_set_and_with!(
        /// Override the base OTLP endpoint.
        pub fn endpoint(mut self, endpoint: Uri) -> Self {
            self.endpoint = Some(endpoint);
            self
        }
    );

    generate_set_and_with!(
        /// Override the base OTLP timeout.
        pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
            self.timeout = timeout;
            self
        }
    );

    generate_set_and_with!(
        /// Override the base OTLP compression.
        pub fn compression(mut self, compression: Option<CompressionEncoding>) -> Self {
            self.compression = compression;
            self
        }
    );

    generate_set_and_with!(
        /// Override the base OTLP metadata.
        pub fn metadata(mut self, metadata: MetadataMap) -> Self {
            self.metadata = metadata;
            self
        }
    );

    generate_set_and_with!(
        /// Override the trace-specific endpoint.
        pub fn traces_endpoint(mut self, endpoint: Option<Uri>) -> Self {
            self.traces.endpoint = endpoint;
            self
        }
    );

    generate_set_and_with!(
        /// Override the trace-specific timeout.
        pub fn traces_timeout(mut self, timeout: Option<Duration>) -> Self {
            self.traces.timeout = timeout;
            self
        }
    );

    generate_set_and_with!(
        /// Override the trace-specific compression.
        pub fn traces_compression(mut self, compression: Option<CompressionEncoding>) -> Self {
            self.traces.compression = compression;
            self
        }
    );

    generate_set_and_with!(
        /// Override the trace-specific metadata.
        pub fn traces_metadata(mut self, metadata: MetadataMap) -> Self {
            self.traces.metadata = metadata;
            self
        }
    );

    generate_set_and_with!(
        /// Override the metrics-specific endpoint.
        pub fn metrics_endpoint(mut self, endpoint: Option<Uri>) -> Self {
            self.metrics.endpoint = endpoint;
            self
        }
    );

    generate_set_and_with!(
        /// Override the metrics-specific timeout.
        pub fn metrics_timeout(mut self, timeout: Option<Duration>) -> Self {
            self.metrics.timeout = timeout;
            self
        }
    );

    generate_set_and_with!(
        /// Override the metrics-specific compression.
        pub fn metrics_compression(mut self, compression: Option<CompressionEncoding>) -> Self {
            self.metrics.compression = compression;
            self
        }
    );

    generate_set_and_with!(
        /// Override the metrics-specific metadata.
        pub fn metrics_metadata(mut self, metadata: MetadataMap) -> Self {
            self.metrics.metadata = metadata;
            self
        }
    );

    generate_set_and_with!(
        /// Configure the metric temporality used by this exporter.
        pub fn temporality(mut self, temporality: Temporality) -> Self {
            self.temporality = temporality;
            self
        }
    );

    fn apply_env(&mut self) -> Result<(), OtelExporterConfigError> {
        if let Some(endpoint) = env_endpoint(OTEL_EXPORTER_OTLP_ENDPOINT)? {
            self.env.base.endpoint = Some(endpoint);
        }
        if let Some(timeout) = env_timeout(OTEL_EXPORTER_OTLP_TIMEOUT)? {
            self.env.base.timeout = Some(timeout);
        }
        if let Some(metadata) = env_headers(OTEL_EXPORTER_OTLP_HEADERS)? {
            self.env.base.metadata = metadata;
        }
        match env_compression(OTEL_EXPORTER_OTLP_COMPRESSION)? {
            EnvCompressionSetting::Unset => {}
            EnvCompressionSetting::Value(compression) => {
                self.env.base.compression = compression;
            }
        }

        if let Some(endpoint) = env_endpoint(OTEL_EXPORTER_OTLP_TRACES_ENDPOINT)? {
            self.env.traces.endpoint = Some(endpoint);
        }
        if let Some(timeout) = env_timeout(OTEL_EXPORTER_OTLP_TRACES_TIMEOUT)? {
            self.env.traces.timeout = Some(timeout);
        }
        if let Some(metadata) = env_headers(OTEL_EXPORTER_OTLP_TRACES_HEADERS)? {
            self.env.traces.metadata = metadata;
        }
        match env_compression(OTEL_EXPORTER_OTLP_TRACES_COMPRESSION)? {
            EnvCompressionSetting::Unset => {}
            EnvCompressionSetting::Value(compression) => {
                self.env.traces.compression = compression;
            }
        }

        if let Some(endpoint) = env_endpoint(OTEL_EXPORTER_OTLP_METRICS_ENDPOINT)? {
            self.env.metrics.endpoint = Some(endpoint);
        }
        if let Some(timeout) = env_timeout(OTEL_EXPORTER_OTLP_METRICS_TIMEOUT)? {
            self.env.metrics.timeout = Some(timeout);
        }
        if let Some(metadata) = env_headers(OTEL_EXPORTER_OTLP_METRICS_HEADERS)? {
            self.env.metrics.metadata = metadata;
        }
        match env_compression(OTEL_EXPORTER_OTLP_METRICS_COMPRESSION)? {
            EnvCompressionSetting::Unset => {}
            EnvCompressionSetting::Value(compression) => {
                self.env.metrics.compression = compression;
            }
        }

        Ok(())
    }

    fn trace_config(&self) -> ResolvedConfig {
        ResolvedConfig::new(self, SignalKind::Traces)
    }

    fn metrics_config(&self) -> ResolvedConfig {
        ResolvedConfig::new(self, SignalKind::Metrics)
    }
}

#[derive(Debug, Clone, Copy)]
enum SignalKind {
    Traces,
    Metrics,
}

struct ResolvedConfig {
    endpoint: Uri,
    timeout: Option<Duration>,
    compression: Option<CompressionEncoding>,
    metadata: MetadataMap,
}

impl ResolvedConfig {
    fn new<S>(exporter: &OtelExporter<S>, signal_kind: SignalKind) -> Self {
        let (signal, env_signal) = match signal_kind {
            SignalKind::Traces => (&exporter.traces, &exporter.env.traces),
            SignalKind::Metrics => (&exporter.metrics, &exporter.env.metrics),
        };

        let endpoint = signal
            .endpoint
            .clone()
            .or_else(|| exporter.endpoint.clone())
            .or_else(|| env_signal.endpoint.clone())
            .or_else(|| exporter.env.base.endpoint.clone())
            .unwrap_or_else(|| Uri::from_static(DEFAULT_OTLP_GRPC_ENDPOINT));
        let timeout = signal
            .timeout
            .or(exporter.timeout)
            .or(env_signal.timeout)
            .or(exporter.env.base.timeout);
        let compression = signal
            .compression
            .or(exporter.compression)
            .or(env_signal.compression)
            .or(exporter.env.base.compression);

        let mut metadata = exporter.env.base.metadata.clone();
        metadata.merge(env_signal.metadata.clone());
        metadata.merge(exporter.metadata.clone());
        metadata.merge(signal.metadata.clone());

        Self {
            endpoint,
            timeout,
            compression,
            metadata,
        }
    }
}

impl<S> SpanExporter for OtelExporter<S>
where
    S: fmt::Debug + Clone + GrpcService<Body>,
    S::ResponseBody: StreamingBody<Error: Into<BoxError>> + Send + Sync + 'static,
{
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(OTelSdkError::AlreadyShutdown);
        }

        let service = self.service.clone();
        let handle = self.handle.clone();
        let config = self.trace_config();
        let resource = self.resource.clone();
        let shutdown = self.shutdown.clone();

        // gRPC client futures are !Send, so run them on the runtime via a blocking task.
        let runtime = handle.clone();
        let join = handle.spawn_blocking(move || {
            runtime.block_on(async move {
                if shutdown.load(Ordering::SeqCst) {
                    return Err(OTelSdkError::AlreadyShutdown);
                }

                let mut grpc = Grpc::new(service, config.endpoint);
                if let Some(compression) = config.compression {
                    grpc = grpc
                        .with_send_compressed(compression)
                        .with_accept_compressed(compression);
                }

                let resource_spans = {
                    let guard = resource.read();
                    group_spans_by_resource_and_scope(&batch, &guard)
                };

                let mut request = Request::new(ExportTraceServiceRequest { resource_spans });
                *request.metadata_mut() = config.metadata;
                if let Some(timeout) = config.timeout {
                    request
                        .try_set_timeout(timeout)
                        .map_err(|err| OTelSdkError::InternalFailure(err.to_string()))?;
                }

                let rpc = grpc.unary(
                    request,
                    PathAndQuery::from_static(TRACE_EXPORT_PATH),
                    ProstCodec::<ExportTraceServiceRequest, ExportTraceServiceResponse>::new(),
                );

                let response = match config.timeout {
                    Some(timeout) => match tokio::time::timeout(timeout, rpc).await {
                        Ok(result) => result,
                        Err(_) => return Err(OTelSdkError::Timeout(timeout)),
                    },
                    None => rpc.await,
                }
                .map_err(|status| {
                    OTelSdkError::InternalFailure(format!("export error: {status:?}"))
                })?;

                otel_debug!(name: "RamaGrpcOtelTraces.ExportSucceeded");

                if let Some(partial_success) =
                    response
                        .into_inner()
                        .partial_success
                        .filter(|partial_success| {
                            partial_success.rejected_spans > 0
                                || !partial_success.error_message.is_empty()
                        })
                {
                    otel_warn!(
                        name: "RamaGrpcOtelTraces.PartialSuccess",
                        rejected_spans = partial_success.rejected_spans,
                        error_message = partial_success.error_message.as_str(),
                    );
                }

                Ok(())
            })
        });

        join.await
            .map_err(|err| OTelSdkError::InternalFailure(err.to_string()))?
    }

    fn shutdown_with_timeout(&mut self, _timeout: Duration) -> OTelSdkResult {
        if self.shutdown.swap(true, Ordering::SeqCst) {
            return Err(OTelSdkError::AlreadyShutdown);
        }

        Ok(())
    }

    fn force_flush(&mut self) -> OTelSdkResult {
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(OTelSdkError::AlreadyShutdown);
        }

        Ok(())
    }

    fn set_resource(&mut self, resource: &sdk::Resource) {
        let mut guard = self.resource.write();
        *guard = resource.into();
    }
}

impl<S> PushMetricExporter for OtelExporter<S>
where
    S: fmt::Debug + Clone + GrpcService<Body>,
    S::ResponseBody: StreamingBody<Error: Into<BoxError>> + Send + Sync + 'static,
{
    async fn export(&self, metrics: &ResourceMetrics) -> OTelSdkResult {
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(OTelSdkError::AlreadyShutdown);
        }

        let service = self.service.clone();
        let handle = self.handle.clone();
        let config = self.metrics_config();
        let shutdown = self.shutdown.clone();
        let request_body = transform::resource_metrics_to_request(metrics);

        // gRPC client futures are !Send, so run them on the runtime via a blocking task.
        let runtime = handle.clone();
        let join = handle.spawn_blocking(move || {
            runtime.block_on(async move {
                if shutdown.load(Ordering::SeqCst) {
                    return Err(OTelSdkError::AlreadyShutdown);
                }

                let mut grpc = Grpc::new(service, config.endpoint);
                if let Some(compression) = config.compression {
                    grpc = grpc
                        .with_send_compressed(compression)
                        .with_accept_compressed(compression);
                }

                let mut request = Request::new(request_body);
                *request.metadata_mut() = config.metadata;
                if let Some(timeout) = config.timeout {
                    request
                        .try_set_timeout(timeout)
                        .map_err(|err| OTelSdkError::InternalFailure(err.to_string()))?;
                }

                let rpc = grpc.unary(
                    request,
                    PathAndQuery::from_static(METRICS_EXPORT_PATH),
                    ProstCodec::<ExportMetricsServiceRequest, ExportMetricsServiceResponse>::new(),
                );

                let response = match config.timeout {
                    Some(timeout) => match tokio::time::timeout(timeout, rpc).await {
                        Ok(result) => result,
                        Err(_) => return Err(OTelSdkError::Timeout(timeout)),
                    },
                    None => rpc.await,
                }
                .map_err(|status| {
                    OTelSdkError::InternalFailure(format!("export error: {status:?}"))
                })?;

                otel_debug!(name: "RamaGrpcOtelMetrics.ExportSucceeded");

                if let Some(partial_success) =
                    response
                        .into_inner()
                        .partial_success
                        .filter(|partial_success| {
                            partial_success.rejected_data_points > 0
                                || !partial_success.error_message.is_empty()
                        })
                {
                    otel_warn!(
                        name: "RamaGrpcOtelMetrics.PartialSuccess",
                        rejected_data_points = partial_success.rejected_data_points,
                        error_message = partial_success.error_message.as_str(),
                    );
                }

                Ok(())
            })
        });

        join.await
            .map_err(|err| OTelSdkError::InternalFailure(err.to_string()))?
    }

    fn force_flush(&self) -> OTelSdkResult {
        if self.shutdown.load(Ordering::SeqCst) {
            return Err(OTelSdkError::AlreadyShutdown);
        }

        Ok(())
    }

    fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
        if self.shutdown.swap(true, Ordering::SeqCst) {
            return Err(OTelSdkError::AlreadyShutdown);
        }

        Ok(())
    }

    fn temporality(&self) -> Temporality {
        self.temporality
    }
}

fn env_endpoint(var: &'static str) -> Result<Option<Uri>, OtelExporterConfigError> {
    let value = match std::env::var(var) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(err) => {
            return Err(OtelExporterConfigError::new(format!(
                "failed to read {var}: {err}"
            )));
        }
    };

    let endpoint = value
        .parse::<Uri>()
        .map_err(|_| OtelExporterConfigError::new(format!("invalid {var} value: {value}")))?;

    Ok(Some(endpoint))
}

fn env_timeout(var: &'static str) -> Result<Option<Duration>, OtelExporterConfigError> {
    let value = match std::env::var(var) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(err) => {
            return Err(OtelExporterConfigError::new(format!(
                "failed to read {var}: {err}"
            )));
        }
    };

    let timeout_ms = value
        .parse::<u64>()
        .map_err(|_| OtelExporterConfigError::new(format!("invalid {var} value: {value}")))?;

    Ok(Some(Duration::from_millis(timeout_ms)))
}

fn env_headers(var: &'static str) -> Result<Option<MetadataMap>, OtelExporterConfigError> {
    let value = match std::env::var(var) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(err) => {
            return Err(OtelExporterConfigError::new(format!(
                "failed to read {var}: {err}"
            )));
        }
    };

    let mut metadata = MetadataMap::new();
    for (key, value) in parse_header_string(&value) {
        if key.ends_with("-bin") {
            let key = crate::metadata::BinaryMetadataKey::from_str(&key).map_err(|err| {
                OtelExporterConfigError::new(format!("invalid {var} key {key}: {err}"))
            })?;
            let parsed = crate::metadata::BinaryMetadataValue::try_from(value.into_bytes())
                .map_err(|err| {
                    OtelExporterConfigError::new(format!("invalid {var} value for {key}: {err}"))
                })?;
            metadata.insert_bin(key, parsed);
        } else {
            let key = crate::metadata::AsciiMetadataKey::from_str(&key).map_err(|err| {
                OtelExporterConfigError::new(format!("invalid {var} key {key}: {err}"))
            })?;
            let parsed = value.parse().map_err(|err| {
                OtelExporterConfigError::new(format!("invalid {var} value for {key}: {err}"))
            })?;
            metadata.insert(key, parsed);
        }
    }

    Ok(Some(metadata))
}

enum EnvCompressionSetting {
    Unset,
    Value(Option<CompressionEncoding>),
}

fn env_compression(var: &'static str) -> Result<EnvCompressionSetting, OtelExporterConfigError> {
    let value = match std::env::var(var) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(EnvCompressionSetting::Unset),
        Err(err) => {
            return Err(OtelExporterConfigError::new(format!(
                "failed to read {var}: {err}"
            )));
        }
    };

    let encoding = match value.trim().to_ascii_lowercase().as_str() {
        "" | "none" => None,
        "gzip" => Some(CompressionEncoding::Gzip),
        "zstd" => Some(CompressionEncoding::Zstd),
        "deflate" => Some(CompressionEncoding::Deflate),
        other => {
            return Err(OtelExporterConfigError::new(format!(
                "invalid {var} compression value: {other}"
            )));
        }
    };

    Ok(EnvCompressionSetting::Value(encoding))
}

fn parse_header_string(value: &str) -> impl Iterator<Item = (String, String)> + '_ {
    value.split_terminator(',').filter_map(|pair| {
        let pair = pair.trim();
        if pair.is_empty() {
            return None;
        }
        let (key, value) = pair.split_once('=')?;
        let key = key.trim();
        if key.is_empty() {
            return None;
        }
        let value = value.trim();
        let value = percent_decode(value.as_bytes())
            .decode_utf8()
            .map(|value| value.into_owned())
            .unwrap_or_else(|_| value.to_owned());
        if value.is_empty() {
            return None;
        }
        Some((key.to_owned(), value))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    fn with_env_var<T>(key: &'static str, value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock();
        let previous = std::env::var(key).ok();

        match value {
            Some(value) => unsafe { std::env::set_var(key, value) },
            None => unsafe { std::env::remove_var(key) },
        }

        let result = f();

        match previous {
            Some(value) => unsafe { std::env::set_var(key, value) },
            None => unsafe { std::env::remove_var(key) },
        }

        result
    }

    #[test]
    fn parse_header_string_decodes_percent_encoded_values() {
        let headers = parse_header_string("authorization=Bearer%20abc%2F123").collect::<Vec<_>>();
        assert_eq!(
            headers,
            vec![("authorization".to_owned(), "Bearer abc/123".to_owned())]
        );
    }

    #[tokio::test]
    async fn resolved_trace_config_prefers_programmatic_override_over_env_signal_value() {
        with_env_var(
            OTEL_EXPORTER_OTLP_TRACES_ENDPOINT,
            Some("http://localhost:4318"),
            || {
                let exporter = OtelExporter::from_env(())
                    .expect("env config should parse")
                    .with_endpoint(Uri::from_static("http://localhost:9999"));

                assert_eq!(
                    exporter.trace_config().endpoint,
                    Uri::from_static("http://localhost:9999")
                );
            },
        );
    }
}
