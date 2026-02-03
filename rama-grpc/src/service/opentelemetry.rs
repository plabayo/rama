use crate::{
    Request,
    client::{Grpc, GrpcService},
    codec::CompressionEncoding,
    metadata::MetadataMap,
    protobuf::ProstCodec,
};
use opentelemetry::{otel_debug, otel_warn};
use opentelemetry_proto::{
    tonic::collector::{
        metrics::v1::{ExportMetricsServiceRequest, ExportMetricsServiceResponse},
        trace::v1::{ExportTraceServiceRequest, ExportTraceServiceResponse},
    },
    transform::{
        common::tonic::ResourceAttributesWithSchema,
        trace::tonic::group_spans_by_resource_and_scope,
    },
};
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use opentelemetry_sdk::{
    error::{OTelSdkError, OTelSdkResult},
    metrics::{Temporality, data::ResourceMetrics},
    trace::{SpanData, SpanExporter},
};
use rama_core::error::BoxError;
use rama_http::{
    Body, StreamingBody,
    uri::{PathAndQuery, Uri},
};
use std::{
    fmt,
    str::FromStr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

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
    endpoint: Uri,
    timeout: Option<Duration>,
    compression: Option<CompressionEncoding>,
    metadata: MetadataMap,
    traces: SignalSettings,
    metrics: SignalSettings,
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
            endpoint: Uri::from_static(DEFAULT_OTLP_GRPC_ENDPOINT),
            timeout: None,
            compression: None,
            metadata: MetadataMap::new(),
            traces: SignalSettings::default(),
            metrics: SignalSettings::default(),
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

    /// Override the base OTLP endpoint.
    pub fn with_endpoint(mut self, endpoint: Uri) -> Self {
        self.endpoint = endpoint;
        self
    }

    /// Override the base OTLP timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Override the base OTLP compression.
    pub fn with_compression(mut self, compression: CompressionEncoding) -> Self {
        self.compression = Some(compression);
        self
    }

    /// Override the base OTLP metadata.
    pub fn with_metadata(mut self, metadata: MetadataMap) -> Self {
        self.metadata = metadata;
        self
    }

    /// Override the trace-specific endpoint.
    pub fn with_traces_endpoint(mut self, endpoint: Uri) -> Self {
        self.traces.endpoint = Some(endpoint);
        self
    }

    /// Override the trace-specific timeout.
    pub fn with_traces_timeout(mut self, timeout: Duration) -> Self {
        self.traces.timeout = Some(timeout);
        self
    }

    /// Override the trace-specific compression.
    pub fn with_traces_compression(mut self, compression: CompressionEncoding) -> Self {
        self.traces.compression = Some(compression);
        self
    }

    /// Override the trace-specific metadata.
    pub fn with_traces_metadata(mut self, metadata: MetadataMap) -> Self {
        self.traces.metadata = metadata;
        self
    }

    /// Override the metrics-specific endpoint.
    pub fn with_metrics_endpoint(mut self, endpoint: Uri) -> Self {
        self.metrics.endpoint = Some(endpoint);
        self
    }

    /// Override the metrics-specific timeout.
    pub fn with_metrics_timeout(mut self, timeout: Duration) -> Self {
        self.metrics.timeout = Some(timeout);
        self
    }

    /// Override the metrics-specific compression.
    pub fn with_metrics_compression(mut self, compression: CompressionEncoding) -> Self {
        self.metrics.compression = Some(compression);
        self
    }

    /// Override the metrics-specific metadata.
    pub fn with_metrics_metadata(mut self, metadata: MetadataMap) -> Self {
        self.metrics.metadata = metadata;
        self
    }

    /// Configure the metric temporality used by this exporter.
    pub fn with_temporality(mut self, temporality: Temporality) -> Self {
        self.temporality = temporality;
        self
    }

    fn apply_env(&mut self) -> Result<(), OtelExporterConfigError> {
        if let Some(endpoint) = env_endpoint(OTEL_EXPORTER_OTLP_ENDPOINT)? {
            self.endpoint = endpoint;
        }
        if let Some(timeout) = env_timeout(OTEL_EXPORTER_OTLP_TIMEOUT)? {
            self.timeout = Some(timeout);
        }
        if let Some(metadata) = env_headers(OTEL_EXPORTER_OTLP_HEADERS)? {
            self.metadata = metadata;
        }
        match env_compression(OTEL_EXPORTER_OTLP_COMPRESSION)? {
            EnvCompressionSetting::Unset => {}
            EnvCompressionSetting::Value(compression) => {
                self.compression = compression;
            }
        }

        if let Some(endpoint) = env_endpoint(OTEL_EXPORTER_OTLP_TRACES_ENDPOINT)? {
            self.traces.endpoint = Some(endpoint);
        }
        if let Some(timeout) = env_timeout(OTEL_EXPORTER_OTLP_TRACES_TIMEOUT)? {
            self.traces.timeout = Some(timeout);
        }
        if let Some(metadata) = env_headers(OTEL_EXPORTER_OTLP_TRACES_HEADERS)? {
            self.traces.metadata = metadata;
        }
        match env_compression(OTEL_EXPORTER_OTLP_TRACES_COMPRESSION)? {
            EnvCompressionSetting::Unset => {}
            EnvCompressionSetting::Value(compression) => {
                self.traces.compression = compression;
            }
        }

        if let Some(endpoint) = env_endpoint(OTEL_EXPORTER_OTLP_METRICS_ENDPOINT)? {
            self.metrics.endpoint = Some(endpoint);
        }
        if let Some(timeout) = env_timeout(OTEL_EXPORTER_OTLP_METRICS_TIMEOUT)? {
            self.metrics.timeout = Some(timeout);
        }
        if let Some(metadata) = env_headers(OTEL_EXPORTER_OTLP_METRICS_HEADERS)? {
            self.metrics.metadata = metadata;
        }
        match env_compression(OTEL_EXPORTER_OTLP_METRICS_COMPRESSION)? {
            EnvCompressionSetting::Unset => {}
            EnvCompressionSetting::Value(compression) => {
                self.metrics.compression = compression;
            }
        }

        Ok(())
    }

    fn trace_config(&self) -> ResolvedConfig {
        ResolvedConfig::new(self, &self.traces)
    }

    fn metrics_config(&self) -> ResolvedConfig {
        ResolvedConfig::new(self, &self.metrics)
    }
}

struct ResolvedConfig {
    endpoint: Uri,
    timeout: Option<Duration>,
    compression: Option<CompressionEncoding>,
    metadata: MetadataMap,
}

impl ResolvedConfig {
    fn new<S>(exporter: &OtelExporter<S>, signal: &SignalSettings) -> Self {
        let endpoint = signal
            .endpoint
            .clone()
            .unwrap_or_else(|| exporter.endpoint.clone());
        let timeout = signal.timeout.or(exporter.timeout);
        let compression = signal.compression.or(exporter.compression);

        let metadata = if signal.metadata.is_empty() {
            exporter.metadata.clone()
        } else if exporter.metadata.is_empty() {
            signal.metadata.clone()
        } else {
            let mut merged = exporter.metadata.clone();
            merged.merge(signal.metadata.clone());
            merged
        };

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
                    let guard = resource.read().map_err(|_| {
                        OTelSdkError::InternalFailure("resource lock poisoned".to_owned())
                    })?;
                    group_spans_by_resource_and_scope(batch, &guard)
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

    fn set_resource(&mut self, resource: &opentelemetry_sdk::Resource) {
        if let Ok(mut guard) = self.resource.write() {
            *guard = resource.into();
        }
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
        let request_body = ExportMetricsServiceRequest::from(metrics);

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
        Some((key.to_owned(), value.trim().to_owned()))
    })
}
