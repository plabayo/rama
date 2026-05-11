use super::{
    EnvCompressionSetting, OTEL_EXPORTER_OTLP_COMPRESSION, OTEL_EXPORTER_OTLP_ENDPOINT,
    OTEL_EXPORTER_OTLP_HEADERS, OTEL_EXPORTER_OTLP_LOGS_COMPRESSION,
    OTEL_EXPORTER_OTLP_LOGS_ENDPOINT, OTEL_EXPORTER_OTLP_LOGS_HEADERS,
    OTEL_EXPORTER_OTLP_LOGS_TIMEOUT, OTEL_EXPORTER_OTLP_METRICS_COMPRESSION,
    OTEL_EXPORTER_OTLP_METRICS_ENDPOINT, OTEL_EXPORTER_OTLP_METRICS_HEADERS,
    OTEL_EXPORTER_OTLP_METRICS_TIMEOUT, OTEL_EXPORTER_OTLP_TIMEOUT,
    OTEL_EXPORTER_OTLP_TRACES_COMPRESSION, OTEL_EXPORTER_OTLP_TRACES_ENDPOINT,
    OTEL_EXPORTER_OTLP_TRACES_HEADERS, OTEL_EXPORTER_OTLP_TRACES_TIMEOUT, OtelExporterConfigError,
    env_compression, env_endpoint, env_timeout, parse_header_string, transform,
};
use crate::{
    codec::{
        CompressionEncoding,
        compression::{CompressionSettings, compress},
    },
    service::opentelemetry::proto::{
        ExportLogsServiceResponse, ExportMetricsServiceResponse, ExportTraceServiceResponse,
    },
};
use arc_swap::ArcSwap;
use prost::Message;
use rama_core::{
    Service,
    bytes::BytesMut,
    error::BoxError,
    telemetry::opentelemetry::{
        otel_debug, otel_warn,
        sdk::{
            self,
            error::{OTelSdkError, OTelSdkResult},
            logs::{LogBatch, LogExporter},
            metrics::exporter::PushMetricExporter,
            metrics::{Temporality, data::ResourceMetrics},
            trace::{SpanData, SpanExporter},
        },
    },
};
use rama_http::{
    Body, HeaderMap, HeaderName, HeaderValue, Method, Request, Response, Uri,
    body::util::BodyExt as _, header::CONTENT_TYPE, uri::PathAndQuery,
};
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

const DEFAULT_OTLP_HTTP_ENDPOINT: &str = "http://localhost:4318";
const OTLP_HTTP_TRACE_PATH: &str = "/v1/traces";
const OTLP_HTTP_METRICS_PATH: &str = "/v1/metrics";
const OTLP_HTTP_LOGS_PATH: &str = "/v1/logs";
const PROTOBUF_CONTENT_TYPE: &str = "application/x-protobuf";
const CONTENT_ENCODING: &str = "content-encoding";

#[must_use]
#[derive(Debug, Clone)]
pub struct HttpExporter<S = ()> {
    service: S,
    endpoint: Option<Uri>,
    timeout: Option<Duration>,
    compression: Option<CompressionEncoding>,
    headers: HeaderMap,
    traces: SignalSettings,
    metrics: SignalSettings,
    logs: SignalSettings,
    env: EnvSettings,
    temporality: Temporality,
    resource: Arc<ArcSwap<transform::ResourceAttributesWithSchema>>,
    shutdown: Arc<AtomicBool>,
    runtime: Option<tokio::runtime::Handle>,
}

#[derive(Debug, Clone, Default)]
struct SignalSettings {
    endpoint: Option<Uri>,
    timeout: Option<Duration>,
    compression: Option<CompressionEncoding>,
    headers: HeaderMap,
}

#[derive(Debug, Clone, Default)]
struct EnvSettings {
    base: SignalSettings,
    traces: SignalSettings,
    metrics: SignalSettings,
    logs: SignalSettings,
}

#[derive(Debug, Clone, Copy)]
enum SignalKind {
    Traces,
    Metrics,
    Logs,
}

struct ResolvedConfig {
    endpoint: Uri,
    timeout: Option<Duration>,
    compression: Option<CompressionEncoding>,
    headers: HeaderMap,
}

impl<S> HttpExporter<S> {
    pub fn new(service: S) -> Self {
        Self {
            service,
            endpoint: None,
            timeout: None,
            compression: None,
            headers: HeaderMap::new(),
            traces: SignalSettings::default(),
            metrics: SignalSettings::default(),
            logs: SignalSettings::default(),
            env: EnvSettings::default(),
            temporality: Temporality::Cumulative,
            resource: Arc::new(ArcSwap::from_pointee(
                transform::ResourceAttributesWithSchema::default(),
            )),
            shutdown: Arc::new(AtomicBool::new(false)),
            runtime: tokio::runtime::Handle::try_current().ok(),
        }
    }

    pub fn from_env(service: S) -> Result<Self, OtelExporterConfigError> {
        let mut exporter = Self::new(service);
        exporter.apply_env()?;
        Ok(exporter)
    }

    generate_set_and_with!(
        /// Override the base OTLP HTTP endpoint.
        pub fn endpoint(mut self, endpoint: Uri) -> Self {
            self.endpoint = Some(endpoint);
            self
        }
    );

    generate_set_and_with!(
        /// Override the base OTLP HTTP timeout.
        pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
            self.timeout = timeout;
            self
        }
    );

    generate_set_and_with!(
        /// Override the base OTLP HTTP compression.
        pub fn compression(mut self, compression: Option<CompressionEncoding>) -> Self {
            self.compression = compression;
            self
        }
    );

    generate_set_and_with!(
        /// Override the base OTLP HTTP headers.
        pub fn headers(mut self, headers: HeaderMap) -> Self {
            self.headers = headers;
            self
        }
    );

    generate_set_and_with!(
        /// Override the trace-specific OTLP HTTP endpoint.
        pub fn traces_endpoint(mut self, endpoint: Option<Uri>) -> Self {
            self.traces.endpoint = endpoint;
            self
        }
    );

    generate_set_and_with!(
        /// Override the trace-specific OTLP HTTP timeout.
        pub fn traces_timeout(mut self, timeout: Option<Duration>) -> Self {
            self.traces.timeout = timeout;
            self
        }
    );

    generate_set_and_with!(
        /// Override the trace-specific OTLP HTTP compression.
        pub fn traces_compression(mut self, compression: Option<CompressionEncoding>) -> Self {
            self.traces.compression = compression;
            self
        }
    );

    generate_set_and_with!(
        /// Override the trace-specific OTLP HTTP headers.
        pub fn traces_headers(mut self, headers: HeaderMap) -> Self {
            self.traces.headers = headers;
            self
        }
    );

    generate_set_and_with!(
        /// Override the metrics-specific OTLP HTTP endpoint.
        pub fn metrics_endpoint(mut self, endpoint: Option<Uri>) -> Self {
            self.metrics.endpoint = endpoint;
            self
        }
    );

    generate_set_and_with!(
        /// Override the metrics-specific OTLP HTTP timeout.
        pub fn metrics_timeout(mut self, timeout: Option<Duration>) -> Self {
            self.metrics.timeout = timeout;
            self
        }
    );

    generate_set_and_with!(
        /// Override the metrics-specific OTLP HTTP compression.
        pub fn metrics_compression(mut self, compression: Option<CompressionEncoding>) -> Self {
            self.metrics.compression = compression;
            self
        }
    );

    generate_set_and_with!(
        /// Override the metrics-specific OTLP HTTP headers.
        pub fn metrics_headers(mut self, headers: HeaderMap) -> Self {
            self.metrics.headers = headers;
            self
        }
    );

    generate_set_and_with!(
        /// Override the logs-specific OTLP HTTP endpoint.
        pub fn logs_endpoint(mut self, endpoint: Option<Uri>) -> Self {
            self.logs.endpoint = endpoint;
            self
        }
    );

    generate_set_and_with!(
        /// Override the logs-specific OTLP HTTP timeout.
        pub fn logs_timeout(mut self, timeout: Option<Duration>) -> Self {
            self.logs.timeout = timeout;
            self
        }
    );

    generate_set_and_with!(
        /// Override the logs-specific OTLP HTTP compression.
        pub fn logs_compression(mut self, compression: Option<CompressionEncoding>) -> Self {
            self.logs.compression = compression;
            self
        }
    );

    generate_set_and_with!(
        /// Override the logs-specific OTLP HTTP headers.
        pub fn logs_headers(mut self, headers: HeaderMap) -> Self {
            self.logs.headers = headers;
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

    generate_set_and_with!(
        /// Override the tokio runtime used to drive each export.
        ///
        /// `new` captures `Handle::try_current()` automatically. Use this to
        /// pin the exporter to a specific runtime, or pass `None` to require
        /// the caller to provide a tokio context for every `export` call.
        pub fn runtime(mut self, runtime: Option<tokio::runtime::Handle>) -> Self {
            self.runtime = runtime;
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
        if let Some(headers) = env_headers(OTEL_EXPORTER_OTLP_HEADERS)? {
            self.env.base.headers = headers;
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
        if let Some(headers) = env_headers(OTEL_EXPORTER_OTLP_TRACES_HEADERS)? {
            self.env.traces.headers = headers;
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
        if let Some(headers) = env_headers(OTEL_EXPORTER_OTLP_METRICS_HEADERS)? {
            self.env.metrics.headers = headers;
        }
        match env_compression(OTEL_EXPORTER_OTLP_METRICS_COMPRESSION)? {
            EnvCompressionSetting::Unset => {}
            EnvCompressionSetting::Value(compression) => {
                self.env.metrics.compression = compression;
            }
        }

        if let Some(endpoint) = env_endpoint(OTEL_EXPORTER_OTLP_LOGS_ENDPOINT)? {
            self.env.logs.endpoint = Some(endpoint);
        }
        if let Some(timeout) = env_timeout(OTEL_EXPORTER_OTLP_LOGS_TIMEOUT)? {
            self.env.logs.timeout = Some(timeout);
        }
        if let Some(headers) = env_headers(OTEL_EXPORTER_OTLP_LOGS_HEADERS)? {
            self.env.logs.headers = headers;
        }
        match env_compression(OTEL_EXPORTER_OTLP_LOGS_COMPRESSION)? {
            EnvCompressionSetting::Unset => {}
            EnvCompressionSetting::Value(compression) => {
                self.env.logs.compression = compression;
            }
        }

        Ok(())
    }

    fn trace_config(&self) -> Result<ResolvedConfig, OTelSdkError> {
        ResolvedConfig::new(self, SignalKind::Traces)
            .map_err(|err| OTelSdkError::InternalFailure(err.to_string()))
    }

    fn metrics_config(&self) -> Result<ResolvedConfig, OTelSdkError> {
        ResolvedConfig::new(self, SignalKind::Metrics)
            .map_err(|err| OTelSdkError::InternalFailure(err.to_string()))
    }

    fn logs_config(&self) -> Result<ResolvedConfig, OTelSdkError> {
        ResolvedConfig::new(self, SignalKind::Logs)
            .map_err(|err| OTelSdkError::InternalFailure(err.to_string()))
    }
}

impl<S> HttpExporter<S>
where
    S: fmt::Debug + Clone + Service<Request<Body>, Output = Response<Body>, Error: Into<BoxError>>,
{
    async fn export_request<Req, Resp>(
        &self,
        signal_kind: SignalKind,
        request_body: Req,
    ) -> Result<Resp, OTelSdkError>
    where
        Req: Message,
        Resp: Message + Default + Send + 'static,
    {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(OTelSdkError::AlreadyShutdown);
        }

        let config = match signal_kind {
            SignalKind::Traces => self.trace_config()?,
            SignalKind::Metrics => self.metrics_config()?,
            SignalKind::Logs => self.logs_config()?,
        };

        let body = encode_body(request_body, config.compression)
            .map_err(|err| OTelSdkError::InternalFailure(err.to_string()))?;

        let mut request = Request::builder()
            .method(Method::POST)
            .uri(config.endpoint)
            .body(Body::from(body.freeze()))
            .map_err(|err| OTelSdkError::InternalFailure(err.to_string()))?;

        request.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static(PROTOBUF_CONTENT_TYPE),
        );
        if let Some(compression) = config.compression {
            request.headers_mut().insert(
                HeaderName::from_static(CONTENT_ENCODING),
                HeaderValue::from_str(compression.as_str())
                    .map_err(|err| OTelSdkError::InternalFailure(err.to_string()))?,
            );
        }
        merge_headers(request.headers_mut(), &config.headers);

        let service = self.service.clone();
        let timeout = config.timeout;
        let work = async move {
            let response = match timeout {
                Some(timeout) => {
                    match tokio::time::timeout(timeout, service.serve(request)).await {
                        Ok(result) => result,
                        Err(_) => return Err(OTelSdkError::Timeout(timeout)),
                    }
                }
                None => service.serve(request).await,
            }
            .map_err(|err| OTelSdkError::InternalFailure(err.into().to_string()))?;

            decode_response(response).await
        };

        match self.runtime.as_ref() {
            Some(handle) => handle
                .spawn(work)
                .await
                .map_err(|err| OTelSdkError::InternalFailure(err.to_string()))?,
            None => work.await,
        }
    }
}

impl<S> SpanExporter for HttpExporter<S>
where
    S: fmt::Debug + Clone + Service<Request<Body>, Output = Response<Body>, Error: Into<BoxError>>,
{
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        let request_body = {
            let resource = self.resource.load();
            transform::span_batch_to_request(&batch, &resource)
        };
        let response: ExportTraceServiceResponse = self
            .export_request(SignalKind::Traces, request_body)
            .await?;

        otel_debug!(name: "RamaHttpOtelTraces.ExportSucceeded");

        if let Some(partial_success) = response.partial_success.filter(|partial_success| {
            partial_success.rejected_spans > 0 || !partial_success.error_message.is_empty()
        }) {
            otel_warn!(
                name: "RamaHttpOtelTraces.PartialSuccess",
                rejected_spans = partial_success.rejected_spans,
                error_message = partial_success.error_message.as_str(),
            );
        }

        Ok(())
    }

    fn shutdown_with_timeout(&mut self, _timeout: Duration) -> OTelSdkResult {
        if self.shutdown.swap(true, Ordering::AcqRel) {
            return Err(OTelSdkError::AlreadyShutdown);
        }

        Ok(())
    }

    fn force_flush(&mut self) -> OTelSdkResult {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(OTelSdkError::AlreadyShutdown);
        }

        Ok(())
    }

    fn set_resource(&mut self, resource: &sdk::Resource) {
        self.resource.store(Arc::new(resource.into()));
    }
}

impl<S> PushMetricExporter for HttpExporter<S>
where
    S: fmt::Debug + Clone + Service<Request<Body>, Output = Response<Body>, Error: Into<BoxError>>,
{
    async fn export(&self, metrics: &ResourceMetrics) -> OTelSdkResult {
        let response: ExportMetricsServiceResponse = self
            .export_request(
                SignalKind::Metrics,
                transform::resource_metrics_to_request(metrics),
            )
            .await?;

        otel_debug!(name: "RamaHttpOtelMetrics.ExportSucceeded");

        if let Some(partial_success) = response.partial_success.filter(|partial_success| {
            partial_success.rejected_data_points > 0 || !partial_success.error_message.is_empty()
        }) {
            otel_warn!(
                name: "RamaHttpOtelMetrics.PartialSuccess",
                rejected_data_points = partial_success.rejected_data_points,
                error_message = partial_success.error_message.as_str(),
            );
        }

        Ok(())
    }

    fn force_flush(&self) -> OTelSdkResult {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(OTelSdkError::AlreadyShutdown);
        }

        Ok(())
    }

    fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
        if self.shutdown.swap(true, Ordering::AcqRel) {
            return Err(OTelSdkError::AlreadyShutdown);
        }

        Ok(())
    }

    fn temporality(&self) -> Temporality {
        self.temporality
    }
}

impl<S> LogExporter for HttpExporter<S>
where
    S: fmt::Debug + Clone + Service<Request, Output = Response, Error: Into<BoxError>>,
{
    async fn export(&self, batch: LogBatch<'_>) -> OTelSdkResult {
        let request_body = {
            let resource = self.resource.load();
            transform::log_batch_to_request(&batch, &resource)
        };

        let response: ExportLogsServiceResponse =
            self.export_request(SignalKind::Logs, request_body).await?;

        otel_debug!(name: "RamaHttpOtelLogs.ExportSucceeded");

        if let Some(partial_success) = response.partial_success.filter(|partial_success| {
            partial_success.rejected_log_records > 0 || !partial_success.error_message.is_empty()
        }) {
            otel_warn!(
                name: "RamaHttpOtelLogs.PartialSuccess",
                rejected_log_records = partial_success.rejected_log_records,
                error_message = partial_success.error_message.as_str(),
            );
        }

        Ok(())
    }

    fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
        if self.shutdown.swap(true, Ordering::AcqRel) {
            return Err(OTelSdkError::AlreadyShutdown);
        }

        Ok(())
    }

    fn set_resource(&mut self, resource: &sdk::Resource) {
        self.resource.store(Arc::new(resource.into()));
    }
}

impl ResolvedConfig {
    fn new<S>(
        exporter: &HttpExporter<S>,
        signal_kind: SignalKind,
    ) -> Result<Self, OtelExporterConfigError> {
        let (signal, env_signal, path) = match signal_kind {
            SignalKind::Traces => (&exporter.traces, &exporter.env.traces, OTLP_HTTP_TRACE_PATH),
            SignalKind::Metrics => (
                &exporter.metrics,
                &exporter.env.metrics,
                OTLP_HTTP_METRICS_PATH,
            ),
            SignalKind::Logs => (&exporter.logs, &exporter.env.logs, OTLP_HTTP_LOGS_PATH),
        };

        let signal_endpoint = signal
            .endpoint
            .clone()
            .or_else(|| env_signal.endpoint.clone());
        let endpoint = match signal_endpoint {
            Some(endpoint) => endpoint,
            None => append_signal_path(
                exporter
                    .endpoint
                    .clone()
                    .or_else(|| exporter.env.base.endpoint.clone())
                    .unwrap_or_else(|| Uri::from_static(DEFAULT_OTLP_HTTP_ENDPOINT)),
                path,
            )?,
        };

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

        let mut headers = exporter.env.base.headers.clone();
        merge_headers(&mut headers, &env_signal.headers);
        merge_headers(&mut headers, &exporter.headers);
        merge_headers(&mut headers, &signal.headers);

        Ok(Self {
            endpoint,
            timeout,
            compression,
            headers,
        })
    }
}

fn append_signal_path(base: Uri, signal_path: &str) -> Result<Uri, OtelExporterConfigError> {
    // TODO: this manual `Uri::into_parts` / `PathAndQuery` surgery is only here because
    // Rama does not yet expose a nicer native URI composition API for this use case.
    // Once that lands in rama-net, revisit this path-joining logic and simplify it.
    // See: https://github.com/plabayo/rama/issues/724
    let base_str = base.to_string();
    let mut parts = base.into_parts();
    let path_and_query = parts
        .path_and_query
        .as_ref()
        .map(PathAndQuery::as_str)
        .unwrap_or("/");
    let (path, query) = match path_and_query.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path_and_query, None),
    };

    let mut joined_path = path.trim_end_matches('/').to_owned();
    joined_path.push_str(signal_path);
    let joined_path_and_query = match query {
        Some(query) => format!("{joined_path}?{query}"),
        None => joined_path,
    };

    parts.path_and_query = Some(
        PathAndQuery::from_str(&joined_path_and_query).map_err(|err| {
            OtelExporterConfigError::new(format!(
                "invalid OTLP HTTP endpoint derived from {base_str:?}: {err}"
            ))
        })?,
    );

    Uri::from_parts(parts).map_err(|err| {
        OtelExporterConfigError::new(format!(
            "invalid OTLP HTTP endpoint derived from {base_str:?}: {err}"
        ))
    })
}

fn merge_headers(target: &mut HeaderMap, source: &HeaderMap) {
    for (key, value) in source.iter() {
        target.insert(key, value.clone());
    }
}

fn env_headers(var: &'static str) -> Result<Option<HeaderMap>, OtelExporterConfigError> {
    let Some(value) = std::env::var_os(var) else {
        return Ok(None);
    };
    let value = value
        .into_string()
        .map_err(|_e| OtelExporterConfigError::new(format!("{var} contains invalid unicode")))?;

    let mut headers = HeaderMap::new();
    for (key, value) in parse_header_string(&value) {
        let key = HeaderName::from_str(&key).map_err(|err| {
            OtelExporterConfigError::new(format!(
                "{var} contains invalid header name {key:?}: {err}"
            ))
        })?;
        let value = HeaderValue::from_str(&value).map_err(|err| {
            OtelExporterConfigError::new(format!(
                "{var} contains invalid header value {value:?}: {err}"
            ))
        })?;
        headers.insert(key, value);
    }

    Ok(Some(headers))
}

async fn decode_response<T>(response: Response<Body>) -> Result<T, OTelSdkError>
where
    T: Message + Default,
{
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|err| OTelSdkError::InternalFailure(err.to_string()))?
        .to_bytes();

    if !status.is_success() {
        return Err(OTelSdkError::InternalFailure(format!(
            "export error: HTTP {status}"
        )));
    }

    if body.is_empty() {
        return Ok(T::default());
    }

    T::decode(body).map_err(|err| OTelSdkError::InternalFailure(err.to_string()))
}

#[expect(clippy::needless_pass_by_value)]
fn encode_body<T>(
    message: T,
    compression: Option<CompressionEncoding>,
) -> Result<BytesMut, BoxError>
where
    T: Message,
{
    let mut body = BytesMut::with_capacity(message.encoded_len());
    message.encode(&mut body)?;

    match compression {
        Some(compression) => {
            let len = body.len();
            let mut compressed = BytesMut::new();
            compress(
                CompressionSettings {
                    encoding: compression,
                    buffer_growth_interval: 8 * 1024,
                },
                &mut body,
                &mut compressed,
                len,
            )?;
            Ok(compressed)
        }
        None => Ok(body),
    }
}
