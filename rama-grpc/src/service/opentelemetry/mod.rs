use crate::codec::CompressionEncoding;
use prost::Message;
use rama_core::telemetry::opentelemetry::{
    otel_debug, otel_warn,
    sdk::{
        self,
        error::{OTelSdkError, OTelSdkResult},
        logs::{LogBatch, LogExporter},
        metrics::exporter::PushMetricExporter,
        metrics::{Temporality, data::ResourceMetrics},
        trace::{SpanData, SpanExporter},
    },
};
use rama_http::uri::Uri;
use rama_net::uri::util::percent_encoding::percent_decode;
use rama_utils::macros::generate_set_and_with;
use std::{
    fmt,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

mod grpc;
mod http;
pub mod proto;
mod transform;

use proto::{ExportLogsServiceResponse, ExportMetricsServiceResponse, ExportTraceServiceResponse};

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

const OTEL_EXPORTER_OTLP_LOGS_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT";
const OTEL_EXPORTER_OTLP_LOGS_TIMEOUT: &str = "OTEL_EXPORTER_OTLP_LOGS_TIMEOUT";
const OTEL_EXPORTER_OTLP_LOGS_HEADERS: &str = "OTEL_EXPORTER_OTLP_LOGS_HEADERS";
const OTEL_EXPORTER_OTLP_LOGS_COMPRESSION: &str = "OTEL_EXPORTER_OTLP_LOGS_COMPRESSION";

/// Identifies one of the three OTLP signal types.
#[derive(Debug, Clone, Copy)]
pub enum SignalKind {
    Traces,
    Metrics,
    Logs,
}

/// Failure to parse OTLP exporter configuration (e.g. from env vars).
#[derive(Debug)]
pub struct OtelExporterConfigError {
    message: String,
}

impl OtelExporterConfigError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
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

/// Abstraction over the header/metadata that works for http/grpc transport
///
/// Implemented for [`rama_http::HeaderMap`] (HTTP exporter)
/// and [`crate::metadata::MetadataMap`] (gRPC exporter).
pub trait HeaderBag: Clone + Default + fmt::Debug + Send + Sync + 'static {
    /// Merge `other` into `self`, with `other` entries winning on conflict.
    fn merge(&mut self, other: Self);

    /// Parse an OTEL_EXPORTER_OTLP_*_HEADERS env var value into a header bag.
    /// `var` is the env var name.
    fn from_env(raw: &str, var: &'static str) -> Result<Self, OtelExporterConfigError>;
}

/// How `OtelExporter` actually sends a protobuf-encoded OTLP request for a
/// given signal. Implemented for `OtelExporter<S, HeaderMap>` (HTTP) and
/// `OtelExporter<S, MetadataMap>` (gRPC).
pub trait OtlpTransport {
    fn send_proto<Req, Resp>(
        &self,
        signal: SignalKind,
        request: Req,
    ) -> impl Future<Output = Result<Resp, OTelSdkError>> + Send
    where
        Req: Message + Send + 'static,
        Resp: Message + Default + Send + 'static;
}

#[derive(Debug, Clone, Default)]
pub(crate) struct SignalSettings<H> {
    pub(crate) endpoint: Option<Uri>,
    pub(crate) timeout: Option<Duration>,
    pub(crate) compression: Option<CompressionEncoding>,
    pub(crate) metadata: H,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct EnvSettings<H> {
    pub(crate) base: SignalSettings<H>,
    pub(crate) traces: SignalSettings<H>,
    pub(crate) metrics: SignalSettings<H>,
    pub(crate) logs: SignalSettings<H>,
}

pub(crate) struct ResolvedConfig<H> {
    pub(crate) endpoint: Uri,
    pub(crate) timeout: Option<Duration>,
    pub(crate) compression: Option<CompressionEncoding>,
    pub(crate) metadata: H,
}

/// http or grpc OTLP exporter
///
/// Create via [`OtelExporter::new_http`] / [`OtelExporter::from_env_http`] for HTTP exporters,
/// or [`OtelExporter::new_grpc`] / [`OtelExporter::from_env_grpc`] for gRPC.
#[must_use]
#[derive(Debug, Clone)]
pub struct OtelExporter<S, H> {
    pub(crate) service: S,
    pub(crate) endpoint: Option<Uri>,
    pub(crate) timeout: Option<Duration>,
    pub(crate) compression: Option<CompressionEncoding>,
    pub(crate) metadata: H,
    pub(crate) traces: SignalSettings<H>,
    pub(crate) metrics: SignalSettings<H>,
    pub(crate) logs: SignalSettings<H>,
    pub(crate) env: EnvSettings<H>,
    pub(crate) temporality: Temporality,
    pub(crate) resource: Arc<arc_swap::ArcSwap<transform::ResourceAttributesWithSchema>>,
    pub(crate) shutdown_traces: Arc<AtomicBool>,
    pub(crate) shutdown_metrics: Arc<AtomicBool>,
    pub(crate) shutdown_logs: Arc<AtomicBool>,
    pub(crate) runtime: Option<tokio::runtime::Handle>,
}

// Most OtelExporter logic is shared between http/grpc
// For transport specific logic see grpc.rs and http.rs

impl<S, H: HeaderBag> OtelExporter<S, H> {
    pub(crate) fn with_defaults(service: S) -> Self {
        Self {
            service,
            endpoint: None,
            timeout: None,
            compression: None,
            metadata: H::default(),
            traces: SignalSettings::default(),
            metrics: SignalSettings::default(),
            logs: SignalSettings::default(),
            env: EnvSettings::default(),
            temporality: Temporality::Cumulative,
            resource: Arc::new(arc_swap::ArcSwap::from_pointee(
                transform::ResourceAttributesWithSchema::default(),
            )),
            shutdown_traces: Arc::new(AtomicBool::new(false)),
            shutdown_metrics: Arc::new(AtomicBool::new(false)),
            shutdown_logs: Arc::new(AtomicBool::new(false)),
            runtime: tokio::runtime::Handle::try_current().ok(),
        }
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
        /// Override the trace-specific OTLP endpoint.
        pub fn traces_endpoint(mut self, endpoint: Option<Uri>) -> Self {
            self.traces.endpoint = endpoint;
            self
        }
    );

    generate_set_and_with!(
        /// Override the trace-specific OTLP timeout.
        pub fn traces_timeout(mut self, timeout: Option<Duration>) -> Self {
            self.traces.timeout = timeout;
            self
        }
    );

    generate_set_and_with!(
        /// Override the trace-specific OTLP compression.
        pub fn traces_compression(mut self, compression: Option<CompressionEncoding>) -> Self {
            self.traces.compression = compression;
            self
        }
    );

    generate_set_and_with!(
        /// Override the metrics-specific OTLP endpoint.
        pub fn metrics_endpoint(mut self, endpoint: Option<Uri>) -> Self {
            self.metrics.endpoint = endpoint;
            self
        }
    );

    generate_set_and_with!(
        /// Override the metrics-specific OTLP timeout.
        pub fn metrics_timeout(mut self, timeout: Option<Duration>) -> Self {
            self.metrics.timeout = timeout;
            self
        }
    );

    generate_set_and_with!(
        /// Override the metrics-specific OTLP compression.
        pub fn metrics_compression(mut self, compression: Option<CompressionEncoding>) -> Self {
            self.metrics.compression = compression;
            self
        }
    );

    generate_set_and_with!(
        /// Override the logs-specific OTLP endpoint.
        pub fn logs_endpoint(mut self, endpoint: Option<Uri>) -> Self {
            self.logs.endpoint = endpoint;
            self
        }
    );

    generate_set_and_with!(
        /// Override the logs-specific OTLP timeout.
        pub fn logs_timeout(mut self, timeout: Option<Duration>) -> Self {
            self.logs.timeout = timeout;
            self
        }
    );

    generate_set_and_with!(
        /// Override the logs-specific OTLP compression.
        pub fn logs_compression(mut self, compression: Option<CompressionEncoding>) -> Self {
            self.logs.compression = compression;
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
        /// Constructors capture `Handle::try_current()` automatically. Use this
        /// to pin the exporter to a specific runtime, or pass `None` to require
        /// the caller to provide a tokio context for every export.
        pub fn runtime(mut self, runtime: Option<tokio::runtime::Handle>) -> Self {
            self.runtime = runtime;
            self
        }
    );

    pub(crate) fn apply_env(&mut self) -> Result<(), OtelExporterConfigError> {
        apply_env_signal(
            &mut self.env.base,
            OTEL_EXPORTER_OTLP_ENDPOINT,
            OTEL_EXPORTER_OTLP_TIMEOUT,
            OTEL_EXPORTER_OTLP_HEADERS,
            OTEL_EXPORTER_OTLP_COMPRESSION,
        )?;
        apply_env_signal(
            &mut self.env.traces,
            OTEL_EXPORTER_OTLP_TRACES_ENDPOINT,
            OTEL_EXPORTER_OTLP_TRACES_TIMEOUT,
            OTEL_EXPORTER_OTLP_TRACES_HEADERS,
            OTEL_EXPORTER_OTLP_TRACES_COMPRESSION,
        )?;
        apply_env_signal(
            &mut self.env.metrics,
            OTEL_EXPORTER_OTLP_METRICS_ENDPOINT,
            OTEL_EXPORTER_OTLP_METRICS_TIMEOUT,
            OTEL_EXPORTER_OTLP_METRICS_HEADERS,
            OTEL_EXPORTER_OTLP_METRICS_COMPRESSION,
        )?;
        apply_env_signal(
            &mut self.env.logs,
            OTEL_EXPORTER_OTLP_LOGS_ENDPOINT,
            OTEL_EXPORTER_OTLP_LOGS_TIMEOUT,
            OTEL_EXPORTER_OTLP_LOGS_HEADERS,
            OTEL_EXPORTER_OTLP_LOGS_COMPRESSION,
        )?;
        Ok(())
    }

    pub(crate) fn shutdown_flag(&self, signal: SignalKind) -> &Arc<AtomicBool> {
        match signal {
            SignalKind::Traces => &self.shutdown_traces,
            SignalKind::Metrics => &self.shutdown_metrics,
            SignalKind::Logs => &self.shutdown_logs,
        }
    }

    pub(crate) fn shutdown_signal(&self, signal: SignalKind) -> OTelSdkResult {
        if self.shutdown_flag(signal).swap(true, Ordering::AcqRel) {
            Err(OTelSdkError::AlreadyShutdown)
        } else {
            Ok(())
        }
    }

    pub(crate) fn force_flush_signal(&self, signal: SignalKind) -> OTelSdkResult {
        if self.shutdown_flag(signal).load(Ordering::Acquire) {
            Err(OTelSdkError::AlreadyShutdown)
        } else {
            Ok(())
        }
    }

    pub(crate) fn store_resource(&self, resource: &sdk::Resource) {
        self.resource.store(Arc::new(resource.into()));
    }

    pub(crate) fn resolve_config(
        &self,
        signal: SignalKind,
        default_endpoint: &'static str,
        append_signal_path: impl FnOnce(Uri) -> Result<Uri, OtelExporterConfigError>,
    ) -> Result<ResolvedConfig<H>, OtelExporterConfigError> {
        let (signal_settings, env_signal) = match signal {
            SignalKind::Traces => (&self.traces, &self.env.traces),
            SignalKind::Metrics => (&self.metrics, &self.env.metrics),
            SignalKind::Logs => (&self.logs, &self.env.logs),
        };

        let signal_endpoint = signal_settings
            .endpoint
            .clone()
            .or_else(|| env_signal.endpoint.clone());
        let endpoint = match signal_endpoint {
            Some(endpoint) => endpoint,
            None => append_signal_path(
                self.endpoint
                    .clone()
                    .or_else(|| self.env.base.endpoint.clone())
                    .unwrap_or_else(|| Uri::from_static(default_endpoint)),
            )?,
        };

        let timeout = signal_settings
            .timeout
            .or(self.timeout)
            .or(env_signal.timeout)
            .or(self.env.base.timeout);
        let compression = signal_settings
            .compression
            .or(self.compression)
            .or(env_signal.compression)
            .or(self.env.base.compression);

        let mut metadata = self.env.base.metadata.clone();
        metadata.merge(env_signal.metadata.clone());
        metadata.merge(self.metadata.clone());
        metadata.merge(signal_settings.metadata.clone());

        Ok(ResolvedConfig {
            endpoint,
            timeout,
            compression,
            metadata,
        })
    }

    pub(crate) async fn run_on_runtime<F, T>(&self, work: F) -> Result<T, OTelSdkError>
    where
        F: Future<Output = Result<T, OTelSdkError>> + Send + 'static,
        T: Send + 'static,
    {
        match self.runtime.as_ref() {
            Some(handle) => handle
                .spawn(work)
                .await
                .map_err(|err| OTelSdkError::InternalFailure(err.to_string()))?,
            None => work.await,
        }
    }
}

impl<S, H> SpanExporter for OtelExporter<S, H>
where
    H: HeaderBag,
    S: fmt::Debug + Send + Sync + 'static,
    Self: OtlpTransport + Send + Sync,
{
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        let request_body = {
            let resource = self.resource.load();
            transform::span_batch_to_request(&batch, &resource)
        };
        let response: ExportTraceServiceResponse =
            self.send_proto(SignalKind::Traces, request_body).await?;

        otel_debug!(name: "RamaOtel.Traces.ExportSucceeded");

        if let Some(partial) = response
            .partial_success
            .filter(|p| p.rejected_spans > 0 || !p.error_message.is_empty())
        {
            otel_warn!(
                name: "RamaOtel.Traces.PartialSuccess",
                rejected_spans = partial.rejected_spans,
                error_message = partial.error_message.as_str(),
            );
        }

        Ok(())
    }

    fn shutdown_with_timeout(&mut self, _timeout: Duration) -> OTelSdkResult {
        self.shutdown_signal(SignalKind::Traces)
    }

    fn force_flush(&mut self) -> OTelSdkResult {
        self.force_flush_signal(SignalKind::Traces)
    }

    fn set_resource(&mut self, resource: &sdk::Resource) {
        self.store_resource(resource);
    }
}

impl<S, H> PushMetricExporter for OtelExporter<S, H>
where
    H: HeaderBag,
    S: fmt::Debug + Send + Sync + 'static,
    Self: OtlpTransport + Send + Sync,
{
    async fn export(&self, metrics: &ResourceMetrics) -> OTelSdkResult {
        let request_body = transform::resource_metrics_to_request(metrics);
        let response: ExportMetricsServiceResponse =
            self.send_proto(SignalKind::Metrics, request_body).await?;

        otel_debug!(name: "RamaOtel.Metrics.ExportSucceeded");

        if let Some(partial) = response
            .partial_success
            .filter(|p| p.rejected_data_points > 0 || !p.error_message.is_empty())
        {
            otel_warn!(
                name: "RamaOtel.Metrics.PartialSuccess",
                rejected_data_points = partial.rejected_data_points,
                error_message = partial.error_message.as_str(),
            );
        }

        Ok(())
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.force_flush_signal(SignalKind::Metrics)
    }

    fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
        self.shutdown_signal(SignalKind::Metrics)
    }

    fn temporality(&self) -> Temporality {
        self.temporality
    }
}

impl<S, H> LogExporter for OtelExporter<S, H>
where
    H: HeaderBag,
    S: fmt::Debug + Send + Sync + 'static,
    Self: OtlpTransport + Send + Sync,
{
    async fn export(&self, batch: LogBatch<'_>) -> OTelSdkResult {
        let request_body = {
            let resource = self.resource.load();
            transform::log_batch_to_request(&batch, &resource)
        };
        let response: ExportLogsServiceResponse =
            self.send_proto(SignalKind::Logs, request_body).await?;

        otel_debug!(name: "RamaOtel.Logs.ExportSucceeded");

        if let Some(partial) = response
            .partial_success
            .filter(|p| p.rejected_log_records > 0 || !p.error_message.is_empty())
        {
            otel_warn!(
                name: "RamaOtel.Logs.PartialSuccess",
                rejected_log_records = partial.rejected_log_records,
                error_message = partial.error_message.as_str(),
            );
        }

        Ok(())
    }

    fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
        self.shutdown_signal(SignalKind::Logs)
    }

    fn set_resource(&mut self, resource: &sdk::Resource) {
        self.store_resource(resource);
    }
}

fn apply_env_signal<H: HeaderBag>(
    settings: &mut SignalSettings<H>,
    endpoint_var: &'static str,
    timeout_var: &'static str,
    headers_var: &'static str,
    compression_var: &'static str,
) -> Result<(), OtelExporterConfigError> {
    if let Some(endpoint) = env_endpoint(endpoint_var)? {
        settings.endpoint = Some(endpoint);
    }
    if let Some(timeout) = env_timeout(timeout_var)? {
        settings.timeout = Some(timeout);
    }
    if let Some(raw) = read_env_var(headers_var)? {
        settings.metadata = H::from_env(&raw, headers_var)?;
    }
    if let EnvCompressionSetting::Value(compression) = env_compression(compression_var)? {
        settings.compression = compression;
    }
    Ok(())
}

fn read_env_var(var: &'static str) -> Result<Option<String>, OtelExporterConfigError> {
    match std::env::var(var) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(OtelExporterConfigError::new(format!(
            "failed to read {var}: {err}"
        ))),
    }
}

fn env_endpoint(var: &'static str) -> Result<Option<Uri>, OtelExporterConfigError> {
    let Some(value) = read_env_var(var)? else {
        return Ok(None);
    };

    let endpoint = value
        .parse::<Uri>()
        .map_err(|_e| OtelExporterConfigError::new(format!("invalid {var} value: {value}")))?;

    Ok(Some(endpoint))
}

fn env_timeout(var: &'static str) -> Result<Option<Duration>, OtelExporterConfigError> {
    let Some(value) = read_env_var(var)? else {
        return Ok(None);
    };

    let timeout_ms = value
        .parse::<u64>()
        .map_err(|_e| OtelExporterConfigError::new(format!("invalid {var} value: {value}")))?;

    Ok(Some(Duration::from_millis(timeout_ms)))
}

pub(crate) enum EnvCompressionSetting {
    Unset,
    Value(Option<CompressionEncoding>),
}

fn env_compression(var: &'static str) -> Result<EnvCompressionSetting, OtelExporterConfigError> {
    let Some(value) = read_env_var(var)? else {
        return Ok(EnvCompressionSetting::Unset);
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

pub(crate) fn parse_header_string(value: &str) -> impl Iterator<Item = (String, String)> + '_ {
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

    #[test]
    fn parse_header_string_decodes_percent_encoded_values() {
        let headers = parse_header_string("authorization=Bearer%20abc%2F123").collect::<Vec<_>>();
        assert_eq!(
            headers,
            vec![("authorization".to_owned(), "Bearer abc/123".to_owned())]
        );
    }
}
