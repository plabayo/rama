use super::{
    HeaderBag, OtelExporter, OtelExporterConfigError, OtlpTransport, SignalKind,
    parse_header_string,
};
use crate::{
    Request,
    client::{Grpc, GrpcService},
    metadata::{AsciiMetadataKey, BinaryMetadataKey, BinaryMetadataValue, MetadataMap},
    protobuf::ProstCodec,
};
use prost::Message;
use rama_core::{error::BoxError, telemetry::opentelemetry::sdk::error::OTelSdkError};
use rama_http::{Body, StreamingBody, uri::PathAndQuery};
use rama_utils::macros::generate_set_and_with;
use std::{fmt, str::FromStr, sync::atomic::Ordering};

pub(super) const DEFAULT_OTLP_GRPC_ENDPOINT: &str = "http://localhost:4317";
const TRACE_EXPORT_PATH: &str = "/opentelemetry.proto.collector.trace.v1.TraceService/Export";
const METRICS_EXPORT_PATH: &str = "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export";
const LOGS_EXPORT_PATH: &str = "/opentelemetry.proto.collector.logs.v1.LogsService/Export";

impl HeaderBag for MetadataMap {
    fn merge(&mut self, other: Self) {
        Self::merge(self, other);
    }

    fn from_env(raw: &str, var: &'static str) -> Result<Self, OtelExporterConfigError> {
        let mut metadata = Self::new();
        for (key, value) in parse_header_string(raw) {
            if key.ends_with("-bin") {
                let key = BinaryMetadataKey::from_str(&key).map_err(|err| {
                    OtelExporterConfigError::new(format!(
                        "{var} contains invalid metadata key {key:?}: {err}"
                    ))
                })?;
                let parsed = BinaryMetadataValue::try_from(value.into_bytes()).map_err(|err| {
                    OtelExporterConfigError::new(format!(
                        "{var} contains invalid metadata value for {key}: {err}"
                    ))
                })?;
                metadata.insert_bin(key, parsed);
            } else {
                let key = AsciiMetadataKey::from_str(&key).map_err(|err| {
                    OtelExporterConfigError::new(format!(
                        "{var} contains invalid metadata key {key:?}: {err}"
                    ))
                })?;
                let parsed = value.parse().map_err(|err| {
                    OtelExporterConfigError::new(format!(
                        "{var} contains invalid metadata value for {key}: {err}"
                    ))
                })?;
                metadata.insert(key, parsed);
            }
        }
        Ok(metadata)
    }
}

impl<S> OtelExporter<S, MetadataMap> {
    /// Create a new gRPC OTLP exporter wrapping `service`.
    ///
    /// Defaults to `http://localhost:4317` with no overrides. Use the various
    /// `with_*` setters to customise, or [`OtelExporter::from_env_grpc`] to
    /// seed values from the standard `OTEL_EXPORTER_OTLP_*` environment
    /// variables.
    pub fn new_grpc(service: S) -> Self {
        Self::with_defaults(service)
    }

    /// Create a new gRPC OTLP exporter wrapping `service` and seed its
    /// configuration from `OTEL_EXPORTER_OTLP_*` environment variables.
    pub fn from_env_grpc(service: S) -> Result<Self, OtelExporterConfigError> {
        let mut exporter = Self::new_grpc(service);
        exporter.apply_env()?;
        Ok(exporter)
    }

    generate_set_and_with!(
        /// Override the base OTLP metadata.
        pub fn metadata(mut self, metadata: MetadataMap) -> Self {
            self.metadata = metadata;
            self
        }
    );

    generate_set_and_with!(
        /// Override the trace-specific OTLP metadata.
        pub fn traces_metadata(mut self, metadata: MetadataMap) -> Self {
            self.traces.metadata = metadata;
            self
        }
    );

    generate_set_and_with!(
        /// Override the metrics-specific OTLP metadata.
        pub fn metrics_metadata(mut self, metadata: MetadataMap) -> Self {
            self.metrics.metadata = metadata;
            self
        }
    );

    generate_set_and_with!(
        /// Override the logs-specific OTLP metadata.
        pub fn logs_metadata(mut self, metadata: MetadataMap) -> Self {
            self.logs.metadata = metadata;
            self
        }
    );
}

impl<S> OtlpTransport for OtelExporter<S, MetadataMap>
where
    S: fmt::Debug + Clone + Send + Sync + 'static + GrpcService<Body>,
    S::ResponseBody: StreamingBody<Error: Into<BoxError>> + Send + Sync + 'static,
{
    async fn send_proto<Req, Resp>(
        &self,
        signal: SignalKind,
        request_body: Req,
    ) -> Result<Resp, OTelSdkError>
    where
        Req: Message + Send + 'static,
        Resp: Message + Default + Send + 'static,
    {
        if self.shutdown_flag(signal).load(Ordering::Acquire) {
            return Err(OTelSdkError::AlreadyShutdown);
        }

        let path = match signal {
            SignalKind::Traces => TRACE_EXPORT_PATH,
            SignalKind::Metrics => METRICS_EXPORT_PATH,
            SignalKind::Logs => LOGS_EXPORT_PATH,
        };

        // gRPC endpoints are host:port URIs without a per-signal path suffix.
        let config = self
            .resolve_config(signal, DEFAULT_OTLP_GRPC_ENDPOINT, Ok)
            .map_err(|err| OTelSdkError::InternalFailure(err.to_string()))?;

        let service = self.service.clone();
        let endpoint = config.endpoint;
        let compression = config.compression;
        let metadata = config.metadata;
        let timeout = config.timeout;

        let work = async move {
            let mut grpc = Grpc::new(service, endpoint);
            if let Some(compression) = compression {
                grpc = grpc
                    .with_send_compressed(compression)
                    .with_accept_compressed(compression);
            }

            let mut request = Request::new(request_body);
            *request.metadata_mut() = metadata;
            if let Some(timeout) = timeout {
                request
                    .try_set_timeout(timeout)
                    .map_err(|err| OTelSdkError::InternalFailure(err.to_string()))?;
            }

            let rpc = grpc.unary(
                request,
                PathAndQuery::from_static(path),
                ProstCodec::<Req, Resp>::new(),
            );

            let response = match timeout {
                Some(timeout) => match tokio::time::timeout(timeout, rpc).await {
                    Ok(result) => result,
                    Err(_) => return Err(OTelSdkError::Timeout(timeout)),
                },
                None => rpc.await,
            }
            .map_err(|status| OTelSdkError::InternalFailure(format!("export error: {status:?}")))?;
            Ok(response.into_inner())
        };
        self.run_on_runtime(work).await
    }
}
