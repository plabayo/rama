use super::{
    HeaderBag, OtelExporter, OtelExporterConfigError, OtlpTransport, SignalKind,
    parse_header_string,
};
use crate::codec::{
    CompressionEncoding,
    compression::{CompressionSettings, compress},
};
use prost::Message;
use rama_core::{
    Service, bytes::BytesMut, error::BoxError, telemetry::opentelemetry::sdk::error::OTelSdkError,
};
use rama_http::{
    Body, HeaderMap, HeaderName, HeaderValue, Method, Request, Response,
    body::util::BodyExt as _,
    header::CONTENT_TYPE,
    uri::{PathAndQuery, Uri},
};
use rama_utils::macros::generate_set_and_with;
use std::{fmt, str::FromStr, sync::atomic::Ordering};

pub(super) const DEFAULT_OTLP_HTTP_ENDPOINT: &str = "http://localhost:4318";
const OTLP_HTTP_TRACE_PATH: &str = "/v1/traces";
const OTLP_HTTP_METRICS_PATH: &str = "/v1/metrics";
const OTLP_HTTP_LOGS_PATH: &str = "/v1/logs";
const PROTOBUF_CONTENT_TYPE: &str = "application/x-protobuf";
const CONTENT_ENCODING: &str = "content-encoding";

impl HeaderBag for HeaderMap {
    fn merge(&mut self, other: Self) {
        for (key, value) in other {
            if let Some(key) = key {
                self.insert(key, value);
            }
        }
    }

    fn from_env(raw: &str, var: &'static str) -> Result<Self, OtelExporterConfigError> {
        let mut headers = Self::new();
        for (key, value) in parse_header_string(raw) {
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
        Ok(headers)
    }
}

impl<S> OtelExporter<S, HeaderMap> {
    /// Create a new HTTP OTLP exporter wrapping `service`.
    ///
    /// Defaults to `http://localhost:4318` with no overrides. Use the various
    /// `with_*` setters to customise, or [`OtelExporter::from_env_http`] to
    /// seed values from the standard `OTEL_EXPORTER_OTLP_*` environment
    /// variables.
    pub fn new_http(service: S) -> Self {
        Self::with_defaults(service)
    }

    /// Create a new HTTP OTLP exporter wrapping `service` and seed its
    /// configuration from `OTEL_EXPORTER_OTLP_*` environment variables.
    pub fn from_env_http(service: S) -> Result<Self, OtelExporterConfigError> {
        let mut exporter = Self::new_http(service);
        exporter.apply_env()?;
        Ok(exporter)
    }

    generate_set_and_with!(
        /// Override the base OTLP HTTP headers.
        pub fn headers(mut self, headers: HeaderMap) -> Self {
            self.metadata = headers;
            self
        }
    );

    generate_set_and_with!(
        /// Override the trace-specific OTLP HTTP headers.
        pub fn traces_headers(mut self, headers: HeaderMap) -> Self {
            self.traces.metadata = headers;
            self
        }
    );

    generate_set_and_with!(
        /// Override the metrics-specific OTLP HTTP headers.
        pub fn metrics_headers(mut self, headers: HeaderMap) -> Self {
            self.metrics.metadata = headers;
            self
        }
    );

    generate_set_and_with!(
        /// Override the logs-specific OTLP HTTP headers.
        pub fn logs_headers(mut self, headers: HeaderMap) -> Self {
            self.logs.metadata = headers;
            self
        }
    );
}

impl<S> OtlpTransport for OtelExporter<S, HeaderMap>
where
    S: fmt::Debug
        + Clone
        + Send
        + Sync
        + 'static
        + Service<Request<Body>, Output = Response<Body>, Error: Into<BoxError>>,
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
            SignalKind::Traces => OTLP_HTTP_TRACE_PATH,
            SignalKind::Metrics => OTLP_HTTP_METRICS_PATH,
            SignalKind::Logs => OTLP_HTTP_LOGS_PATH,
        };

        let config = self
            .resolve_config(signal, DEFAULT_OTLP_HTTP_ENDPOINT, |base| {
                append_signal_path(base, path)
            })
            .map_err(|err| OTelSdkError::InternalFailure(err.to_string()))?;

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
        merge_headers(request.headers_mut(), &config.metadata);

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
        self.run_on_runtime(work).await
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
