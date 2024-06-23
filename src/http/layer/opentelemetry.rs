//! Http OpenTelemetry [`Layer`] Support for Rama.
//!
//! [`Layer`]: crate::service::Layer

use crate::telemetry::opentelemetry::{
    global,
    metrics::{Histogram, Meter, Unit, UpDownCounter},
    semantic_conventions, KeyValue,
};
use crate::{
    http::{
        self, get_request_context,
        headers::{HeaderMapExt, UserAgent},
        IntoResponse, Request, Response,
    },
    net::stream::SocketInfo,
    service::{Context, Layer, Service},
};
use headers::ContentLength;
use std::{fmt, sync::Arc, time::SystemTime};

// Follows the experimental semantic conventions for HTTP metrics:
// https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/metrics/semantic_conventions/http-metrics.md

use semantic_conventions::trace::{
    CLIENT_ADDRESS, CLIENT_PORT, HTTP_REQUEST_BODY_SIZE, HTTP_REQUEST_METHOD,
    HTTP_RESPONSE_BODY_SIZE, HTTP_RESPONSE_STATUS_CODE, NETWORK_PROTOCOL_VERSION, SERVER_ADDRESS,
    SERVER_PORT, URL_PATH, URL_QUERY, URL_SCHEME, USER_AGENT_ORIGINAL,
};

const HTTP_SERVER_DURATION: &str = "http.server.duration";
const HTTP_SERVER_ACTIVE_REQUESTS: &str = "http.server.active_requests";

// TODO: do we also want to track actual calculated body size?
// this would mean we _need_ to buffer the body, which is not ideal
// Perhaps make it opt-in?
// NOTE: we could also make this opt-in via BytesRWTrackerHandle (rama::net::stream::BytesRWTrackerHandle)
// this would however not work properly (I think) with h2/h3...
// const HTTP_SERVER_REQUEST_SIZE: &str = "http.server.request.size";
// const HTTP_SERVER_RESPONSE_SIZE: &str = "http.server.response.size";

/// Records http server metrics
///
/// See the [spec] for details.
///
/// [spec]: https://github.com/open-telemetry/semantic-conventions/blob/v1.21.0/docs/http/http-metrics.md#http-server
#[derive(Clone, Debug)]
struct Metrics {
    http_server_duration: Histogram<f64>,
    http_server_active_requests: UpDownCounter<i64>,
    // http_server_request_size: Histogram<u64>,
    // http_server_response_size: Histogram<u64>,
}

impl Metrics {
    /// Create a new [`RequestMetrics`]
    fn new(meter: Meter) -> Self {
        let http_server_duration = meter
            .f64_histogram(HTTP_SERVER_DURATION)
            .with_description("Measures the duration of inbound HTTP requests.")
            .with_unit(Unit::new("s"))
            .init();

        let http_server_active_requests = meter
            .i64_up_down_counter(HTTP_SERVER_ACTIVE_REQUESTS)
            .with_description(
                "Measures the number of concurrent HTTP requests that are currently in-flight.",
            )
            .init();

        // let http_server_request_size = meter
        //     .u64_histogram(HTTP_SERVER_REQUEST_SIZE)
        //     .with_description("Measures the size of HTTP request messages (compressed).")
        //     .with_unit(Unit::new("By"))
        //     .init();

        // let http_server_response_size = meter
        //     .u64_histogram(HTTP_SERVER_RESPONSE_SIZE)
        //     .with_description("Measures the size of HTTP response messages (compressed).")
        //     .with_unit(Unit::new("By"))
        //     .init();

        Metrics {
            http_server_active_requests,
            http_server_duration,
            // http_server_request_size,
            // http_server_response_size,
        }
    }
}

#[derive(Debug, Clone)]
/// A layer that records http server metrics using OpenTelemetry.
pub struct RequestMetricsLayer {
    metrics: Arc<Metrics>,
}

impl RequestMetricsLayer {
    /// Create a new [`RequestMetricsLayer`] using the global [`Meter`] provider.
    pub fn new() -> Self {
        let meter = get_versioned_meter();
        let metrics = Metrics::new(meter);
        Self {
            metrics: Arc::new(metrics),
        }
    }
}

impl Default for RequestMetricsLayer {
    fn default() -> Self {
        Self::new()
    }
}

/// construct meters for this crate
fn get_versioned_meter() -> Meter {
    global::meter_with_version(
        crate::utils::info::NAME,
        Some(crate::utils::info::VERSION),
        Some(semantic_conventions::SCHEMA_URL),
        None,
    )
}

impl<S> Layer<S> for RequestMetricsLayer {
    type Service = RequestMetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestMetricsService {
            inner,
            metrics: self.metrics.clone(),
        }
    }
}

/// A [`Service`] that records [http] server metrics using OpenTelemetry.
pub struct RequestMetricsService<S> {
    inner: S,
    metrics: Arc<Metrics>,
}

impl<S> RequestMetricsService<S> {
    /// Create a new [`RequestMetricsService`].
    pub fn new(inner: S) -> Self {
        RequestMetricsLayer::new().layer(inner)
    }

    define_inner_service_accessors!();
}

impl<S: fmt::Debug> fmt::Debug for RequestMetricsService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestMetricsService")
            .field("inner", &self.inner)
            .field("metrics", &self.metrics)
            .finish()
    }
}

impl<S: Clone> Clone for RequestMetricsService<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            metrics: self.metrics.clone(),
        }
    }
}

impl<S, State, Body> Service<State, Request<Body>> for RequestMetricsService<S>
where
    S: Service<State, Request<Body>>,
    S::Response: IntoResponse,
    State: Send + Sync + 'static,
    Body: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let mut attributes: Vec<KeyValue> = compute_attributes(&mut ctx, &req);

        self.metrics.http_server_active_requests.add(1, &attributes);

        // used to compute the duration of the request
        let timer = SystemTime::now();

        let result = self.inner.serve(ctx, req).await;
        self.metrics
            .http_server_active_requests
            .add(-1, &attributes);

        match result {
            Ok(res) => {
                let res = res.into_response();

                attributes.push(KeyValue::new(
                    HTTP_RESPONSE_STATUS_CODE,
                    res.status().as_u16() as i64,
                ));

                if let Some(content_length) = res.headers().typed_get::<ContentLength>() {
                    attributes.push(KeyValue::new(
                        HTTP_RESPONSE_BODY_SIZE,
                        content_length.0 as i64,
                    ));
                }

                self.metrics.http_server_duration.record(
                    timer.elapsed().map(|t| t.as_secs_f64()).unwrap_or_default(),
                    &attributes,
                );

                Ok(res)
            }
            Err(err) => Err(err),
        }
    }
}

fn compute_attributes<State, Body>(ctx: &mut Context<State>, req: &Request<Body>) -> Vec<KeyValue> {
    let mut attributes = Vec::with_capacity(12);

    // client info
    if let Some(socket_info) = ctx.get::<SocketInfo>() {
        let peer_addr = socket_info.peer_addr();
        attributes.push(KeyValue::new(CLIENT_ADDRESS, peer_addr.ip().to_string()));
        attributes.push(KeyValue::new(CLIENT_PORT, peer_addr.port() as i64));
    }

    // server info
    let request_ctx = get_request_context!(*ctx, *req);
    if let Some(authority) = request_ctx.authority.as_ref() {
        attributes.push(KeyValue::new(SERVER_ADDRESS, authority.host().to_string()));
        attributes.push(KeyValue::new(SERVER_PORT, authority.port() as i64));
    }

    // Request Info
    let uri = req.uri();
    match uri.path() {
        "" | "/" => (),
        path => attributes.push(KeyValue::new(URL_PATH, path.to_owned())),
    }
    match uri.query() {
        Some("") | None => (),
        Some(query) => attributes.push(KeyValue::new(URL_QUERY, query.to_owned())),
    }
    attributes.push(KeyValue::new(URL_SCHEME, request_ctx.protocol.to_string()));

    // Common attrs (Request Info)
    // <https://github.com/open-telemetry/semantic-conventions/blob/v1.21.0/docs/http/http-spans.md#common-attributes>

    attributes.push(KeyValue::new(HTTP_REQUEST_METHOD, req.method().to_string()));
    if let Some(http_version) = match request_ctx.http_version {
        http::Version::HTTP_09 => Some("0.9"),
        http::Version::HTTP_10 => Some("1.0"),
        http::Version::HTTP_11 => Some("1.1"),
        http::Version::HTTP_2 => Some("2"),
        http::Version::HTTP_3 => Some("3"),
        _ => None,
    } {
        attributes.push(KeyValue::new(NETWORK_PROTOCOL_VERSION, http_version));
    }

    if let Some(ua) = req.headers().typed_get::<UserAgent>() {
        attributes.push(KeyValue::new(USER_AGENT_ORIGINAL, ua.to_string()));
    }

    if let Some(content_length) = req.headers().typed_get::<ContentLength>() {
        attributes.push(KeyValue::new(
            HTTP_REQUEST_BODY_SIZE,
            content_length.0 as i64,
        ));
    }

    attributes
}
