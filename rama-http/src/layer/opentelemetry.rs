//! Http OpenTelemetry [`Layer`] Support for Rama.
//!
//! [`Layer`]: rama_core::Layer

use crate::{
    headers::{HeaderMapExt, UserAgent},
    IntoResponse, Request, Response,
};
use rama_core::telemetry::opentelemetry::{
    global,
    metrics::{Histogram, Meter, UpDownCounter},
    semantic_conventions, AttributesFactory, KeyValue,
};
use rama_core::{Context, Layer, Service};
use rama_net::http::RequestContext;
use rama_utils::macros::define_inner_service_accessors;
use std::{borrow::Cow, fmt, sync::Arc, time::SystemTime};

// Follows the experimental semantic conventions for HTTP metrics:
// https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/metrics/semantic_conventions/http-metrics.md

use semantic_conventions::attribute::{
    HTTP_REQUEST_METHOD, HTTP_RESPONSE_STATUS_CODE, NETWORK_PROTOCOL_VERSION, SERVER_PORT,
    URL_SCHEME, USER_AGENT_ORIGINAL,
};

const HTTP_SERVER_DURATION: &str = "http.server.duration";
const HTTP_SERVER_ACTIVE_REQUESTS: &str = "http.server.active_requests";

/// Records http server metrics
///
/// See the [spec] for details.
///
/// [spec]: https://github.com/open-telemetry/semantic-conventions/blob/v1.21.0/docs/http/http-metrics.md#http-server
#[derive(Clone, Debug)]
struct Metrics {
    http_server_duration: Histogram<f64>,
    http_server_active_requests: UpDownCounter<i64>,
}

impl Metrics {
    /// Create a new [`RequestMetrics`]
    fn new(meter: Meter) -> Self {
        let http_server_duration = meter
            .f64_histogram(HTTP_SERVER_DURATION)
            .with_description("Measures the duration of inbound HTTP requests.")
            .with_unit("s")
            .init();

        let http_server_active_requests = meter
            .i64_up_down_counter(HTTP_SERVER_ACTIVE_REQUESTS)
            .with_description(
                "Measures the number of concurrent HTTP requests that are currently in-flight.",
            )
            .init();

        Metrics {
            http_server_active_requests,
            http_server_duration,
        }
    }
}

/// A layer that records http server metrics using OpenTelemetry.
pub struct RequestMetricsLayer<F = ()> {
    metrics: Arc<Metrics>,
    attributes_factory: F,
}

impl<F: fmt::Debug> fmt::Debug for RequestMetricsLayer<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RequestMetricsLayer")
            .field("metrics", &self.metrics)
            .field("attributes_factory", &self.attributes_factory)
            .finish()
    }
}

impl<F: Clone> Clone for RequestMetricsLayer<F> {
    fn clone(&self) -> Self {
        RequestMetricsLayer {
            metrics: self.metrics.clone(),
            attributes_factory: self.attributes_factory.clone(),
        }
    }
}

impl RequestMetricsLayer<()> {
    /// Create a new [`RequestMetricsLayer`] using the global [`Meter`] provider,
    /// with the default name and version.
    pub fn new() -> Self {
        Self::custom(rama_utils::info::NAME, rama_utils::info::VERSION)
    }

    /// Create a new [`RequestMetricsLayer`] using the global [`Meter`] provider,
    /// with a custom name and version.
    pub fn custom(
        name: impl Into<Cow<'static, str>>,
        version: impl Into<Cow<'static, str>>,
    ) -> Self {
        let meter = get_versioned_meter(name, version);
        let metrics = Metrics::new(meter);
        Self {
            metrics: Arc::new(metrics),
            attributes_factory: (),
        }
    }

    /// Attach an [`AttributesFactory`] to this [`RequestMetricsLayer`], allowing
    /// you to inject custom attributes.
    pub fn with_attributes<F>(self, attributes: F) -> RequestMetricsLayer<F> {
        RequestMetricsLayer {
            metrics: self.metrics,
            attributes_factory: attributes,
        }
    }
}

impl Default for RequestMetricsLayer {
    fn default() -> Self {
        Self::new()
    }
}

/// construct meters for this crate
fn get_versioned_meter(
    name: impl Into<Cow<'static, str>>,
    version: impl Into<Cow<'static, str>>,
) -> Meter {
    global::meter_with_version(
        name,
        Some(version),
        Some(semantic_conventions::SCHEMA_URL),
        None,
    )
}

impl<S, F: Clone> Layer<S> for RequestMetricsLayer<F> {
    type Service = RequestMetricsService<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestMetricsService {
            inner,
            metrics: self.metrics.clone(),
            attributes_factory: self.attributes_factory.clone(),
        }
    }
}

/// A [`Service`] that records [http] server metrics using OpenTelemetry.
pub struct RequestMetricsService<S, F = ()> {
    inner: S,
    metrics: Arc<Metrics>,
    attributes_factory: F,
}

impl<S> RequestMetricsService<S, ()> {
    /// Create a new [`RequestMetricsService`].
    pub fn new(inner: S) -> Self {
        RequestMetricsLayer::new().layer(inner)
    }

    define_inner_service_accessors!();
}

impl<S: fmt::Debug, F: fmt::Debug> fmt::Debug for RequestMetricsService<S, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestMetricsService")
            .field("inner", &self.inner)
            .field("metrics", &self.metrics)
            .field("attributes_factory", &self.attributes_factory)
            .finish()
    }
}

impl<S: Clone, F: Clone> Clone for RequestMetricsService<S, F> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            metrics: self.metrics.clone(),
            attributes_factory: self.attributes_factory.clone(),
        }
    }
}

impl<S, F> RequestMetricsService<S, F> {
    fn compute_attributes<Body, State>(
        &self,
        ctx: &mut Context<State>,
        req: &Request<Body>,
    ) -> Vec<KeyValue>
    where
        F: AttributesFactory<State>,
    {
        let mut attributes = self.attributes_factory.attributes(5, ctx);

        // server info
        let request_ctx: Option<&mut RequestContext> = ctx
            .get_or_try_insert_with_ctx(|ctx| (ctx, req).try_into())
            .ok();
        if let Some(authority) = request_ctx.as_ref().map(|rc| &rc.authority) {
            attributes.push(KeyValue::new(SERVER_PORT, authority.port() as i64));
        }

        // Request Info
        if let Some(protocol) = request_ctx.as_ref().map(|rc| &rc.protocol) {
            attributes.push(KeyValue::new(URL_SCHEME, protocol.to_string()));
        }

        // Common attrs (Request Info)
        // <https://github.com/open-telemetry/semantic-conventions/blob/v1.21.0/docs/http/http-spans.md#common-attributes>

        attributes.push(KeyValue::new(HTTP_REQUEST_METHOD, req.method().to_string()));
        if let Some(http_version) = request_ctx.as_ref().and_then(|rc| match rc.http_version {
            http::Version::HTTP_09 => Some("0.9"),
            http::Version::HTTP_10 => Some("1.0"),
            http::Version::HTTP_11 => Some("1.1"),
            http::Version::HTTP_2 => Some("2"),
            http::Version::HTTP_3 => Some("3"),
            _ => None,
        }) {
            attributes.push(KeyValue::new(NETWORK_PROTOCOL_VERSION, http_version));
        }

        if let Some(ua) = req.headers().typed_get::<UserAgent>() {
            attributes.push(KeyValue::new(USER_AGENT_ORIGINAL, ua.to_string()));
        }

        attributes
    }
}

impl<S, State, Body> Service<State, Request<Body>> for RequestMetricsService<S>
where
    S: Service<State, Request<Body>, Response: IntoResponse>,
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
        let mut attributes: Vec<KeyValue> = self.compute_attributes(&mut ctx, &req);

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
