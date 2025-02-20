//! Http OpenTelemetry [`Layer`] Support for Rama.
//!
//! [`Layer`]: rama_core::Layer

use crate::{
    IntoResponse, Request, Response,
    headers::{HeaderMapExt, UserAgent},
};
use rama_core::telemetry::opentelemetry::{
    AttributesFactory, InstrumentationScope, KeyValue, MeterOptions, ServiceInfo, global,
    metrics::{Counter, Histogram, Meter},
    semantic_conventions::{
        self,
        resource::{SERVICE_NAME, SERVICE_VERSION},
    },
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

const HTTP_SERVER_DURATION: &str = "http.requests.duration";
const HTTP_SERVER_TOTAL_REQUESTS: &str = "http.requests.total";
const HTTP_SERVER_TOTAL_FAILURES: &str = "http.failures.total";
const HTTP_SERVER_TOTAL_RESPONSES: &str = "http.responses.total";

const HTTP_REQUEST_HOST: &str = "http.request.host";

/// Records http server metrics
///
/// See the [spec] for details.
///
/// [spec]: https://github.com/open-telemetry/semantic-conventions/blob/v1.21.0/docs/http/http-metrics.md#http-server
#[derive(Clone, Debug)]
struct Metrics {
    http_server_duration: Histogram<f64>,
    http_server_total_requests: Counter<u64>,
    http_server_total_responses: Counter<u64>,
    http_server_total_failures: Counter<u64>,
}

impl Metrics {
    /// Create a new [`RequestMetrics`]
    fn new(meter: Meter, prefix: Option<String>) -> Self {
        let http_server_duration = meter
            .f64_histogram(match &prefix {
                Some(prefix) => Cow::Owned(format!("{prefix}.{HTTP_SERVER_DURATION}")),
                None => Cow::Borrowed(HTTP_SERVER_DURATION),
            })
            .with_description("Measures the duration of inbound HTTP requests.")
            .with_unit("s")
            .build();

        let http_server_total_requests = meter
            .u64_counter(match &prefix {
                Some(prefix) => Cow::Owned(format!("{prefix}.{HTTP_SERVER_TOTAL_REQUESTS}")),
                None => Cow::Borrowed(HTTP_SERVER_TOTAL_REQUESTS),
            })
            .with_description("Measures the total number of HTTP requests have been seen.")
            .build();

        let http_server_total_responses = meter
            .u64_counter(match &prefix {
                Some(prefix) => Cow::Owned(format!("{prefix}.{HTTP_SERVER_TOTAL_RESPONSES}")),
                None => Cow::Borrowed(HTTP_SERVER_TOTAL_RESPONSES),
            })
            .with_description("Measures the total number of HTTP responses have been seen.")
            .build();

        let http_server_total_failures = meter
            .u64_counter(match &prefix {
                Some(prefix) => Cow::Owned(format!("{prefix}.{HTTP_SERVER_TOTAL_FAILURES}")),
                None => Cow::Borrowed(HTTP_SERVER_TOTAL_FAILURES),
            })
            .with_description(
                "Measures the total number of failed HTTP requests that have been seen.",
            )
            .build();

        Metrics {
            http_server_total_requests,
            http_server_total_responses,
            http_server_total_failures,
            http_server_duration,
        }
    }
}

/// A layer that records http server metrics using OpenTelemetry.
pub struct RequestMetricsLayer<F = ()> {
    metrics: Arc<Metrics>,
    base_attributes: Vec<KeyValue>,
    attributes_factory: F,
}

impl<F: fmt::Debug> fmt::Debug for RequestMetricsLayer<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RequestMetricsLayer")
            .field("metrics", &self.metrics)
            .field("base_attributes", &self.base_attributes)
            .field("attributes_factory", &self.attributes_factory)
            .finish()
    }
}

impl<F: Clone> Clone for RequestMetricsLayer<F> {
    fn clone(&self) -> Self {
        RequestMetricsLayer {
            metrics: self.metrics.clone(),
            base_attributes: self.base_attributes.clone(),
            attributes_factory: self.attributes_factory.clone(),
        }
    }
}

impl RequestMetricsLayer<()> {
    /// Create a new [`RequestMetricsLayer`] using the global [`Meter`] provider,
    /// with the default name and version.
    pub fn new() -> Self {
        Self::custom(MeterOptions::default())
    }

    /// Create a new [`RequestMetricsLayer`] using the global [`Meter`] provider,
    /// with a custom name and version.
    pub fn custom(opts: MeterOptions) -> Self {
        let service_info = opts.service.unwrap_or_else(|| ServiceInfo {
            name: rama_utils::info::NAME.to_owned(),
            version: rama_utils::info::VERSION.to_owned(),
        });

        let mut attributes = opts.attributes.unwrap_or_else(|| Vec::with_capacity(2));
        attributes.push(KeyValue::new(SERVICE_NAME, service_info.name.clone()));
        attributes.push(KeyValue::new(SERVICE_VERSION, service_info.version.clone()));

        let meter = get_versioned_meter();
        let metrics = Metrics::new(meter, opts.metric_prefix);

        Self {
            metrics: Arc::new(metrics),
            base_attributes: attributes,
            attributes_factory: (),
        }
    }

    /// Attach an [`AttributesFactory`] to this [`RequestMetricsLayer`], allowing
    /// you to inject custom attributes.
    pub fn with_attributes<F>(self, attributes: F) -> RequestMetricsLayer<F> {
        RequestMetricsLayer {
            metrics: self.metrics,
            base_attributes: self.base_attributes,
            attributes_factory: attributes,
        }
    }
}

impl Default for RequestMetricsLayer {
    fn default() -> Self {
        Self::new()
    }
}

fn get_versioned_meter() -> Meter {
    global::meter_with_scope(
        InstrumentationScope::builder(const_format::formatcp!(
            "{}-network-http",
            rama_utils::info::NAME
        ))
        .with_version(rama_utils::info::VERSION)
        .with_schema_url(semantic_conventions::SCHEMA_URL)
        .build(),
    )
}

impl<S, F: Clone> Layer<S> for RequestMetricsLayer<F> {
    type Service = RequestMetricsService<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestMetricsService {
            inner,
            metrics: self.metrics.clone(),
            base_attributes: self.base_attributes.clone(),
            attributes_factory: self.attributes_factory.clone(),
        }
    }
}

/// A [`Service`] that records [http] server metrics using OpenTelemetry.
pub struct RequestMetricsService<S, F = ()> {
    inner: S,
    metrics: Arc<Metrics>,
    base_attributes: Vec<KeyValue>,
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
            .field("base_attributes", &self.base_attributes)
            .field("attributes_factory", &self.attributes_factory)
            .finish()
    }
}

impl<S: Clone, F: Clone> Clone for RequestMetricsService<S, F> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            metrics: self.metrics.clone(),
            base_attributes: self.base_attributes.clone(),
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
        let mut attributes = self
            .attributes_factory
            .attributes(6 + self.base_attributes.len(), ctx);
        attributes.extend(self.base_attributes.iter().cloned());

        // server info
        let request_ctx: Option<&mut RequestContext> = ctx
            .get_or_try_insert_with_ctx(|ctx| (ctx, req).try_into())
            .ok();
        if let Some(authority) = request_ctx.as_ref().map(|rc| &rc.authority) {
            attributes.push(KeyValue::new(
                HTTP_REQUEST_HOST,
                authority.host().to_string(),
            ));
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

impl<S, F, State, Body> Service<State, Request<Body>> for RequestMetricsService<S, F>
where
    S: Service<State, Request<Body>, Response: IntoResponse>,
    F: AttributesFactory<State>,
    State: Clone + Send + Sync + 'static,
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

        self.metrics.http_server_total_requests.add(1, &attributes);

        // used to compute the duration of the request
        let timer = SystemTime::now();

        let result = self.inner.serve(ctx, req).await;

        match result {
            Ok(res) => {
                let res = res.into_response();

                attributes.push(KeyValue::new(
                    HTTP_RESPONSE_STATUS_CODE,
                    res.status().as_u16() as i64,
                ));

                self.metrics.http_server_total_responses.add(1, &attributes);
                self.metrics.http_server_duration.record(
                    timer.elapsed().map(|t| t.as_secs_f64()).unwrap_or_default(),
                    &attributes,
                );

                Ok(res)
            }
            Err(err) => {
                self.metrics.http_server_total_failures.add(1, &attributes);

                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_svc_compute_attributes_default() {
        let svc = RequestMetricsService::new(());
        let mut ctx = Context::default();
        let req = Request::builder()
            .uri("http://www.example.com")
            .body(())
            .unwrap();

        let attributes = svc.compute_attributes(&mut ctx, &req);
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == SERVICE_NAME)
        );
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == SERVICE_VERSION)
        );
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == HTTP_REQUEST_HOST)
        );
    }

    #[test]
    fn test_custom_svc_compute_attributes_default() {
        let svc = RequestMetricsLayer::custom(MeterOptions {
            service: Some(ServiceInfo {
                name: "test".to_owned(),
                version: "42".to_owned(),
            }),
            metric_prefix: Some("foo".to_owned()),
            ..Default::default()
        })
        .layer(());
        let mut ctx = Context::default();
        let req = Request::builder()
            .uri("http://www.example.com")
            .body(())
            .unwrap();

        let attributes = svc.compute_attributes(&mut ctx, &req);
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == SERVICE_NAME && attr.value.as_str() == "test")
        );
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == SERVICE_VERSION && attr.value.as_str() == "42")
        );
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == HTTP_REQUEST_HOST)
        );
    }

    #[test]
    fn test_custom_svc_compute_attributes_attributes_vec() {
        let svc = RequestMetricsLayer::custom(MeterOptions {
            service: Some(ServiceInfo {
                name: "test".to_owned(),
                version: "42".to_owned(),
            }),
            metric_prefix: Some("foo".to_owned()),
            ..Default::default()
        })
        .with_attributes(vec![KeyValue::new("test", "attribute_fn")])
        .layer(());
        let mut ctx = Context::default();
        let req = Request::builder()
            .uri("http://www.example.com")
            .body(())
            .unwrap();

        let attributes = svc.compute_attributes(&mut ctx, &req);
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == SERVICE_NAME && attr.value.as_str() == "test")
        );
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == SERVICE_VERSION && attr.value.as_str() == "42")
        );
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == HTTP_REQUEST_HOST)
        );
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == "test" && attr.value.as_str() == "attribute_fn")
        );
    }

    #[test]
    fn test_custom_svc_compute_attributes_attribute_fn() {
        let svc = RequestMetricsLayer::custom(MeterOptions {
            service: Some(ServiceInfo {
                name: "test".to_owned(),
                version: "42".to_owned(),
            }),
            metric_prefix: Some("foo".to_owned()),
            ..Default::default()
        })
        .with_attributes(|size_hint: usize, _ctx: &Context<()>| {
            let mut attributes = Vec::with_capacity(size_hint + 1);
            attributes.push(KeyValue::new("test", "attribute_fn"));
            attributes
        })
        .layer(());
        let mut ctx = Context::default();
        let req = Request::builder()
            .uri("http://www.example.com")
            .body(())
            .unwrap();

        let attributes = svc.compute_attributes(&mut ctx, &req);
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == SERVICE_NAME && attr.value.as_str() == "test")
        );
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == SERVICE_VERSION && attr.value.as_str() == "42")
        );
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == HTTP_REQUEST_HOST)
        );
        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == "test" && attr.value.as_str() == "attribute_fn")
        );
    }
}
