//! Http OpenTelemetry [`Layer`] Support for Rama.
//!
//! [`Layer`]: rama_core::Layer

use crate::service::web::response::IntoResponse;
use crate::{
    Request, Response, StreamingBody,
    body::{Frame, SizeHint},
};
use pin_project_lite::pin_project;
use rama_core::bytes::Bytes;
use rama_core::error::BoxError;
use rama_core::extensions::ExtensionsRef;
use rama_core::telemetry::opentelemetry::metrics::UpDownCounter;
use rama_core::telemetry::opentelemetry::semantic_conventions::metric::{
    HTTP_SERVER_ACTIVE_REQUESTS, HTTP_SERVER_REQUEST_BODY_SIZE,
};
use rama_core::telemetry::opentelemetry::{
    AttributesFactory, InstrumentationScope, KeyValue, MeterOptions, global,
    metrics::{Counter, Histogram, Meter},
    semantic_conventions,
};
use rama_core::{Layer, Service};
use rama_net::{AuthorityInputExt, HttpVersionInputExt, ProtocolInputExt};
use rama_utils::guard::DropGuard;
use rama_utils::macros::define_inner_service_accessors;
use std::sync::atomic::{self, AtomicUsize};
use std::{borrow::Cow, fmt, sync::Arc};
use tokio::time::Instant;

// Follows the experimental semantic conventions for HTTP metrics:
// https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/metrics/semantic_conventions/http-metrics.md

use semantic_conventions::attribute::{
    HTTP_REQUEST_METHOD, HTTP_RESPONSE_STATUS_CODE, NETWORK_PROTOCOL_VERSION, SERVER_PORT,
    URL_SCHEME,
};

const HTTP_SERVER_DURATION: &str = "http.requests.duration";
const HTTP_SERVER_TOTAL_REQUESTS: &str = "http.requests.total";
const HTTP_SERVER_TOTAL_FAILURES: &str = "http.failures.total";
const HTTP_SERVER_TOTAL_RESPONSES: &str = "http.responses.total";
const HTTP_SERVER_TOTAL_CANCELLATIONS: &str = "http.cancellations.total";

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
    http_server_total_cancellations: Counter<u64>,
    http_server_active_requests: UpDownCounter<i64>,
    http_server_request_body_size: Histogram<u64>,
}

impl Metrics {
    /// Create a new [`RequestMetrics`]
    #[must_use]
    fn new(meter: &Meter, prefix: Option<&str>) -> Self {
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

        let http_server_total_cancellations = meter
            .u64_counter(match &prefix {
                Some(prefix) => Cow::Owned(format!("{prefix}.{HTTP_SERVER_TOTAL_CANCELLATIONS}")),
                None => Cow::Borrowed(HTTP_SERVER_TOTAL_CANCELLATIONS),
            })
            .with_description(
                "Measures the total number of HTTP requests that were cancelled before a response or failure was recorded.",
            )
            .build();

        let http_server_active_requests = meter
            .i64_up_down_counter(match &prefix {
                Some(prefix) => Cow::Owned(format!("{prefix}.{HTTP_SERVER_ACTIVE_REQUESTS}")),
                None => Cow::Borrowed(HTTP_SERVER_ACTIVE_REQUESTS),
            })
            .with_description("Measures the number of active HTTP server requests.")
            .build();

        let http_server_request_body_size = meter
            .u64_histogram(match &prefix {
                Some(prefix) => Cow::Owned(format!("{prefix}.{HTTP_SERVER_REQUEST_BODY_SIZE}")),
                None => Cow::Borrowed(HTTP_SERVER_REQUEST_BODY_SIZE),
            })
            .with_description("Measures the HTTP request body size.")
            .with_unit("B")
            .build();

        Self {
            http_server_total_requests,
            http_server_total_responses,
            http_server_total_failures,
            http_server_total_cancellations,
            http_server_duration,
            http_server_active_requests,
            http_server_request_body_size,
        }
    }
}

/// A layer that records http server metrics using OpenTelemetry.
#[derive(Debug, Clone)]
pub struct RequestMetricsLayer<F = ()> {
    metrics: Arc<Metrics>,
    base_attributes: Vec<KeyValue>,
    attributes_factory: F,
}

impl RequestMetricsLayer<()> {
    /// Create a new [`RequestMetricsLayer`] using the global [`Meter`] provider,
    /// with the default name and version.
    #[must_use]
    pub fn new() -> Self {
        Self::custom(MeterOptions::default())
    }

    /// Create a new [`RequestMetricsLayer`] using the global [`Meter`] provider,
    /// with a custom name and version.
    #[must_use]
    pub fn custom(opts: MeterOptions) -> Self {
        Self::custom_with_meter(&get_versioned_meter(), opts)
    }

    /// Create a new [`RequestMetricsLayer`] using the given [`Meter`],
    /// instead of the global [`Meter`] provider.
    #[must_use]
    pub fn custom_with_meter(meter: &Meter, opts: MeterOptions) -> Self {
        let attributes = opts.attributes.unwrap_or_default();
        let metrics = Metrics::new(meter, opts.metric_prefix.as_deref());

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

    fn into_layer(self, inner: S) -> Self::Service {
        RequestMetricsService {
            inner,
            metrics: self.metrics,
            base_attributes: self.base_attributes,
            attributes_factory: self.attributes_factory,
        }
    }
}

/// A [`Service`] that records HTTP server metrics using OpenTelemetry.
#[derive(Debug, Clone)]
pub struct RequestMetricsService<S, F = ()> {
    inner: S,
    metrics: Arc<Metrics>,
    base_attributes: Vec<KeyValue>,
    attributes_factory: F,
}

impl<S> RequestMetricsService<S, ()> {
    /// Create a new [`RequestMetricsService`].
    pub fn new(inner: S) -> Self {
        RequestMetricsLayer::new().into_layer(inner)
    }

    define_inner_service_accessors!();
}

impl<S, F> RequestMetricsService<S, F> {
    fn compute_attributes<Body>(&self, req: &Request<Body>) -> Vec<KeyValue>
    where
        F: AttributesFactory,
    {
        let mut attributes = self
            .attributes_factory
            .attributes(5 + self.base_attributes.len(), req.extensions());
        attributes.extend(self.base_attributes.iter().cloned());

        // server info
        let authority = req.authority();
        let protocol = req.protocol();
        let http_version = req.http_version();

        if let Some(authority) = authority.as_ref() {
            attributes.push(KeyValue::new(HTTP_REQUEST_HOST, authority.host.to_string()));
            if let Some(port) = authority.port.as_u16() {
                attributes.push(KeyValue::new(SERVER_PORT, port as i64));
            }
        }

        // Request Info
        if let Some(protocol) = protocol.as_ref() {
            attributes.push(KeyValue::new(URL_SCHEME, protocol.to_string()));
        }

        attributes.push(KeyValue::new(HTTP_REQUEST_METHOD, req.method().to_string()));
        if let Some(http_version) = http_version.map(|v| match v {
            rama_http_types::Version::HTTP_09 => "0.9",
            rama_http_types::Version::HTTP_10 => "1.0",
            rama_http_types::Version::HTTP_11 => "1.1",
            rama_http_types::Version::HTTP_2 => "2",
            rama_http_types::Version::HTTP_3 => "3",
        }) {
            attributes.push(KeyValue::new(NETWORK_PROTOCOL_VERSION, http_version));
        }

        attributes
    }
}

impl<S, F, Body> Service<Request<Body>> for RequestMetricsService<S, F>
where
    S: Service<Request, Output: IntoResponse>,
    F: AttributesFactory,
    Body: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    type Output = Response;
    type Error = S::Error;

    async fn serve(&self, req: Request<Body>) -> Result<Self::Output, Self::Error> {
        let mut attributes: Vec<KeyValue> = self.compute_attributes(&req);

        self.metrics.http_server_total_requests.add(1, &attributes);
        self.metrics.http_server_active_requests.add(1, &attributes);

        // used to compute the duration of the request
        let timer = Instant::now();

        let polled_body_size: Arc<AtomicUsize> = Default::default();
        let req = req.map(|body| {
            crate::Body::new(BodyTracker {
                inner: body,
                polled_size: polled_body_size.clone(),
            })
        });

        let result = {
            let mut cancel_guard = DropGuard::new(|| {
                self.metrics
                    .http_server_active_requests
                    .add(-1, &attributes);
                self.metrics
                    .http_server_total_cancellations
                    .add(1, &attributes);
            });
            let result = self.inner.serve(req).await;
            cancel_guard.disarm();
            result
        };

        self.metrics
            .http_server_active_requests
            .add(-1, &attributes);
        self.metrics.http_server_request_body_size.record(
            polled_body_size.load(atomic::Ordering::Relaxed) as u64,
            &attributes,
        );

        match result {
            Ok(res) => {
                let res = res.into_response();

                attributes.push(KeyValue::new(
                    HTTP_RESPONSE_STATUS_CODE,
                    res.status().as_u16() as i64,
                ));

                self.metrics.http_server_total_responses.add(1, &attributes);
                self.metrics
                    .http_server_duration
                    .record(timer.elapsed().as_secs_f64(), &attributes);

                Ok(res)
            }
            Err(err) => {
                self.metrics.http_server_total_failures.add(1, &attributes);

                Err(err)
            }
        }
    }
}

pin_project! {
    /// Wrapper around the incoming Request body used
    /// to track the request body size.
    pub struct BodyTracker<B> {
        #[pin]
        inner: B,
        polled_size: Arc<AtomicUsize>,
    }
}

impl<B: fmt::Debug> fmt::Debug for BodyTracker<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BodyTracker")
            .field("inner", &self.inner)
            .field("polled_size", &self.polled_size)
            .finish()
    }
}

impl<B> StreamingBody for BodyTracker<B>
where
    B: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        match this.inner.poll_frame(cx) {
            std::task::Poll::Ready(opt) => {
                if let Some(Ok(frame)) = &opt
                    && let Some(data) = frame.data_ref()
                {
                    this.polled_size
                        .fetch_add(data.len(), atomic::Ordering::Relaxed);
                }
                std::task::Poll::Ready(opt)
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use ahash::HashMap;
    use parking_lot::Mutex;
    use rama_core::extensions::Extensions;
    use rama_core::telemetry::opentelemetry::metrics::MeterProvider as _;
    use rama_core::telemetry::opentelemetry::sdk::{
        error::OTelSdkResult,
        metrics::{
            PeriodicReader, SdkMeterProvider, Temporality,
            data::{AggregatedMetrics, MetricData, ResourceMetrics},
            exporter::PushMetricExporter,
        },
    };
    use std::{convert::Infallible, time::Duration};

    use super::*;

    #[test]
    fn test_default_svc_compute_attributes_default() {
        let svc = RequestMetricsService::new(());
        let req = Request::builder()
            .uri("http://www.example.com")
            .body(())
            .unwrap();

        let attributes = svc.compute_attributes(&req);

        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == HTTP_REQUEST_HOST)
        );
    }

    #[test]
    fn test_custom_svc_compute_attributes_default() {
        let svc = RequestMetricsLayer::custom(MeterOptions {
            metric_prefix: Some("foo".to_owned()),
            ..Default::default()
        })
        .into_layer(());
        let req = Request::builder()
            .uri("http://www.example.com")
            .body(())
            .unwrap();

        let attributes = svc.compute_attributes(&req);

        assert!(
            attributes
                .iter()
                .any(|attr| attr.key.as_str() == HTTP_REQUEST_HOST)
        );
    }

    #[test]
    fn test_custom_svc_compute_attributes_attributes_vec() {
        let svc = RequestMetricsLayer::custom(MeterOptions {
            metric_prefix: Some("foo".to_owned()),
            ..Default::default()
        })
        .with_attributes(vec![KeyValue::new("test", "attribute_fn")])
        .into_layer(());
        let req = Request::builder()
            .uri("http://www.example.com")
            .body(())
            .unwrap();

        let attributes = svc.compute_attributes(&req);
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
            metric_prefix: Some("foo".to_owned()),
            ..Default::default()
        })
        .with_attributes(|size_hint: usize, _extensions: &Extensions| {
            let mut attributes = Vec::with_capacity(size_hint + 1);
            attributes.push(KeyValue::new("test", "attribute_fn"));
            attributes
        })
        .into_layer(());
        let req = Request::builder()
            .uri("http://www.example.com")
            .body(())
            .unwrap();

        let attributes = svc.compute_attributes(&req);

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

    #[derive(Debug, Clone, Default)]
    struct SumCapture {
        sums: Arc<Mutex<HashMap<String, i64>>>,
    }

    impl SumCapture {
        fn get(&self, name: &str) -> i64 {
            self.sums.lock().get(name).copied().unwrap_or_default()
        }
    }

    impl PushMetricExporter for SumCapture {
        async fn export(&self, metrics: &ResourceMetrics) -> OTelSdkResult {
            let mut sums = self.sums.lock();
            for scope in metrics.scope_metrics() {
                for metric in scope.metrics() {
                    let total: i64 = match metric.data() {
                        AggregatedMetrics::I64(MetricData::Sum(sum)) => {
                            sum.data_points().map(|point| point.value()).sum()
                        }
                        AggregatedMetrics::U64(MetricData::Sum(sum)) => sum
                            .data_points()
                            .map(|point| i64::try_from(point.value()).unwrap())
                            .sum(),
                        _ => continue,
                    };
                    sums.insert(metric.name().to_owned(), total);
                }
            }
            Ok(())
        }

        fn force_flush(&self) -> OTelSdkResult {
            Ok(())
        }

        fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
            Ok(())
        }

        fn temporality(&self) -> Temporality {
            Temporality::Cumulative
        }
    }

    struct OkService;

    impl Service<Request> for OkService {
        type Output = Response;
        type Error = Infallible;

        async fn serve(&self, _req: Request) -> Result<Self::Output, Self::Error> {
            Ok(Response::new(crate::Body::empty()))
        }
    }

    struct PendingService;

    impl Service<Request> for PendingService {
        type Output = Response;
        type Error = Infallible;

        async fn serve(&self, _req: Request) -> Result<Self::Output, Self::Error> {
            std::future::pending().await
        }
    }

    fn test_request() -> Request {
        Request::builder()
            .uri("http://www.example.com")
            .body(crate::Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn test_active_requests_balanced_on_completion_and_cancellation() {
        let exporter = SumCapture::default();
        let provider = SdkMeterProvider::builder()
            .with_reader(PeriodicReader::builder(exporter.clone()).build())
            .build();
        let meter = provider.meter("test");

        let svc = RequestMetricsLayer::custom_with_meter(&meter, MeterOptions::default())
            .into_layer(OkService);
        svc.serve(test_request()).await.unwrap();

        provider.force_flush().unwrap();
        assert_eq!(
            0,
            exporter.get(HTTP_SERVER_ACTIVE_REQUESTS),
            "completed request must not leave an active request behind"
        );
        assert_eq!(1, exporter.get(HTTP_SERVER_TOTAL_RESPONSES));
        assert_eq!(0, exporter.get(HTTP_SERVER_TOTAL_CANCELLATIONS));

        let svc = RequestMetricsLayer::custom_with_meter(&meter, MeterOptions::default())
            .into_layer(PendingService);
        let cancelled = tokio::time::timeout(Duration::from_millis(10), svc.serve(test_request()))
            .await
            .is_err();
        assert!(cancelled, "inner service should never have resolved");

        provider.force_flush().unwrap();
        assert_eq!(
            0,
            exporter.get(HTTP_SERVER_ACTIVE_REQUESTS),
            "cancelled request must not leak an active request"
        );
        assert_eq!(
            1,
            exporter.get(HTTP_SERVER_TOTAL_CANCELLATIONS),
            "cancelled request must be recorded as a cancellation"
        );
        assert_eq!(
            0,
            exporter.get(HTTP_SERVER_TOTAL_FAILURES),
            "cancellation must not be counted as a failure"
        );
        assert_eq!(
            2,
            exporter.get(HTTP_SERVER_TOTAL_REQUESTS),
            "every request must be accounted for exactly once"
        );
    }
}
