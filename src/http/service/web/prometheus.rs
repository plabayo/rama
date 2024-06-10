//! [`prometheus`] metrics endpoint and service.
//!
//! This module provides a simple service ([`PrometheusMetricsHandler`]) that can be used to expose
//! prometheus metrics over HTTP. The service is built using the
//! [`WebService`].
//!
//! [`prometheus`]: https://crates.io/crates/prometheus
//! [`WebService`]: crate::http::service::web::WebService

use std::convert::Infallible;

use crate::{
    http::{header, IntoResponse, Request, Response, StatusCode},
    service::{Context, Service},
};
use prometheus::{Encoder, TextEncoder};

#[derive(Debug, Clone, Default)]
/// A [`WebService`] endpoint that serves [`prometheus`] metrics.
///
/// Often used together with open telemetry layers, such as:
/// - [`RequestMetricsLayer`]: for Http request metrics;
/// - [`NetworkMetricsLayer`]: for network (tcp/udp) metrics.
///
/// [`WebService`]: crate::http::service::web::WebService
/// [`prometheus`]: https://crates.io/crates/prometheus
/// [`RequestMetricsLayer`]: crate::http::layer::opentelemetry::RequestMetricsLayer
/// [`NetworkMetricsLayer`]: crate::net::stream::layer::opentelemetry::NetworkMetricsLayer
pub struct PrometheusMetricsHandler {
    registry: Option<prometheus::Registry>,
}

impl PrometheusMetricsHandler {
    /// Create a new [`WebService`] endpoint that serves [`prometheus`] metrics.
    ///
    /// See [`PrometheusMetricsHandler`] for more details.
    ///
    /// [`WebService`]: crate::http::service::web::WebService
    /// [`prometheus`]: https://crates.io/crates/prometheus
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the [`prometheus::Registry`] to use for gathering metrics.
    ///
    /// The global registry is used by default.
    pub fn with_registry(mut self, registry: prometheus::Registry) -> Self {
        self.registry = Some(registry);
        self
    }
}

impl<State, Body> Service<State, Request<Body>> for PrometheusMetricsHandler
where
    State: Send + Sync + 'static,
    Body: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;

    async fn serve(
        &self,
        _: Context<State>,
        _: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let registry = match self.registry {
            Some(ref registry) => registry,
            None => prometheus::default_registry(),
        };

        let encoder = TextEncoder::new();

        let metric_families = registry.gather();
        let mut buffer = vec![];
        match encoder.encode(&metric_families, &mut buffer) {
            Ok(_) => (),
            Err(e) => {
                return Ok((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to encode prometheus metrics: {}", e),
                )
                    .into_response());
            }
        }

        Ok((
            [
                (header::CONTENT_TYPE, encoder.format_type().to_owned()),
                (header::CONTENT_LENGTH, buffer.len().to_string()),
            ],
            buffer,
        )
            .into_response())
    }
}
