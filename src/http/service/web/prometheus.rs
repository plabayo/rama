//! [`prometheus`] metrics endpoint and service.
//!
//! This module provides a simple service that can be used to expose
//! prometheus metrics over HTTP. The service is built using the
//! [`WebService`].
//!
//! [`prometheus`]: https://crates.io/crates/prometheus
//! [`WebService`]: crate::http::service::web::WebService

use crate::http::{header, Body, Response, StatusCode};
use prometheus::{Encoder, TextEncoder};

/// Create a new [`WebService`] endpoint that serves [`prometheus`]` metrics.
///
/// [`WebService`]: crate::http::service::web::WebService
/// [`prometheus`]: https://crates.io/crates/prometheus
pub async fn prometheus_metrics() -> Response {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    match encoder.encode(&metric_families, &mut buffer) {
        Ok(_) => (),
        Err(e) => {
            return http::Response::builder()
                .status(500)
                .body(Body::from(format!(
                    "failed to encode prometheus metrics: {}",
                    e
                )))
                .unwrap();
        }
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, encoder.format_type())
        .header(header::CONTENT_LENGTH, buffer.len())
        .body(Body::from(buffer))
        .unwrap()
}
