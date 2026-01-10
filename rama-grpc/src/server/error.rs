use rama_core::{error::BoxError, telemetry::tracing};

use crate::Status;

pub fn unexpected_error_into_http_response(
    error: impl Into<BoxError>,
) -> rama_http_types::Response {
    let error = error.into();
    tracing::debug!("unexpected grpc error: {error}; return generic http response");

    let status = Status::from_error(error);

    let mut response = rama_http::Response::new(rama_http::Body::default());
    let headers = response.headers_mut();
    headers.insert(Status::GRPC_STATUS, (status.code() as i32).into());
    headers.insert(
        rama_http::header::CONTENT_TYPE,
        crate::metadata::GRPC_CONTENT_TYPE,
    );

    response
}
