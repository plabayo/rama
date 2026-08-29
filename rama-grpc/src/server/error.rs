use rama_core::{error::BoxError, telemetry::tracing};
use rama_http::headers::{ContentType, HeaderMapExt as _};

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
    headers.typed_insert(ContentType::grpc());

    response
}

#[cfg(test)]
mod tests {
    use rama_http::header::CONTENT_TYPE;

    use super::*;

    #[test]
    fn unexpected_errors_produce_a_typed_grpc_response() {
        let response = unexpected_error_into_http_response(std::io::Error::other("boom"));

        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/grpc"
        );
        assert!(response.headers().contains_key(Status::GRPC_STATUS));
    }
}
