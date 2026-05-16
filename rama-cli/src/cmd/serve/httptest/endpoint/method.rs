use rama::http::service::web::response::ErrorResponse;
use rama::http::{Method, StatusCode};

pub(in crate::cmd::serve::httptest) async fn handler(
    method: Method,
) -> Result<String, ErrorResponse> {
    if method == Method::CONNECT {
        // CONNECT requests are not allowed to have response payload
        return Err(StatusCode::BAD_REQUEST.into());
    }
    Ok(method.to_string())
}
