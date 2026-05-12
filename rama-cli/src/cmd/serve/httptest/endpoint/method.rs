use rama::http::{Method, StatusCode, service::web::response::IntoResponse, Response};

pub(in crate::cmd::serve::httptest) async fn handler(method: Method) -> Response {
    if method == Method::CONNECT {
        // CONNECT requests are not allowed to have response payload
        return StatusCode::BAD_REQUEST.into_response();
    }
    method.to_string().into_response()
}
