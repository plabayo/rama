use rama::http::{Method, StatusCode, service::web::response::IntoResponse};

pub(in crate::cmd::serve::httptest) async fn handler(method: Method) -> impl IntoResponse {
    if method == Method::CONNECT {
        // CONNECT requests are not allowed to have response payload
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(method.to_string())
}
