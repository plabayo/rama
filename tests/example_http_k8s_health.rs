mod test_server;
use http::StatusCode;
use rama::{error::BoxError, http::Request};

use crate::test_server::recive_as_string;

#[tokio::test]
async fn test_http_k8s_health() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("http_k8s_health");

    let request = Request::builder()
        .method("GET")
        .uri("http://127.0.0.1:40003/k8s/ready")
        .body(String::new())
        .unwrap();

    let (parts, _) = recive_as_string(request.clone()).await?;

    assert_eq!(parts.status, StatusCode::SERVICE_UNAVAILABLE);

    tokio::time::sleep(std::time::Duration::from_secs(11)).await;

    let (parts, _) = recive_as_string(request).await?;

    assert_eq!(parts.status, StatusCode::OK);

    Ok(())
}
