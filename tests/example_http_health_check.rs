mod test_server;
use http::StatusCode;
use rama::{error::BoxError, http::Request};

use crate::test_server::recive_as_string;

#[tokio::test]
async fn test_http_health_check() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("http_health_check");

    let request = Request::builder()
        .method("GET")
        .uri("http://127.0.0.1:40002/")
        .body(String::new())
        .unwrap();

    let (parts, _) = recive_as_string(request).await?;

    assert_eq!(parts.status, StatusCode::OK);

    Ok(())
}
