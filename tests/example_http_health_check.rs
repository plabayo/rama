mod test_server;
use http::StatusCode;
use rama::error::BoxError;
use rama::http::client::HttpClientExt;
use rama::service::Context;

#[tokio::test]
#[ignore]
async fn test_http_health_check() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("http_health_check");

    let resp = test_server::client()
        .get("http://127.0.0.1:40002/")
        .send(Context::default())
        .await
        .unwrap();

    let (parts, _) = resp.into_parts();

    assert_eq!(parts.status, StatusCode::OK);

    Ok(())
}
