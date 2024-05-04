mod test_server;
use http::StatusCode;
use rama::error::BoxError;
use rama::http::client::HttpClientExt;
use rama::service::Context;

const URL: &str = "http://127.0.0.1:40003/k8s/ready";

#[tokio::test]
async fn test_http_k8s_health() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("http_k8s_health");

    let resp = test_server::client()
        .get(URL)
        .send(Context::default())
        .await
        .unwrap();

    let (parts, _) = resp.into_parts();

    assert_eq!(parts.status, StatusCode::SERVICE_UNAVAILABLE);

    tokio::time::sleep(std::time::Duration::from_secs(11)).await;

    let resp = test_server::client()
        .get(URL)
        .send(Context::default())
        .await
        .unwrap();

    let (parts, _) = resp.into_parts();
    assert_eq!(parts.status, StatusCode::OK);

    Ok(())
}
