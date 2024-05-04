mod test_server;

use rama::error::BoxError;
use rama::http::client::HttpClientExt;
use rama::http::BodyExtractExt;
use rama::service::Context;

const ADDRESS: &str = "127.0.0.1:40006";

#[tokio::test]
#[ignore]
async fn test_http_prometheus() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("http_prometheus");
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    test_root_path().await?;

    test_metrics().await?;

    Ok(())
}

async fn test_root_path() -> Result<(), BoxError> {
    for counter in 1..=2 {
        let resp = test_server::client()
            .get(format!("http://{ADDRESS}"))
            .send(Context::default())
            .await
            .unwrap();

        let res_str = resp.try_into_string().await?;
        let test_str = format!("<h1>Hello, #{}!", counter);
        assert_eq!(res_str, test_str);
    }
    Ok(())
}

async fn test_metrics() -> Result<(), BoxError> {
    let resp = test_server::client()
        .get(format!("http://{ADDRESS}/{}", "metrics"))
        .send(Context::default())
        .await
        .unwrap();
    let res_str = resp.try_into_string().await?;
    assert!(res_str.contains("counter 2"));

    Ok(())
}
