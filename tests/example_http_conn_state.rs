mod test_server;

use rama::error::BoxError;
use rama::http::client::HttpClientExt;
use rama::http::BodyExtractExt;
use rama::service::Context;

const ADDRESS: &str = "127.0.0.1:40000";

#[tokio::test]
#[ignore]
async fn test_http_conn_state() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("http_conn_state");

    let resp = test_server::client()
        .get(format!("http://{ADDRESS}"))
        .send(Context::default())
        .await
        .unwrap();

    let res_str = resp.try_into_string().await.unwrap();

    assert!(res_str.contains("Connection <code>1</code>"));

    Ok(())
}
