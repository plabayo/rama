mod test_server;

use rama::error::BoxError;
use rama::http::client::HttpClientExt;
use rama::http::BodyExtractExt;
use rama::service::Context;
use serde_json::{self, json, Value};

const ADDRESS: &str = "127.0.0.1:40005";

#[tokio::test]
#[ignore]
async fn test_http_listener_hello() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("http_listener_hello");

    let resp = test_server::client()
        .get(format!("http://{ADDRESS}/path"))
        .send(Context::default())
        .await
        .unwrap();

    let res_json = resp.try_into_json::<Value>().await.unwrap();

    let test_json = json!({"method":"GET","path":"/path"});

    assert_eq!(res_json, test_json);

    Ok(())
}
