mod test_server;

use http::StatusCode;
use rama::error::BoxError;
use rama::http::client::HttpClientExt;
use rama::http::BodyExtractExt;
use rama::service::Context;

const ADDRESS: &str = "127.0.0.1:40004";

#[tokio::test]
async fn test_http_key_value_store() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("http_key_value_store");

    let (key, value) = ("key3", "value3");

    let resp = test_server::client()
        .post(format!("http://{ADDRESS}/item/{}", key))
        .body(value.to_string())
        .send(Context::default())
        .await
        .unwrap();

    let (parts, _) = resp.into_parts();

    assert_eq!(parts.status, StatusCode::OK);

    let resp = test_server::client()
        .get(format!("http://{ADDRESS}/item/{}", key))
        .send(Context::default())
        .await
        .unwrap();

    let res_str = resp.try_into_string().await.unwrap();
    assert_eq!(res_str, value);
    Ok(())
}
