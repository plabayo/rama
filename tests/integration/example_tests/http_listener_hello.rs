use super::utils;
use rama::http::BodyExtractExt;
use rama::service::Context;
use serde_json::{self, json, Value};

#[tokio::test]
#[ignore]
async fn test_http_listener_hello() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_listener_hello");

    let value = runner
        .post("http://127.0.0.1:62007/foo/bar")
        .send(Context::default())
        .await
        .unwrap()
        .try_into_json::<Value>()
        .await
        .unwrap();

    let expected_value = json!({"method":"POST","path":"/foo/bar"});

    assert_eq!(expected_value, value);
}
