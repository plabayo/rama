use super::utils;
use rama::http::BodyExtractExt;
use serde_json::{self, Value, json};

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_http_listener_hello() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive(utils::example!("http_listener_hello"));

    let value = runner
        .post("http://127.0.0.1:62007/foo/bar")
        .send()
        .await
        .unwrap()
        .try_into_json::<Value>()
        .await
        .unwrap();

    let expected_value = json!({"method":"POST","path":"/foo/bar"});

    assert_eq!(expected_value, value);
}
