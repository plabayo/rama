use super::utils;
use itertools::Itertools;
use rama::{
    http::{BodyExtractExt, StatusCode},
    service::Context,
};
use serde_json::json;

#[tokio::test]
#[ignore]
async fn test_example_http_form() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_key_value_store");

    // store multiple key value pairs
    let response = runner
        .post("http://127.0.0.1:62006/items")
        .json(&json!({
            "key1": "value1",
            "key2": "value2",
        }))
        .send(Context::default())
        .await
        .unwrap();
    assert_eq!(StatusCode::OK, response.status());

    // list all keys
    let keys = runner
        .get("http://127.0.0.1:62006/keys")
        .send(Context::default())
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap()
        .split(',')
        .map(str::trim)
        .sorted()
        .join(", ");
    assert_eq!("key1, key2", keys);

    // store a single key value pair
    let response = runner
        .post("http://127.0.0.1:62006/item/key3")
        .body("value3")
        .send(Context::default())
        .await
        .unwrap();
    assert_eq!(StatusCode::OK, response.status());

    // get a single key value pair
    let value = runner
        .get("http://127.0.0.1:62006/item/key3")
        .send(Context::default())
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();
    assert_eq!("value3", value);

    // check existence for a key
    let response = runner
        .head("http://127.0.0.1:62006/item/key3")
        .send(Context::default())
        .await
        .unwrap();
    assert_eq!(StatusCode::OK, response.status());

    // delete a key
    let response = runner
        .delete("http://127.0.0.1:62006/admin/item/key3")
        .bearer_auth("secret-token")
        .send(Context::default())
        .await
        .unwrap();
    assert_eq!(StatusCode::OK, response.status());

    // check existence for that same key again
    let response = runner
        .head("http://127.0.0.1:62006/item/key3")
        .send(Context::default())
        .await
        .unwrap();
    assert_eq!(StatusCode::NOT_FOUND, response.status());
}
