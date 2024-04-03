mod test_server;
use rama::{error::BoxError, http::Request};

use crate::test_server::recive_as_string;
use serde_json::{self, json, Value};

#[tokio::test]
async fn test_http_listener_hello() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("http_listener_hello");

    let get_request = Request::builder()
        .method("GET")
        .uri("http://127.0.0.1:40005/path")
        .body(String::new())
        .unwrap();

    let (_, res_str) = recive_as_string(get_request).await?;
    let res_json: Value = serde_json::from_str(&res_str).unwrap();

    let test_json = json!({"method":"GET","path":"/path"});

    assert_eq!(res_json, test_json);

    Ok(())
}
