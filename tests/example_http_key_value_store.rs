mod test_server;
use std::any::Any;

use http::StatusCode;
use rama::{
    http::Request,
    error::BoxError,
};

use serde_json;

use crate::test_server::recive_as_string;

#[tokio::test]
async fn test_http_key_value_store() -> Result<(), BoxError> {
   let _example = test_server::run_example_server("http_key_value_store");

   // because the example couldn't recive request yet.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    let value = "value3";
    let request = Request::builder()
        .method("POST")
        .uri("http://127.0.0.1:40004/item/key3")
        .body(value.to_string())
        .unwrap();

    let (parts, _) = recive_as_string(request).await?;
    assert_eq!(parts.status, StatusCode::OK);

    let request = Request::builder()
        .method("GET")
        .uri("http://127.0.0.1:40004/item/key3")
        .body(String::new())
        .unwrap();

    let (parts, res_str) = recive_as_string(request).await?;
    assert_eq!(res_str, value);

    Ok(())
}
