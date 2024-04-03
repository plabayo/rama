mod test_server;
use std::any::Any;

use http::StatusCode;
use rama::{error::BoxError, http::Request};

use crate::test_server::recive_as_string;

#[tokio::test]
async fn test_http_key_value_store() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("http_key_value_store");

    // because the example couldn't recive request yet.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    let (key, value) = ("key3", "value3");
    test_post(key, value).await?;
    test_get(key, value).await?;

    Ok(())
}

async fn test_post(key: &str, value: &str) -> Result<(), BoxError> {
    let request = Request::builder()
        .method("POST")
        .uri(format!("http://127.0.0.1:40004/item/{}", key))
        .body(value.to_string())
        .unwrap();

    let (parts, _) = recive_as_string(request).await?;
    assert_eq!(parts.status, StatusCode::OK);
    Ok(())
}

async fn test_get(key: &str, value: &str) -> Result<(), BoxError>{
    let request = Request::builder()
        .method("GET")
        .uri(format!("http://127.0.0.1:40004/item/{}", key))
        .body(String::new())
        .unwrap();

    let (_, res_str) = recive_as_string(request).await?;
    assert_eq!(res_str, value);
    Ok(())
}
