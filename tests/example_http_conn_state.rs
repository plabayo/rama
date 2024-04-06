mod test_server;

use rama::{error::BoxError, http::Request};

use crate::test_server::recive_as_string;

#[tokio::test]
async fn test_http_conn_state() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("http_conn_state");

    let get_request = Request::builder()
        .method("GET")
        .uri("http://127.0.0.1:40000/")
        .body(String::new())
        .unwrap();

    let (_, res_str) = recive_as_string(get_request).await?;
    assert!(res_str.contains("Connection "));

    Ok(())
}
