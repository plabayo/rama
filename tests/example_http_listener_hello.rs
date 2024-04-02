mod test_server;
use rama::{
    http::Request,
    error::BoxError,
};

use crate::test_server::recive_as_string;

#[tokio::test]
async fn test_http_listener_hello() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("http_listener_hello");

    let get_request = Request::builder()
        .method("GET")
        .uri("http://127.0.0.1:40001/path")
        .body(String::new())
        .unwrap();

    let res_str = recive_as_string(get_request).await?;

    let test_str = r##"{"method":"GET","path":"/path"}"##;

    assert_eq!(res_str, test_str);

    Ok(())
}
