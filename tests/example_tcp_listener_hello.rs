mod test_server;
use crate::test_server::recive_as_string;
use rama::{error::BoxError, http::Request};
const URL: &str = "http://127.0.0.1:49000";
const SRC: &str = include_str!("../examples/tcp_listener_hello.rs");

#[tokio::test]
async fn test_tcp_listener_hello() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("tcp_listener_hello");

    let request = Request::builder()
        .method("GET")
        .uri(URL)
        .body(String::new())?;
    let (_, body) = recive_as_string(request).await?;
    assert_eq!(body, SRC);

    Ok(())
}
