mod test_server;
use crate::test_server::recive_as_string;
use rama::{error::BoxError, http::Request};
use regex::Regex;
const URL: &str = "http://127.0.0.1:40009";

#[tokio::test]
async fn test_http_service_fs() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("http_service_hello");
    let request = Request::builder()
        .method("GET")
        .uri(URL)
        .body(String::new())?;

    let (_, body) = recive_as_string(request).await?;
    let peer = Regex::new(r"Peer: 127.0.0.1:[56][0-9]{4}").unwrap();
    assert!(peer.is_match(&body));
    Ok(())
}
