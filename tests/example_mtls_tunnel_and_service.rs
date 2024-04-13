mod test_server;
use crate::test_server::recive_as_string;

use rama::{error::BoxError, http::Request};
const URL: &str = "http://127.0.0.1:40012";

#[tokio::test]
async fn test_mtls_tunnel_and_service() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("mtls_tunnel_and_service");

    let request = Request::builder()
        .method("GET")
        .uri(format!("{}{}", URL, "/hello"))
        .body(String::new())?;
    let (_, body) = recive_as_string(request).await?;
    assert_eq!(body, "<h1>Hello, authorized client!</h1>");

    // TODO: connect by mTLS
    Ok(())
}
