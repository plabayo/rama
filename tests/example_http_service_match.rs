mod test_server;
use crate::test_server::recive_as_string;
use rama::{error::BoxError, http::Request};
use serde_json::{json, Value};
const URL: &str = "http://127.0.0.1:40010";

#[tokio::test]
async fn test_http_service_match() -> Result<(), BoxError> {
    let method = "PATCH";
    let path = "/echo";
    let _example = test_server::run_example_server("http_service_match");
    let request = Request::builder()
        .method(method)
        .uri(format!("{}{}", URL, path))
        .body(String::new())?;
    let (_, body) = recive_as_string(request).await?;
    let res_json: Value = serde_json::from_str(&body).unwrap();

    let test_json = json!({"method":method,"path":path});
    assert_eq!(res_json, test_json);
    Ok(())
}
