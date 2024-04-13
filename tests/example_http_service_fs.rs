mod test_server;

use crate::test_server::recive_as_string;
use rama::{error::BoxError, http::Request};
use std::fs::read_to_string;
const URL: &str = "http://127.0.0.1:40008";

#[tokio::test]
async fn test_http_service_fs() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("http_service_fs");
    let cwd = std::env::current_dir().expect("current working dir");
    let path = "test-files/index.html";
    let request = Request::builder()
        .method("GET")
        .uri(format!("{}/{}", URL, path))
        .body(String::new())?;

    let (_, body) = recive_as_string(request).await?;
    let index_path = cwd.join(path);
    let test_file_index = read_to_string(index_path).unwrap();
    assert_eq!(body, test_file_index);
    Ok(())
}
