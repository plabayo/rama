mod test_server;
use crate::test_server::recive_as_string;
use rama::{error::BoxError, http::Request};
const URL: &str = "http://127.0.0.1:40011";

#[tokio::test]
async fn test_http_web_service_dir_and_api() -> Result<(), BoxError> {
    let coin_count = r##"<h1 id="coinCount">{count}</h1>"##;
    let _example = test_server::run_example_server("http_web_service_dir_and_api");

    let request = Request::builder()
        .method("GET")
        .uri(format!("{}{}", URL, "/coin"))
        .body(String::new())?;
    let (_, body) = recive_as_string(request).await?;
    assert!(body.contains(&coin_count.replace("{count}", "0")));

    let request = Request::builder()
        .method("POST")
        .uri(format!("{}{}", URL, "/coin"))
        .body(String::new())?;
    let (_, body) = recive_as_string(request).await?;
    assert!(body.contains(&coin_count.replace("{count}", "1")));
    Ok(())
}
