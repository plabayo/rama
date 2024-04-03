mod test_server;

use crate::test_server::recive_as_string;
use rama::{error::BoxError, http::Request};

const URL: &str = "http://127.0.0.1:40006/";

#[tokio::test]
async fn test_http_prometheus() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("http_prometheus");
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    test_root_path().await?;

    test_metrics().await?;

    Ok(())
}

async fn test_root_path() -> Result<(), BoxError> {
    let request = Request::builder()
        .method("GET")
        .uri(URL)
        .body(String::new())
        .unwrap();

    for counter in 1..=2 {
        let (_, res_str) = recive_as_string(request.clone()).await?;
        let test_str = format!("<h1>Hello, #{}!", counter);
        assert_eq!(res_str, test_str);
    }
    Ok(())
}

async fn test_metrics() -> Result<(), BoxError> {
    let request = Request::builder()
        .method("GET")
        .uri(format!("{}{}", URL, "metrics"))
        .body(String::new())
        .unwrap();
    let (_, res_str) = recive_as_string(request.clone()).await?;
    assert_eq!(res_str,"# HELP example_counter example counter\n# TYPE example_counter counter\nexample_counter 2\n");

    Ok(())
}
