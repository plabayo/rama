mod test_server;
use rama::{error::BoxError, http::Request};

use crate::test_server::recive_as_string;
use tokio::process::Command;

// this test is failed.
#[tokio::test]
async fn test_http_listener_hello() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("http_connect_proxy");


    let get_request = Request::builder()
        .method("GET")
        .uri("http://127.0.0.1:40001/path")
        .header(
            "proxy-user",
            "'john-red-blue:secret' http://echo.example.internal/foo/bar",
        )
        .body(String::new())
        .unwrap();

    let output = Command::new("curl")
        .arg("-v -x http://127.0.0.1:40001 --proxy-user 'john:secret' http://www.example.com/")
        .output()
        .await
        .unwrap()
        .stdout;

    //let (_, res_str) = recive_as_string(get_request).await?;
    let res_str = String::from_utf8_lossy(&output).to_string();
    let test_str = r##"{"method":"GET","path":"/path"}"##;

    assert_eq!(res_str, test_str);

    Ok(())
}
