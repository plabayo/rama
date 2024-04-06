mod test_server;

use tokio::process::Command;

// this test is failed.
#[tokio::test]
async fn test_http_connect_proxy() {
    let _example = test_server::run_example_server("http_connect_proxy");
}
