use super::utils;
use rama::http::BodyExtractExt;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct FdPassingResponse {
    message: String,
    pid: u64,
    zero_downtime: bool,
}

#[tokio::test]
#[ignore]
async fn test_tcp_listener_fd_passing() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("tcp_listener_fd_passing", None);

    let response = runner
        .get("http://127.0.0.1:62046")
        .send()
        .await
        .unwrap()
        .try_into_json::<FdPassingResponse>()
        .await
        .unwrap();

    assert_eq!(response.message, "Hello from child process!");
    assert!(response.zero_downtime);
    assert!(response.pid > 0);
}
