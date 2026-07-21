use super::utils;

#[tokio::test]
#[ignore]
async fn test_http_har_replay() {
    utils::init_tracing();

    let exit_status = utils::ExampleRunner::run("http_har_replay").await;
    assert!(exit_status.success());
}
