use super::utils;

#[tokio::test]
#[ignore]
async fn test_http_pooled_client() {
    utils::init_tracing();

    let exit_status = utils::ExampleRunner::run("http_pooled_client").await;
    assert!(exit_status.success());
}
