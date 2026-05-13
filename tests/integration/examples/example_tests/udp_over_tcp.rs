use super::utils;

#[tokio::test]
#[ignore]
async fn test_udp_over_tcp() {
    utils::init_tracing();

    let exit_status = utils::ExampleRunner::run("udp_over_tcp").await;
    assert!(exit_status.success());
}
