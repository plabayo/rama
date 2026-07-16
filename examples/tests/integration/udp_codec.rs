use super::utils;

#[tokio::test]
#[ignore]
async fn test_udp_codec() {
    utils::init_tracing();

    let exit_status = utils::ExampleRunner::run("udp_codec").await;
    assert!(exit_status.success());
}
