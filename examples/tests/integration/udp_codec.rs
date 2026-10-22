use super::utils;

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_udp_codec() {
    utils::init_tracing();

    let exit_status = utils::ExampleRunner::run(utils::example!("udp_codec")).await;
    assert!(exit_status.success());
}
