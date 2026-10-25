use super::utils;

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_unix_datagram_codec() {
    utils::init_tracing();

    let exit_status = utils::ExampleRunner::run(utils::example!("unix_datagram_codec")).await;
    assert!(exit_status.success());
}
