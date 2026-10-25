use super::utils;

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_socks5_bind_proxy() {
    utils::init_tracing();

    let exit_status = utils::ExampleRunner::run(utils::example!("socks5_bind_proxy")).await;
    assert!(exit_status.success());
}
