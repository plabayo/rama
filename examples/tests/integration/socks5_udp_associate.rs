use super::utils;

#[tokio::test]
#[ignore]
async fn test_socks5_udp_associate() {
    utils::init_tracing();

    let exit_status = utils::ExampleRunner::run("socks5_udp_associate").await;
    assert!(exit_status.success());
}
