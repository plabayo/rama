use super::utils;

#[tokio::test]
#[ignore]
async fn test_socks5_udp_associate_framed() {
    utils::init_tracing();

    let exit_status = utils::ExampleRunner::run("socks5_udp_associate_framed").await;
    assert!(exit_status.success());
}
