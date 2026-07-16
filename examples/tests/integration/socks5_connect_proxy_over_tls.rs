use super::utils;

#[tokio::test]
#[ignore]
async fn test_socks5_connect_proxy_over_tls() {
    utils::init_tracing();

    let exit_status = utils::ExampleRunner::run("socks5_connect_proxy_over_tls").await;
    assert!(exit_status.success());
}
