use super::utils;

#[tokio::test]
#[ignore]
async fn test_socks5_bind_proxy() {
    utils::init_tracing();

    let exit_status = utils::ExampleRunner::run("socks5_bind_proxy").await;
    assert!(exit_status.success());
}
