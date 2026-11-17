use super::utils;

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_http_proxy_db_exclude_broken() {
    utils::init_tracing();

    let exit_status =
        utils::ExampleRunner::run(utils::example!("http_proxy_db_exclude_broken")).await;
    assert!(exit_status.success());
}
