use super::utils;

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_http_high_level_client() {
    utils::init_tracing();

    let exit_status = utils::ExampleRunner::run(utils::example!("http_high_level_client")).await;
    assert!(exit_status.success());
}
