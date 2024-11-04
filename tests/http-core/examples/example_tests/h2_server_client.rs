use super::utils;

#[tokio::test]
#[ignore]
async fn test_h2_server_client() {
    utils::init_tracing();

    let _guard = utils::ExampleRunner::run_background("h2_server", None);
    let exit_status = utils::ExampleRunner::run("h2_client");

    assert!(exit_status.success());
}
