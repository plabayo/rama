use rama::http::{StatusCode, layer::retry::managed::DoNotRetry};

use super::utils;

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_http_abort() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive(utils::example!("http_abort"));

    assert_eq!(
        StatusCode::OK,
        runner
            .get("http://127.0.0.1:62047")
            .send()
            .await
            .unwrap()
            .status()
    );

    runner
        .get("http://127.0.0.1:62047/abort")
        .extension(DoNotRetry::default())
        .send()
        .await
        .unwrap_err();
}
