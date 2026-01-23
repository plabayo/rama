use rama::http::StatusCode;

use super::utils;

#[tokio::test]
#[ignore]
async fn test_http_abort() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_abort", None);

    assert_eq!(
        StatusCode::OK,
        runner
            .get("http://127.0.0.1:62047")
            .send()
            .await
            .unwrap()
            .status()
    );

    assert!(
        runner
            .get("http://127.0.0.1:62047/abort")
            .send()
            .await
            .is_err()
    );
}
