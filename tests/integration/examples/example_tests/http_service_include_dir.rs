use super::utils;
use rama::{Context, http::BodyExtractExt};

const EXPECTED_FILE_CONTENT: &str = include_str!("../../../../test-files/index.html");

#[tokio::test]
// #[ignore]
async fn test_http_service_include_dir() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_service_include_dir", None);

    let file_content = runner
        .get("http://127.0.0.1:62037/test-files/index.html")
        .send(Context::default())
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();

    assert_eq!(EXPECTED_FILE_CONTENT, file_content);
}
