use super::utils;
use rama::http::BodyExtractExt;

const EXPECTED_FILE_CONTENT: &str = include_str!("../../../test-files/index.html");

#[tokio::test]
#[ignore]
async fn test_http_service_include_dir() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive(utils::example!("http_service_include_dir"));

    let file_content = runner
        .get("http://127.0.0.1:62037")
        .send()
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();

    assert_eq!(EXPECTED_FILE_CONTENT, file_content);
}
