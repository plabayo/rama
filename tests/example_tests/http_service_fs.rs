use rama::{http::BodyExtractExt, service::Context};
use super::utils;

const EXPECTED_FILE_CONTENT: &str = include_str!("../../test-files/index.html");

#[tokio::test]
#[ignore]
async fn test_http_service_fs() {
    let runner = utils::ExampleRunner::interactive("http_service_fs");

    let file_content = runner
        .get("http://localhost:40009/test-files/index.html")
        .send(Context::default())
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();

    assert_eq!(EXPECTED_FILE_CONTENT, file_content);
}
