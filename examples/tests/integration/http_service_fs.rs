use super::utils;
use rama::http::BodyExtractExt;

const EXPECTED_FILE_CONTENT: &str = include_str!("../../../test-files/index.html");

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_http_service_fs() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive(utils::example!("http_service_fs"));

    let file_content = runner
        .get("http://127.0.0.1:62009/test-files/index.html")
        .send()
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();

    assert_eq!(EXPECTED_FILE_CONTENT, file_content);
}
