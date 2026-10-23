use super::utils;
use rama::http::BodyExtractExt;

const EXPECTED_FILE_CONTENT: &str = include_str!("../../../examples/src/tcp_listener_hello.rs");

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_tcp_listener_hello() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive(utils::example!("tcp_listener_hello"));

    let file_content = runner
        .get("http://127.0.0.1:62500")
        .send()
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();

    assert_eq!(EXPECTED_FILE_CONTENT, file_content);
}
