use rama::{http::BodyExtractExt, service::Context};

mod utils;

#[tokio::test]
#[ignore]
async fn test_http_conn_state() {
    let runner = utils::ExampleRunner::interactive("http_conn_state");

    let response = runner
        .get("http://127.0.0.1:40000")
        .send(Context::default())
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();

    assert!(response.contains("Connection <code>1</code>"));
}
