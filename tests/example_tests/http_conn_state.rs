use super::utils;
use rama::{
    http::{BodyExtractExt, StatusCode},
    service::Context,
};

#[tokio::test]
#[ignore]
async fn test_http_conn_state() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_conn_state");

    let response = runner
        .get("http://127.0.0.1:62000")
        .send(Context::default())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.try_into_string().await.unwrap();
    assert!(body.contains("Connection <code>1</code>"));
}
