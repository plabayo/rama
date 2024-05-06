use rama::{http::StatusCode, service::Context};

mod utils;

#[tokio::test]
#[ignore]
async fn test_http_conn_state() {
    let runner = utils::ExampleRunner::interactive("http_health_check");

    let response = runner
        .get("http://127.0.0.1:40003")
        .send(Context::default())
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, response.status())
}
