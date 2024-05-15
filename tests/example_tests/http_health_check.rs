use super::utils;
use rama::{http::StatusCode, service::Context};

#[tokio::test]
#[ignore]
async fn test_http_conn_state() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_health_check");

    let response = runner
        .get("http://127.0.0.1:62003")
        .send(Context::default())
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, response.status())
}
