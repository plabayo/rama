use super::*;
use rama::{Context, http::StatusCode};

#[tokio::test]
#[ignore]
async fn test_http_conn_state() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_k8s_health", None);

    let response = runner
        .get("http://127.0.0.1:62005/k8s/ready")
        .send(Context::default())
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, response.status())
}
