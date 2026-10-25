use super::*;
use rama::http::StatusCode;

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_http_conn_state() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive(utils::example!("http_k8s_health"));

    let response = runner
        .get("http://127.0.0.1:62005/k8s/ready")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, response.status())
}
