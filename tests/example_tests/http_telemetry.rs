use super::utils;
use rama::{http::BodyExtractExt, service::Context};

#[tokio::test]
#[ignore]
async fn test_http_prometheus() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_telemetry");

    let homepage = runner
        .get("http://127.0.0.1:62012")
        .send(Context::default())
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();
    assert!(homepage.contains("<h1>Hello!</h1>"));

    let metrics = runner
        .get("http://127.0.0.1:63012/metrics")
        .send(Context::default())
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();

    let counter_line = metrics
        .lines()
        .find(|line| line.starts_with("visitor_counter"))
        .unwrap();
    assert!(counter_line.starts_with("visitor_counter{"));
    assert!(counter_line.ends_with("} 1"));
}
