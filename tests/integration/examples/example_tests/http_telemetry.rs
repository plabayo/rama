use super::utils;
use rama::{Context, http::BodyExtractExt};

#[tokio::test]
#[ignore]
async fn test_http_telemetry() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_telemetry", Some("telemetry"));

    let homepage = runner
        .get("http://127.0.0.1:62012")
        .send(Context::default())
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();
    assert!(homepage.contains("<h1>Hello!</h1>"));
}
