use super::utils;
use rama::{http::BodyExtractExt, service::Context};

#[tokio::test]
#[ignore]
async fn test_tls_termination() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("tls_termination");

    let reply = runner
        .get("http://localhost:62800")
        .send(Context::default())
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();

    assert_eq!("Hello world!", reply);

    // TODO: test https proxy once http client supports https
}
