use super::utils;
use rama::{http::BodyExtractExt, Context};

#[tokio::test]
#[ignore]
async fn test_tls_termination() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("tls_termination");

    // We do not test the direct http service, it's end-to-end anyway,
    // but mostly because otherwise we need to fake the Forwarding stuff (HaProxy) as well.

    let reply = runner
        .get("https://127.0.0.1:63800")
        .send(Context::default())
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();

    assert!(reply.starts_with("hello client"));
    assert!(reply.contains("you were served by tls terminator proxy"));
}
