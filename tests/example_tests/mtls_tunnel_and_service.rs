use super::utils;
use rama::http::layer::retry::managed::DoNotRetry;
use rama::http::BodyExtractExt;
use rama::service::Context;

#[tokio::test]
#[ignore]
async fn test_mtls_tunnel_and_service() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("mtls_tunnel_and_service");

    let res_str = runner
        .get("http://127.0.0.1:62014/hello")
        .send(Context::default())
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();

    assert_eq!(res_str, "<h1>Hello, authorized client!</h1>");

    let mut ctx = Context::default();
    ctx.insert(DoNotRetry::default());
    let err = runner
        .get("https://127.0.0.1:63014/hello")
        .send(ctx)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("https://127.0.0.1:63014/hello"));
}
