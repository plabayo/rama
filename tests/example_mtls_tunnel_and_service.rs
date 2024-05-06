use rama::http::BodyExtractExt;
use rama::service::Context;

mod utils;

#[tokio::test]
#[ignore]
async fn test_mtls_tunnel_and_service() {
    let runner = utils::ExampleRunner::interactive("mtls_tunnel_and_service");

    // TODO: once http client supports https,
    // test we cannot go directly to http://127.0.0.1:41013

    let res_str = runner
        .get("http://127.0.0.1:40014/hello")
        .send(Context::default())
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();

    assert_eq!(res_str, "<h1>Hello, authorized client!</h1>");
}
