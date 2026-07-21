use rama::http::BodyExtractExt;

use super::utils;

#[tokio::test]
#[ignore]
async fn test_http_js_middleware() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_js_middleware", Some("js"));
    let response = runner
        .post("http://127.0.0.1:62059/api/launch")
        .send()
        .await
        .unwrap();

    assert_eq!(response.headers()["x-rama-script"], "active");
    assert_eq!(
        response.try_into_string().await.unwrap(),
        "JavaScript routed this request as api:post\n",
    );
}
