use super::utils;
use rama::{
    http::{BodyExtractExt, StatusCode},
    service::Context,
};

#[tokio::test]
#[ignore]
async fn test_http_web_service_dir_and_api() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_web_service_dir_and_api");

    // test index.html via directory service
    let response = runner
        .get("http://127.0.0.1:62013")
        .send(Context::default())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let homepage = response.try_into_string().await.unwrap();
    assert!(homepage.contains("<h1>Coin Clicker</h1>"));

    // test redirect
    let response = runner
        .get("http://127.0.0.1:62013/foo/bar")
        .send(Context::default())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let error_page = response.try_into_string().await.unwrap();
    assert!(error_page.contains("<h1>Not Found (404)</h1>"));

    // test coin fetching
    let response = runner
        .get("http://127.0.0.1:62013/coin")
        .send(Context::default())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let coin_page = response.try_into_string().await.unwrap();
    assert!(coin_page.contains(r#"<h1 id="coinCount">0</h1>"#));

    // test coin post
    let response = runner
        .post("http://127.0.0.1:62013/coin")
        .send(Context::default())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let coin_page = response.try_into_string().await.unwrap();
    assert!(coin_page.contains(r#"<h1 id="coinCount">1</h1>"#));

    // test coin fetching (again)
    let response = runner
        .get("http://127.0.0.1:62013/coin")
        .send(Context::default())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let coin_page = response.try_into_string().await.unwrap();
    assert!(coin_page.contains(r#"<h1 id="coinCount">1</h1>"#));
}
