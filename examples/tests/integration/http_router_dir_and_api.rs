use super::utils;
use rama::http::{BodyExtractExt, StatusCode, header::ACCEPT};

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_http_router_dir_and_api() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive(utils::example!("http_router_dir_and_api"));

    // test index.html via directory service
    let response = runner.get("http://127.0.0.1:12013").send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let homepage = response.try_into_string().await.unwrap();
    assert!(homepage.contains("<h1>Coin Clicker</h1>"));

    // test redirect
    let response = runner
        .get("http://127.0.0.1:12013/foo/bar")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let error_page = response.try_into_string().await.unwrap();
    assert!(error_page.contains("<h1>Not Found (404)</h1>"));

    // test coin fetching
    let response = runner
        .get("http://127.0.0.1:12013/coin")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let coin_page = response.try_into_string().await.unwrap();
    assert!(coin_page.contains(r#"<h1 id="coinCount">0</h1>"#));

    // test coin post
    let response = runner
        .post("http://127.0.0.1:12013/coin")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let coin_page = response.try_into_string().await.unwrap();
    assert!(coin_page.contains(r#"<h1 id="coinCount">1</h1>"#));

    // test coin fetching (again)
    let response = runner
        .get("http://127.0.0.1:12013/coin")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let coin_page = response.try_into_string().await.unwrap();
    assert!(coin_page.contains(r#"<h1 id="coinCount">1</h1>"#));

    // test the nested api router
    let response = runner
        .get("http://127.0.0.1:12013/api/coins")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let coins: serde_json::Value = response.try_into_json().await.unwrap();
    assert_eq!(coins["coins"], 1);

    // test the path-less json not-found matcher
    let response = runner
        .get("http://127.0.0.1:12013/foo/bar")
        .header(ACCEPT, "application/json")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let error: serde_json::Value = response.try_into_json().await.unwrap();
    assert_eq!(error["error"], "not found");
}
