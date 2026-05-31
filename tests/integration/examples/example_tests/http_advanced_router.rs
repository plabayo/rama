use super::utils;
use rama::http::{BodyExtractExt, StatusCode};

const ADDRESS: &str = "127.0.0.1:62031";

#[tokio::test]
#[ignore]
async fn test_http_advanced_router() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_advanced_router", None);

    let resp = runner
        .get(format!("http://{ADDRESS}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.try_into_string().await.unwrap();
    assert!(body.contains("<h1>Advanced Router</h1>"));

    let resp = runner
        .get(format!("http://{ADDRESS}/api/v2/greet?name=Jane"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let envelope: SignedGreet = resp.try_into_json().await.unwrap();
    assert_eq!(envelope.data.text, "Hello Jane!");
    assert_eq!(envelope.signature, "signed by secret key");

    let resp = runner
        .get(format!("http://{ADDRESS}/api/v2/greet?name=John"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: AppErr = resp.try_into_json().await.unwrap();
    assert!(body.error);
    assert_eq!(body.key, "ban");

    // rate-limit: first call ok, second call 429
    let resp = runner
        .get(format!("http://{ADDRESS}/api/v2/greet?name=Mike"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = runner
        .get(format!("http://{ADDRESS}/api/v2/greet?name=Mike"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let body: AppErr = resp.try_into_json().await.unwrap();
    assert_eq!(body.key, "rate_limit");
}

#[derive(serde::Deserialize)]
struct SignedGreet {
    data: GreetData,
    signature: String,
}

#[derive(serde::Deserialize)]
struct GreetData {
    text: String,
}

#[derive(serde::Deserialize)]
struct AppErr {
    error: bool,
    key: String,
}
