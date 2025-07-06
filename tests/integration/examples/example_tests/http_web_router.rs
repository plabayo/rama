use super::utils;
use rama::{
    Context,
    http::{BodyExtractExt, StatusCode},
};

const ADDRESS: &str = "127.0.0.1:62018";

#[tokio::test]
#[ignore]
async fn test_http_web_router() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_web_router", None);

    let req_uri = format!("http://{ADDRESS}");
    let response = runner.get(req_uri).send(Context::default()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let homepage = response.try_into_string().await.unwrap();
    assert!(homepage.contains("<h1>Rama - Web Router</h1>"));

    #[derive(serde::Deserialize)]
    struct Greet {
        method: String,
        message: String,
    }

    let req_uri = format!("http://{ADDRESS}/greet/world");
    let response = runner.post(req_uri).send(Context::default()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json: Greet = response.try_into_json().await.unwrap();
    assert_eq!(json.message, "Hello, world!");
    assert_eq!(json.method, "POST");

    #[derive(serde::Deserialize)]
    struct Lang {
        message: String,
    }

    let test_cases = [
        ("en", "Welcome to our site!"),
        ("fr", "Bienvenue sur notre site!"),
        ("es", "¡Bienvenido a nuestro sitio!"),
        ("de", "Language not supported"),
    ];

    for (code, expected_message) in test_cases.iter() {
        let req_uri = format!("http://{ADDRESS}/lang/{code}");
        let response = runner.get(req_uri).send(Context::default()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json: Lang = response.try_into_json().await.unwrap();
        assert_eq!(json.message, *expected_message);
    }

    #[derive(serde::Deserialize)]
    struct ApiStatus {
        status: String,
    }

    let test_cases = [
        ("/api/v1/status", "API v1 is up and running"),
        ("/api/v2/status", "API v2 is up and running"),
    ];

    for (path, expected_status) in test_cases.iter() {
        let req_uri = format!("http://{ADDRESS}{path}");
        let response = runner.get(req_uri).send(Context::default()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json: ApiStatus = response.try_into_json().await.unwrap();
        assert_eq!(json.status, *expected_status);
    }
}
