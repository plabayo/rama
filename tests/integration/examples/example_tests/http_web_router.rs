use super::utils;
use rama::http::headers::{HeaderMapExt, Location};
use rama::http::service::client::HttpClientExt as _;
use rama::http::{BodyExtractExt, StatusCode, client::EasyHttpWebClient};

const ADDRESS: &str = "127.0.0.1:62018";

#[tokio::test]
#[ignore]
async fn test_http_web_router() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_web_router", None);

    let req_uri = format!("http://{ADDRESS}");
    let response = runner.get(req_uri).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let homepage = response.try_into_string().await.unwrap();
    assert!(homepage.contains("<h1>Rama - Web Router</h1>"));

    #[derive(serde::Deserialize)]
    struct Greet {
        method: String,
        message: String,
    }

    let req_uri = format!("http://{ADDRESS}/greet/world");
    let response = runner.post(req_uri).send().await.unwrap();
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

    // new endpoint
    for (code, expected_message) in test_cases.iter() {
        let req_uri = format!("http://{ADDRESS}/lang/{code}");
        let response = runner.get(req_uri).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json: Lang = response.try_into_json().await.unwrap();
        assert_eq!(json.message, *expected_message);
    }

    // old (redirected) endpoint
    for (code, expected_message) in test_cases.iter() {
        let req_uri = format!("http://{ADDRESS}/greet?lang={code}");
        let response = runner.get(req_uri).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json: Lang = response.try_into_json().await.unwrap();
        assert_eq!(json.message, *expected_message);
    }

    #[derive(serde::Deserialize)]
    struct ApiStatus {
        status: String,
    }

    let test_cases = [
        ("/api/v1/status", "API v2 is up and running"), // redirected :)
        ("/api/v2/status", "API v2 is up and running"),
    ];

    for (path, expected_status) in test_cases.iter() {
        let req_uri = format!("http://{ADDRESS}{path}");
        let response = runner.get(req_uri).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json: ApiStatus = response.try_into_json().await.unwrap();
        assert_eq!(json.status, *expected_status);
    }

    // test redirects

    let test_cases = [
        ("/greet?lang=en", "/lang/en"),
        ("/greet?lang=fr", "/lang/fr"),
        ("/greet?lang=es", "/lang/es"),
        ("/api/v1/status", "/api/v2/status"),
    ];

    for (path, expected_redirect_path) in test_cases.iter() {
        let req_uri = format!("http://{ADDRESS}{path}");
        let response = EasyHttpWebClient::default()
            .get(req_uri)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        let loc: Location = response.headers().typed_get::<Location>().unwrap();
        assert!(
            loc.to_str()
                .unwrap()
                .trim_end_matches('/')
                .ends_with(expected_redirect_path)
        );
    }
}
