use super::utils;
use rama::{http::BodyExtractExt, service::Context};

const ADDRESS: &str = "127.0.0.1:62011";

#[tokio::test]
#[ignore]
async fn test_http_service_match() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_service_match");

    let homepage = runner
        .get(format!("http://{ADDRESS}"))
        .send(Context::default())
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();
    assert!(homepage.contains("<h1>Home</h1>"));

    #[derive(serde::Deserialize)]
    struct Echo {
        method: String,
        path: String,
    }

    let echo: Echo = runner
        .post(format!("http://{ADDRESS}/echo"))
        .send(Context::default())
        .await
        .unwrap()
        .try_into_json()
        .await
        .unwrap();

    assert_eq!(echo.method, "POST");
    assert_eq!(echo.path, "/echo");
}
