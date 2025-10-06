use super::utils;
use rama::http::{BodyExtractExt, StatusCode};

const ADDRESS: &str = "127.0.0.1:62020";

#[tokio::test]
#[ignore]
async fn test_http_rama_tower() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_rama_tower", Some("tower"));

    let req_uri = format!("http://{ADDRESS}");
    let response = runner.get(req_uri).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let homepage = response.try_into_string().await.unwrap();
    assert!(homepage.contains("Rama"));
    assert!(homepage.contains("Tower"));
}
