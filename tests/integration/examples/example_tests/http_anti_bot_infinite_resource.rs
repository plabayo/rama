use super::utils;
use rama::{
    http::body::util::BodyExt,
    http::client::EasyHttpWebClient,
    http::service::client::HttpClientExt,
    http::{BodyExtractExt, StatusCode, service::web::response::robots_txt::RobotsTxt},
};

const ADDRESS: &str = "127.0.0.1:62039";

#[tokio::test]
#[ignore]
async fn test_http_anti_bot_infinite_resource() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_anti_bot_infinite_resource", None);

    // test index
    {
        let req_uri = format!("http://{ADDRESS}");
        let response = runner.get(req_uri).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let homepage = response.try_into_string().await.unwrap();
        assert!(homepage.contains("<h1>Hello, Human!?</h1>"));
    }

    // test robots.txt
    {
        let req_uri = format!("http://{ADDRESS}/robots.txt");
        let response = runner.get(req_uri).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let robots_txt = response.try_into_string().await.unwrap();
        let robots = RobotsTxt::parse(&robots_txt);
        let rules = robots.rules_for("example-bot");

        assert!(!rules.is_allowed("/internal/"));
        assert!(!rules.is_allowed("/internal/clients.csv"));
        assert!(rules.is_allowed("/"));
    }

    // test infinite resource
    {
        let req_uri = format!("http://{ADDRESS}/internal/clients.csv?_test_limit=42");
        let response = runner.get(req_uri).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let fake_content = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!fake_content.is_empty());
    }

    // test that we are blocked now
    {
        let client = EasyHttpWebClient::default();
        let req_uri = format!("http://{ADDRESS}");
        assert!(client.get(req_uri).send().await.is_err());
    }
}
