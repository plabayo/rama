use super::utils;
use rama::{
    http::body::util::BodyExt,
    http::headers::UserAgent,
    http::{BodyExtractExt, StatusCode},
};

const ADDRESS: &str = "127.0.0.1:62036";

#[tokio::test]
#[ignore]
async fn test_http_anti_bot_zip_bomb() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_anti_bot_zip_bomb", None);

    // test index
    {
        let req_uri = format!("http://{ADDRESS}");
        let response = runner.get(req_uri).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let homepage = response.try_into_string().await.unwrap();
        assert!(homepage.contains("<h1>Rates Catalogue</h1>"));
    }

    // test zip file as non-curl UA

    let real_file_content = {
        let req_uri = format!("http://{ADDRESS}/api/rates/2024.csv");
        let response = runner.get(req_uri).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let content = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!content.is_empty());
        content
    };

    // test zip file as curl UA
    {
        let req_uri = format!("http://{ADDRESS}/api/rates/2024.csv");
        let response = runner
            .get(req_uri)
            .typed_header(UserAgent::from_static("curl/42"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let zip_bomb = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!zip_bomb.is_empty());
        assert_ne!(zip_bomb, real_file_content);
    }
}
