use super::utils;
use rama::http::BodyExtractExt;
use rama::service::Context;

#[tokio::test]
#[ignore]
async fn test_http_user_agent_classifier() {
    let runner = utils::ExampleRunner::interactive("http_user_agent_classifier");

    #[derive(Debug, serde::Deserialize)]
    struct UserAgentInfo {
        ua: String,
        kind: Option<String>,
        version: Option<usize>,
        platform: Option<String>,
    }

    let ua_rama: UserAgentInfo = runner
        .get("http://127.0.0.1:40015")
        .send(Context::default())
        .await
        .unwrap()
        .try_into_json()
        .await
        .unwrap();
    assert_eq!(
        ua_rama.ua,
        format!("{}/{}", rama::info::NAME, rama::info::VERSION)
    );
    assert_eq!(ua_rama.kind, None);
    assert_eq!(ua_rama.version, None);
    assert_eq!(ua_rama.platform, None);

    const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67";

    let ua_chrome: UserAgentInfo = runner
        .get("http://127.0.0.1:40015")
        .typed_header(headers::UserAgent::from_static(UA))
        .send(Context::default())
        .await
        .unwrap()
        .try_into_json()
        .await
        .unwrap();
    assert_eq!(ua_chrome.ua, UA);
    assert_eq!(ua_chrome.kind, Some("chromium".to_string()));
    assert_eq!(ua_chrome.version, Some(124));
    assert_eq!(ua_chrome.platform, Some("windows".to_string()));
}
