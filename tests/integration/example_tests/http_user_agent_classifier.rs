use super::utils;
use rama::http::BodyExtractExt;
use rama::service::Context;
use rama::ua::{HttpAgent, TlsAgent, UserAgentOverwrites};

#[tokio::test]
#[ignore]
async fn test_http_user_agent_classifier() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_user_agent_classifier");

    #[derive(Debug, serde::Deserialize)]
    struct UserAgentInfo {
        ua: String,
        kind: Option<String>,
        version: Option<usize>,
        platform: Option<String>,
        http_agent: Option<String>,
        tls_agent: Option<String>,
    }

    let ua_rama: UserAgentInfo = runner
        .get("http://127.0.0.1:62015")
        .send(Context::default())
        .await
        .unwrap()
        .try_into_json()
        .await
        .unwrap();
    assert_eq!(
        ua_rama.ua,
        format!("{}/{}", rama::utils::info::NAME, rama::utils::info::VERSION)
    );
    assert_eq!(ua_rama.kind, None);
    assert_eq!(ua_rama.version, None);
    assert_eq!(ua_rama.platform, None);
    assert_eq!(ua_rama.http_agent, Some("Chromium".to_owned()));
    assert_eq!(ua_rama.tls_agent, Some("Rustls".to_owned()));

    const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67";

    let ua_chrome: UserAgentInfo = runner
        .get("http://127.0.0.1:62015")
        .typed_header(headers::UserAgent::from_static(UA))
        .send(Context::default())
        .await
        .unwrap()
        .try_into_json()
        .await
        .unwrap();
    assert_eq!(ua_chrome.ua, UA);
    assert_eq!(ua_chrome.kind, Some("Chromium".to_owned()));
    assert_eq!(ua_chrome.version, Some(124));
    assert_eq!(ua_chrome.platform, Some("Windows".to_owned()));
    assert_eq!(ua_chrome.http_agent, Some("Chromium".to_owned()));
    assert_eq!(ua_chrome.tls_agent, Some("Boringssl".to_owned()));

    const UA_APP: &str = "iPhone App/1.0";

    let ua_app: UserAgentInfo = runner
        .get("http://127.0.0.1:62015")
        .typed_header(headers::UserAgent::from_static(UA))
        .header(
            "x-proxy-ua",
            serde_html_form::to_string(&UserAgentOverwrites {
                ua: Some(UA_APP.to_owned()),
                http: Some(HttpAgent::Safari),
                tls: Some(TlsAgent::Boringssl),
                preserve_ua: Some(false),
            })
            .unwrap(),
        )
        .send(Context::default())
        .await
        .unwrap()
        .try_into_json()
        .await
        .unwrap();
    assert_eq!(ua_app.ua, UA_APP);
    assert!(ua_app.kind.is_none());
    assert!(ua_app.version.is_none());
    assert!(ua_app.platform.is_none());
    assert_eq!(ua_app.http_agent, Some("Safari".to_owned()));
    assert_eq!(ua_app.tls_agent, Some("Boringssl".to_owned()));
}
