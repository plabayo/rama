use super::utils;
use rama::http::{
    BodyExtractExt, StatusCode,
    headers::{ContentType, HeaderMapExt},
};

#[tokio::test]
#[ignore]
async fn test_http_rss_blog() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_rss_blog", None);

    // RSS 2.0 feed
    let rss_response = runner
        .get("http://127.0.0.1:62050/feed.rss")
        .send()
        .await
        .unwrap();
    assert_eq!(StatusCode::OK, rss_response.status());
    let rss_ct = rss_response
        .headers()
        .typed_get::<ContentType>()
        .map(|ct| ct.mime().to_string())
        .unwrap_or_default();
    assert!(
        rss_ct.contains("rss+xml"),
        "expected rss+xml content-type, got {rss_ct}"
    );
    let rss_body = rss_response.try_into_string().await.unwrap();
    assert!(rss_body.contains(r#"<rss version="2.0""#));
    assert!(rss_body.contains("<title>The Rama Blog</title>"));
    assert!(rss_body.contains("<item>"));
    assert!(rss_body.contains("Introducing Rama"));
    assert!(rss_body.contains("<content:encoded>"));

    // Atom feed
    let atom_response = runner
        .get("http://127.0.0.1:62050/feed.atom")
        .send()
        .await
        .unwrap();
    assert_eq!(StatusCode::OK, atom_response.status());
    let atom_ct = atom_response
        .headers()
        .typed_get::<ContentType>()
        .map(|ct| ct.mime().to_string())
        .unwrap_or_default();
    assert!(
        atom_ct.contains("atom+xml"),
        "expected atom+xml content-type, got {atom_ct}"
    );
    let atom_body = atom_response.try_into_string().await.unwrap();
    assert!(atom_body.contains(r#"xmlns="http://www.w3.org/2005/Atom""#));
    assert!(atom_body.contains("<entry>"));
    assert!(atom_body.contains("Introducing Rama"));
}
