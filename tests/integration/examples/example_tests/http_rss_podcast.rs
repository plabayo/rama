use super::utils;
use rama::http::{
    BodyExtractExt, StatusCode,
    headers::{ContentType, HeaderMapExt},
};

#[tokio::test]
#[ignore]
async fn test_http_rss_podcast() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_rss_podcast", None);

    // One-shot podcast feed
    let resp = runner
        .get("http://127.0.0.1:62051/podcast.rss")
        .send()
        .await
        .unwrap();
    assert_eq!(StatusCode::OK, resp.status());
    let ct = resp
        .headers()
        .typed_get::<ContentType>()
        .map(|ct| ct.mime().to_string())
        .unwrap_or_default();
    assert!(ct.contains("rss+xml"), "expected rss+xml, got {ct}");
    let body = resp.try_into_string().await.unwrap();
    assert!(body.contains("Netstack.FM"));
    assert!(body.contains("itunes:author"));
    assert!(body.contains("itunes:duration"));
    assert!(body.contains("itunes:episode"));
    assert!(body.contains("<enclosure"));
    assert!(body.contains("podcast:season"));
    assert!(body.contains("Episode 1"));
    assert!(body.contains("Episode 2"));
    assert!(body.contains("Episode 3"));

    // Streaming podcast feed — same content, different path
    let stream_resp = runner
        .get("http://127.0.0.1:62051/podcast-stream.rss")
        .send()
        .await
        .unwrap();
    assert_eq!(StatusCode::OK, stream_resp.status());
    let stream_ct = stream_resp
        .headers()
        .typed_get::<ContentType>()
        .map(|ct| ct.mime().to_string())
        .unwrap_or_default();
    assert!(stream_ct.contains("rss+xml"), "expected rss+xml, got {stream_ct}");
    let stream_body = stream_resp.try_into_string().await.unwrap();
    assert!(stream_body.contains("<rss"));
    assert!(stream_body.contains("<channel>"));
    assert!(stream_body.contains("Netstack.FM"));
    assert!(stream_body.contains("</channel>"));
    assert!(stream_body.contains("</rss>"));
}
