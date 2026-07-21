use super::utils;
use ahash::{HashSet, HashSetExt as _};
use rama::{
    futures::StreamExt,
    http::{
        BodyExtractExt, StatusCode,
        headers::{ContentType, HeaderMapExt},
        mime,
    },
};

#[tokio::test]
#[ignore]
async fn test_http_sse() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_sse", None);

    // basic html page sanity checks,
    // to at least give some basic guarantees for the human experience

    let index_response = runner.get("http://127.0.0.1:62027").send().await.unwrap();
    assert_eq!(StatusCode::OK, index_response.status());
    assert!(
        index_response
            .headers()
            .typed_get::<ContentType>()
            .map(|ct| ct.mime().eq(&mime::TEXT_HTML_UTF_8))
            .unwrap_or_default()
    );
    let index_content = index_response.try_into_string().await.unwrap();
    assert!(index_content.contains("new EventSource('/api/events')"));

    // test the actual stream content

    let mut unique_events = HashSet::new();
    let mut event_count = 0;
    let mut stream = runner
        .get("http://127.0.0.1:62027/api/events")
        .send()
        .await
        .unwrap()
        .into_body()
        .into_string_data_event_stream();
    while let Some(result) = stream.next().await {
        let event = result.unwrap();
        let message = event.into_data().unwrap();
        assert!(!message.is_empty());
        unique_events.insert(message);
        event_count += 1;
    }
    assert_eq!(42, event_count);
    assert_eq!(17, unique_events.len());
}
