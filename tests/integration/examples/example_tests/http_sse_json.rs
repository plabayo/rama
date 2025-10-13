use super::utils;

use rama::{
    futures::StreamExt,
    http::{
        BodyExtractExt, StatusCode,
        headers::{ContentType, HeaderMapExt},
        mime,
        sse::JsonEventData,
    },
};

use ahash::{HashSet, HashSetExt as _};
use serde::Deserialize;

#[tokio::test]
#[ignore]
async fn test_http_sse_json() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_sse_json", None);

    // basic html page sanity checks,
    // to at least give some basic guarantees for the human experience

    let index_response = runner.get("http://127.0.0.1:62028").send().await.unwrap();
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

    // test the atual stream content

    #[derive(Debug, Clone, Deserialize)]
    #[allow(dead_code)]
    struct OrderEvent {
        item: String,
        quantity: u32,
        prepaid: bool,
    }

    let mut unique_events = HashSet::new();
    let mut event_count = 0;
    let mut stream = runner
        .get("http://127.0.0.1:62028/api/events")
        .send()
        .await
        .unwrap()
        .into_body()
        .into_event_stream::<JsonEventData<OrderEvent>>();
    while let Some(result) = stream.next().await {
        let event = result.unwrap();
        let JsonEventData(order_event) = event.into_data().unwrap();
        assert!(!order_event.item.is_empty());
        unique_events.insert(order_event.item);
        event_count += 1;
    }
    assert_eq!(42, event_count);
    assert_eq!(21, unique_events.len());
}
