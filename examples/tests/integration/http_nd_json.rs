use super::utils;

use rama::{
    futures::StreamExt,
    http::{
        StatusCode,
        headers::{ContentType, HeaderMapExt},
    },
};

use ahash::{HashSet, HashSetExt as _};
use serde::Deserialize;

#[tokio::test]
#[ignore]
async fn test_http_nd_json() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_nd_json", None);

    #[derive(Debug, Clone, Deserialize)]
    #[allow(dead_code)]
    struct OrderEvent {
        item: String,
        quantity: u32,
        prepaid: bool,
    }

    let mut unique_events = HashSet::new();
    let mut event_count = 0;
    let response = runner
        .get("http://127.0.0.1:62041/orders")
        .send()
        .await
        .unwrap();

    assert_eq!(StatusCode::OK, response.status());
    assert!(
        response
            .headers()
            .typed_get::<ContentType>()
            .map(|ct| ct.eq(&ContentType::ndjson()))
            .unwrap_or_default()
    );

    let mut stream = response.into_body().into_json_stream::<OrderEvent>();
    while let Some(result) = stream.next().await {
        let order_event = result.unwrap();
        assert!(!order_event.item.is_empty());
        unique_events.insert(order_event.item);
        event_count += 1;
    }
    assert_eq!(28, event_count);
    assert_eq!(22, unique_events.len());
}
