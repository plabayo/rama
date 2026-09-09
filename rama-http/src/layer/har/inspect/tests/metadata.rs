use rama_core::{Layer, Service, service::service_fn};

use super::*;
use crate::{
    Body, Request, Response,
    body::util::BodyExt,
    inspect::capture::{CaptureConfig, CaptureHttpLayer, CaptureStore},
};

#[test]
fn captured_har_time_and_size_conversions_are_bounded() {
    let start = "2026-08-23T12:00:00Z".parse().unwrap();
    let end = "2026-08-23T12:00:00.125Z".parse().unwrap();

    assert_eq!(elapsed_millis(start, end), 125);
    assert_eq!(elapsed_millis(end, start), 0);
    assert_eq!(byte_count(42), 42);
    assert_eq!(byte_count(u64::MAX), i64::MAX);
}

#[tokio::test]
async fn captured_har_entry_preserves_observed_timing_and_byte_totals() {
    let store = CaptureStore::with_storage(
        Storage::new(MemoryStore::new(Default::default())),
        CaptureConfig::default(),
        Default::default(),
    );
    let service =
        CaptureHttpLayer::new(Some(store.clone())).layer(service_fn(async |request: Request| {
            request.into_body().collect().await.unwrap();
            Ok::<_, Infallible>(Response::builder().status(201).body(Body::empty()).unwrap())
        }));
    service
        .serve(
            Request::builder()
                .method("POST")
                .uri("https://example.test/upload")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("a=b&c=hello+world"))
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    let mut details = store.details(1).await.unwrap();
    details.summary.started_at = "2026-08-23T12:00:00Z".parse().unwrap();
    details.summary.response_started_at = Some("2026-08-23T12:00:00.125Z".parse().unwrap());
    details.summary.completed_at = Some("2026-08-23T12:00:00.375Z".parse().unwrap());
    details.summary.request_bytes = 42;
    details.summary.response_bytes = 84;
    let entry = entry_metadata(details, 17, 0).unwrap();

    assert_eq!(entry.time, 375);
    assert_eq!(entry.timings.send, 0);
    assert_eq!(entry.timings.wait, 125);
    assert_eq!(entry.timings.receive, 250);
    assert_eq!(entry.request.body_size, 42);
    assert_eq!(entry.response.body_size, 84);
    assert_eq!(entry.response.content.size, 84);
}
