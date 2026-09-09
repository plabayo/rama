use std::{fmt, sync::atomic::AtomicUsize};

use rama::{
    futures::FutureExt as _,
    http::{Method, header},
};
use serde::{Serialize, Serializer, ser::SerializeSeq as _};
use tokio::sync::oneshot;

use super::streaming::JSON_BUFFER_SIZE;
use super::*;
use crate::cmd::serve::proxy::dashboard_auth::DashboardAuthService;

fn request(method: Method, uri: &str, body: &serde_json::Value) -> Request {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, "127.0.0.1:8080")
        .header(header::AUTHORIZATION, "Bearer api-test-token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

async fn json(response: Response) -> serde_json::Value {
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn machine_api_uses_startup_capability_without_a_browser_session() {
    let state = crate::cmd::serve::proxy::dashboard::tests::test_state();
    let service = DashboardAuthService::new(
        crate::cmd::serve::proxy::dashboard::service(state.clone()),
        Arc::from("api-test-token"),
    );
    let mut unauthorized = request(Method::GET, "/api", &serde_json::Value::Null);
    unauthorized.headers_mut().remove(header::AUTHORIZATION);
    assert_eq!(
        service.serve(unauthorized).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let mut foreign = request(Method::GET, "/api/control", &serde_json::Value::Null);
    foreign
        .headers_mut()
        .insert(header::ORIGIN, "http://untrusted.example".parse().unwrap());
    assert_eq!(
        service.serve(foreign).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let discovery = json(
        service
            .serve(request(Method::GET, "/api", &serde_json::Value::Null))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(discovery["version"], 1);
    let initial = json(
        service
            .serve(request(
                Method::GET,
                "/api/control",
                &serde_json::Value::Null,
            ))
            .await
            .unwrap(),
    )
    .await;
    let mut config = initial["control"]["config"].clone();
    config["enabled"] = true.into();
    let response = service
        .serve(request(
            Method::POST,
            "/api/control/config",
            &serde_json::json!({"revision":initial["control"]["revision"], "config":config}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = service
        .serve(request(
            Method::POST,
            "/api/mitm-policy",
            &serde_json::json!({"mode":"selected", "allow":["example.com"], "deny":[]}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        json(
            service
                .serve(request(
                    Method::GET,
                    "/api/control",
                    &serde_json::Value::Null
                ))
                .await
                .unwrap()
        )
        .await["scope"]["mode"],
        "selected"
    );
    let response = service
        .serve(request(
            Method::POST,
            "/api/inspection/pause",
            &serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(!state.inspection.is_enabled());
    let response = service
        .serve(request(
            Method::POST,
            "/api/inspection/resume",
            &serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(state.inspection.is_enabled());
    assert!(state.sessions.read().is_empty());
    let response = service
        .serve(request(
            Method::GET,
            "/api/control?session=missing",
            &serde_json::Value::Null,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn capture_listing_stream_and_exports_share_the_same_capture() {
    let state = crate::cmd::serve::proxy::dashboard::tests::test_state();
    crate::cmd::serve::proxy::dashboard::tests::capture_request_for_replay(
        &state,
        "http://example.test/action",
    )
    .await;
    let service = DashboardAuthService::new(
        crate::cmd::serve::proxy::dashboard::service(state.clone()),
        Arc::from("api-test-token"),
    );
    let view = json(
        service
            .serve(request(
                Method::GET,
                "/api/captures?endpoint=example.test",
                &serde_json::Value::Null,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(view["exchanges"].as_array().unwrap().len(), 1);
    let id = view["exchanges"][0]["id"].as_u64().unwrap();
    let removed = service
        .serve(request(
            Method::GET,
            &format!("/api/capture/{id}.json"),
            &serde_json::Value::Null,
        ))
        .await
        .unwrap();
    assert_eq!(removed.status(), StatusCode::NOT_FOUND);
    let export = json(
        service
            .serve(request(
                Method::GET,
                &format!("/api/har/export?ids={id}"),
                &serde_json::Value::Null,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(export["log"]["entries"].as_array().unwrap().len(), 1);
    let response = service
        .serve(request(
            Method::GET,
            "/api/captures/events",
            &serde_json::Value::Null,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let bytes = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut bytes = Vec::new();
        while bytes.last() != Some(&b'\n') {
            bytes.extend_from_slice(&body.frame().await.unwrap().unwrap().into_data().unwrap());
        }
        bytes
    })
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["exchanges"][0]["id"],
        id
    );
    assert_eq!(
        state.event_streams.available_permits(),
        MAX_UI_EVENT_STREAMS - 1
    );
    drop(body);
    assert_eq!(
        state.event_streams.available_permits(),
        MAX_UI_EVENT_STREAMS
    );
}

struct GeneratedNumbers(usize);

impl Serialize for GeneratedNumbers {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0))?;
        for number in 0..self.0 {
            sequence.serialize_element(&number)?;
        }
        sequence.end()
    }
}

#[tokio::test]
async fn json_and_ndjson_preserve_typed_values_across_bounded_chunks() {
    for newline in [false, true] {
        let mut body = Body::from_stream(json_bytes(GeneratedNumbers(16_384), newline));
        let mut encoded = Vec::new();
        let mut chunks = 0;
        while let Some(frame) = body.frame().await {
            let bytes = frame.unwrap().into_data().unwrap();
            assert!(bytes.len() <= JSON_BUFFER_SIZE);
            encoded.extend_from_slice(&bytes);
            chunks += 1;
        }
        assert!(chunks > 1);
        assert_eq!(encoded.last() == Some(&b'\n'), newline);
        let values: Vec<usize> = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(values.len(), 16_384);
        assert!(
            values
                .into_iter()
                .enumerate()
                .all(|(index, value)| index == value)
        );
    }
}

struct GeneratedText {
    repeats: usize,
    produced: Arc<AtomicUsize>,
    dropped: Option<oneshot::Sender<()>>,
}

impl Serialize for GeneratedText {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl fmt::Display for GeneratedText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for _ in 0..self.repeats {
            self.produced.fetch_add(1, Ordering::Relaxed);
            formatter.write_str("0123456789abcdef")?;
        }
        Ok(())
    }
}

impl Drop for GeneratedText {
    fn drop(&mut self) {
        if let Some(dropped) = self.dropped.take() {
            _ = dropped.send(());
        }
    }
}

#[tokio::test]
async fn a_large_generated_json_string_never_requires_a_large_output_chunk() {
    let mut body = Body::from_stream(json_bytes(
        GeneratedText {
            repeats: mib(1),
            produced: Arc::new(AtomicUsize::new(0)),
            dropped: None,
        },
        false,
    ));
    let mut length = 0;
    while let Some(frame) = body.frame().await {
        let bytes = frame.unwrap().into_data().unwrap();
        assert!(bytes.len() <= JSON_BUFFER_SIZE);
        length += bytes.len();
    }
    assert_eq!(length, mib(16) + 2);
}

#[tokio::test]
async fn json_serialization_is_lazy_and_client_drop_releases_its_input() {
    for poll in [false, true] {
        let produced = Arc::new(AtomicUsize::new(0));
        let (dropped, released) = oneshot::channel();
        let mut body = Body::from_stream(json_bytes(
            GeneratedText {
                repeats: mib(1),
                produced: produced.clone(),
                dropped: Some(dropped),
            },
            false,
        ));
        assert_eq!(produced.load(Ordering::Relaxed), 0);
        if poll {
            body.frame().await.unwrap().unwrap();
        }
        drop(body);
        tokio::time::timeout(Duration::from_secs(2), released)
            .await
            .unwrap()
            .unwrap();
        let produced = produced.load(Ordering::Relaxed);
        if poll {
            assert!(produced > 0);
            // The pending writer, pipe and yielded chunk cannot consume the rest
            // of the 16 MiB generated value after a reader stops polling.
            assert!(produced <= JSON_BUFFER_SIZE * 4 / 16 + 1);
        } else {
            assert_eq!(produced, 0);
        }
    }
}

#[test]
fn dropping_a_json_body_cancels_serialization_queued_on_the_blocking_pool() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    let (entered, started) = oneshot::channel();
    let (release, wait) = oneshot::channel();
    let blocker = runtime.spawn_blocking(move || {
        _ = entered.send(());
        _ = wait.blocking_recv();
    });
    runtime.block_on(async move {
        started.await.unwrap();
        let produced = Arc::new(AtomicUsize::new(0));
        let (dropped, released) = oneshot::channel();
        let mut body = Body::from_stream(json_bytes(
            GeneratedText {
                repeats: mib(1),
                produced: produced.clone(),
                dropped: Some(dropped),
            },
            false,
        ));
        assert!(body.frame().now_or_never().is_none());
        drop(body);
        release.send(()).unwrap();
        blocker.await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), released)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(produced.load(Ordering::Relaxed), 0);
    });
}

struct FailingValue {
    panic: bool,
}

impl Serialize for FailingValue {
    fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        assert!(!self.panic, "inspector serialization task panicked");
        Err(serde::ser::Error::custom("inspector serialization failed"))
    }
}

#[tokio::test]
async fn json_serialization_and_task_errors_reach_the_response_body() {
    for panic in [false, true] {
        let body = Body::from_stream(json_bytes(FailingValue { panic }, false));
        let error = body.collect().await.unwrap_err();
        let message = format!("{error:?}");
        assert!(message.contains(if panic {
            "join inspector JSON writer"
        } else {
            "serialize inspector view"
        }));
    }
}
