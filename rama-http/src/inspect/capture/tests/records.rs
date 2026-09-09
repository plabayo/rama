use rama_net::{
    address::HostWithOptPort,
    forwarded::{Forwarded, ForwardedElement},
};

use super::*;

#[tokio::test]
async fn captured_headers_and_bodies_round_trip_through_storage() {
    let store = test_store();
    let request = Request::builder()
        .method("POST")
        .uri("http://example.test/private")
        .header("authorization", "Bearer secret-value")
        .body(Body::from("private-payload"))
        .unwrap();
    let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(
        rama_core::service::service_fn(async |_request: Request| {
            Ok::<_, Infallible>(Response::new(Body::from("private-response")))
        }),
    );
    let response = service.serve(request).await.unwrap();
    response.into_body().collect().await.unwrap();

    let details = store.details(1).await.unwrap();
    assert_eq!(
        details.summary.status,
        Some(StatusCode::from_u16(200).unwrap())
    );
    assert!(details.records.iter().any(|record| matches!(
        record,
        StoredRecord::ResponseBody { data } if data.as_ref() == b"private-response"
    )));
}

#[tokio::test]
async fn replay_reconstructs_relative_url_headers_and_captured_body() {
    let store = test_store();
    let request = Request::builder()
        .method("PATCH")
        .uri("/resource")
        .header("host", "example.test:8080")
        .header("x-replay", "yes")
        .extension(Forwarded::new(ForwardedElement::new_forwarded_host(
            "routing.example:443".parse::<HostWithOptPort>().unwrap(),
        )))
        .body(Body::from("patch-body"))
        .unwrap();
    let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(
        rama_core::service::service_fn(async |request: Request| {
            request.into_body().collect().await.unwrap();
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }),
    );
    service
        .serve(request)
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();

    let replay = store.replay_request(1).await.unwrap();
    assert_eq!(replay.method, "PATCH");
    assert_eq!(
        replay.url,
        "http://example.test:8080/resource".parse().unwrap()
    );
    let mut body = Vec::new();
    replay.body.reader().read_to_end(&mut body).await.unwrap();
    assert_eq!(body, b"patch-body");
    assert!(
        replay
            .headers
            .iter()
            .any(|(name, value)| name == "x-replay" && value == "yes")
    );
}

#[tokio::test]
async fn replay_requires_one_complete_request_end_on_an_inactive_exchange() {
    let store = test_store_with_limits(8, 8, rama_utils::octets::kib_u64(1));
    let request_parts = |path: &str| {
        Request::builder()
            .uri(format!("http://example.test/{path}"))
            .body(Body::empty())
            .unwrap()
            .into_parts()
            .0
    };

    let active = store
        .begin_exchange(&request_parts("active"))
        .await
        .unwrap()
        .unwrap();
    store
        .body_event(
            active,
            BodyDirection::Request,
            BodyCaptureEvent::End(CaptureOutcome::Complete),
        )
        .await;
    assert!(
        store
            .replay_request(active)
            .await
            .unwrap_err()
            .to_string()
            .contains("active")
    );

    for (path, outcome, expected) in [
        ("aborted", CaptureOutcome::Aborted, "aborted"),
        ("error", CaptureOutcome::Error, "error"),
    ] {
        let id = store
            .begin_exchange(&request_parts(path))
            .await
            .unwrap()
            .unwrap();
        store
            .body_event(id, BodyDirection::Request, BodyCaptureEvent::End(outcome))
            .await;
        store
            .body_event(
                id,
                BodyDirection::Response,
                BodyCaptureEvent::End(CaptureOutcome::Complete),
            )
            .await;
        assert!(
            store
                .replay_request(id)
                .await
                .unwrap_err()
                .to_string()
                .contains(expected)
        );
    }

    let missing = store
        .begin_exchange(&request_parts("missing"))
        .await
        .unwrap()
        .unwrap();
    store
        .body_event(
            missing,
            BodyDirection::Response,
            BodyCaptureEvent::End(CaptureOutcome::Complete),
        )
        .await;
    assert!(
        store
            .replay_request(missing)
            .await
            .unwrap_err()
            .to_string()
            .contains("completion record missing")
    );
}

#[tokio::test]
async fn capture_derives_protocol_from_request_extensions() {
    let store = test_store();
    let service = CaptureHttpLayer::new(Some(store.clone())).layer(rama_core::service::service_fn(
        async |_request: Request| Ok::<_, Infallible>(Response::new(Body::empty())),
    ));
    service
        .serve(
            Request::builder()
                .uri("/custom")
                .extension(Protocol::from_static("custom"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    let parts = Request::builder()
        .uri("/custom")
        .extension(Protocol::from_static("custom"))
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let message = crate::inspect::control::http_message(&parts);
    assert_eq!(message.protocol, Protocol::from_static("custom"));
    assert_eq!(message.port, None);
    assert_eq!(
        store.details(1).await.unwrap().summary.protocol,
        Protocol::from_static("custom")
    );
}
