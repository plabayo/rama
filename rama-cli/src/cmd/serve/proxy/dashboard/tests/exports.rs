use rama::http::Version;

use super::*;

fn selected_export() -> Query<ExportQuery> {
    Query(ExportQuery {
        session: None,
        ids: Some("1".to_owned()),
        connection_ids: None,
    })
}

#[tokio::test]
async fn export_concurrency_is_unlimited_by_default() {
    let state = test_state();
    capture_request_for_replay(&state, "http://example.test/").await;
    let mut downloads = Vec::new();
    for _ in 0..4 {
        let response = export_har(State(state.clone()), selected_export()).await;
        assert_eq!(response.status(), StatusCode::OK);
        downloads.push(response);
    }
}

#[tokio::test]
async fn configured_export_limit_is_shared_and_released_with_the_download() {
    let state = test_state().with_export_limit(1).unwrap();
    capture_request_for_replay(&state, "http://example.test/").await;
    let first = export_har(State(state.clone()), selected_export()).await;
    assert_eq!(first.status(), StatusCode::OK);
    let second = export_har(State(state.clone()), selected_export()).await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(second.headers().get("retry-after").unwrap(), "1");
    let profiles = export_profiles(State(state.clone()), selected_export()).await;
    assert_eq!(profiles.status(), StatusCode::TOO_MANY_REQUESTS);

    let independent = test_state().with_export_limit(1).unwrap();
    capture_request_for_replay(&independent, "http://example.test/").await;
    let other = export_har(State(independent), selected_export()).await;
    assert_eq!(other.status(), StatusCode::OK);

    drop(first);
    let profiles = export_profiles(State(state.clone()), selected_export()).await;
    assert_eq!(profiles.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let next = export_har(State(state), selected_export()).await;
    assert_eq!(next.status(), StatusCode::OK);
}

#[tokio::test]
async fn export_limit_rejects_unsupported_capacity_and_can_be_disabled() {
    test_state()
        .with_export_limit(Semaphore::MAX_PERMITS + 1)
        .unwrap_err();
    let state = test_state()
        .with_export_limit(1)
        .unwrap()
        .with_export_limit(0)
        .unwrap();
    assert!(state.export_limit.is_none());
}

#[test]
fn unicode_header_values_are_bounded_on_a_character_boundary() {
    let details = test_details(vec![StoredRecord::RequestHead {
        method: Method::GET,
        url: "http://example.test".parse().unwrap(),
        version: Version::HTTP_11,
        headers: test_headers([("x-unicode".to_owned(), "é".repeat(5_000))]),
    }]);

    let rendered = render_details(&details).into_string();
    assert!(rendered.contains(&format!("{}…", "é".repeat(4_096))));
    assert!(!rendered.contains(&"é".repeat(4_097)));
}

#[tokio::test]
async fn har_control_is_compact_and_streams_a_cross_browser_download() {
    let state = test_state();
    state.ensure_session("known");

    let inactive = state.render_live("known", 0).await;
    assert!(inactive.contains("class=\"request-tools\""));
    assert!(inactive.contains("data-har-action=\"start\""));
    assert!(inactive.contains("Record HAR"));
    assert!(!inactive.contains("HAR output file"));

    let response = start_har(
        State(state.clone()),
        Query(StartHarQuery {
            session: NonEmptyStr::try_from("known").ok(),
            file_name: "picked.har".to_owned(),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let active = state.render_live("known", 0).await;
    assert!(active.contains("HAR recording"));
    assert!(active.contains("method=\"post\""));
    assert!(active.contains("action=\"/api/har/stop?session=known\""));
    assert!(active.contains("target=\"har-download\""));
    assert!(active.contains("Stop &amp; download"));

    let response = stop_har(
        State(state.clone()),
        Query(HarSessionQuery {
            session: NonEmptyStr::try_from("known").ok(),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(
        response.headers()["content-disposition"],
        "attachment; filename=\"picked.har\""
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(value.get("log").is_some());
    assert!(!state.har.status().active);

    let response = start_har(
        State(state),
        Query(StartHarQuery {
            session: NonEmptyStr::try_from("unknown").ok(),
            file_name: "ignored.har".to_owned(),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
