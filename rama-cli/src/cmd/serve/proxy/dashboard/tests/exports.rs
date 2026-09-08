use super::*;

#[test]
fn unicode_header_values_are_bounded_on_a_character_boundary() {
    let details = test_details(vec![StoredRecord::RequestHead {
        method: Method::GET,
        url: "http://example.test".parse().unwrap(),
        version: rama::http::Version::HTTP_11,
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
            session: "known".to_owned(),
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
            session: "known".to_owned(),
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
            session: "unknown".to_owned(),
            file_name: "ignored.har".to_owned(),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
