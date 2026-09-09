use super::*;
use crate::cmd::serve::proxy::{control::Config as ControlConfig, mitm_policy::ScopeMode};

#[tokio::test]
async fn pending_traffic_uses_request_rows_without_creating_captures() {
    use crate::cmd::serve::proxy::control::{Config, ControlConnection, Message};
    let state = test_state();
    state.ensure_session("known");
    let control = state.capture.control();
    control
        .configure(
            0,
            Config {
                enabled: true,
                ..Default::default()
            },
        )
        .unwrap();
    let mut changes = control.subscribe_changes();
    let task = tokio::spawn({
        let control = control.clone();
        async move {
            control
                .decide(
                    &ControlConnection::new(91),
                    Message {
                        exchange: Some(71),
                        connection: 91,
                        protocol: "https".parse().unwrap(),
                        direction: "ingress".parse().unwrap(),
                        method: "GET".parse().unwrap(),
                        url: "https://example.test/<script>".parse().unwrap(),
                        ..Default::default()
                    },
                )
                .await
        }
    });
    changes.changed().await.unwrap();
    let pending = control.pending_summaries();
    let rendered = state.render_live("known", 1).await;
    assert_eq!(rendered.matches("id=\"request-71\"").count(), 1);
    assert!(rendered.contains("Awaiting request approval"));
    assert!(rendered.contains("id=\"approval-slot-1\" data-ignore-morph"));
    assert!(!rendered.contains("https://example.test/<script>"));
    assert!(rendered.contains("<span>Requests</span><strong>0</strong>"));
    let fixture = test_state();
    capture_request_for_replay(&fixture, "http://example.test/").await;
    let mut exchange = fixture
        .capture
        .snapshot_limited_for_connections(&CaptureFilter::default(), &BTreeSet::new(), 0, 8, 8)
        .await
        .exchanges
        .pop()
        .unwrap();
    exchange.id = 71;
    let live = LiveStatus {
        recording: true,
        pending,
    };
    assert!(
        render_pending_fallbacks(&live.pending, &[exchange.clone()], None)
            .into_string()
            .is_empty()
    );
    let row = render_focused_request_row(&exchange, &live).into_string();
    assert!(row.contains("id=\"request-71\""));
    assert!(row.contains("id=\"approval-slot-1\""));
    control.stop_and_forward();
    task.await.unwrap();
    assert!(
        !state
            .render_live("known", 2)
            .await
            .contains("id=\"request-71\"")
    );
}

#[tokio::test]
async fn inspection_pause_and_resume_are_global_but_session_authenticated() {
    let state = test_state();
    state.ensure_session("known");
    let signals = |session: &str| {
        ReadSignals(UiSignals {
            session: NonEmptyStr::try_from(session).ok(),
            ..Default::default()
        })
    };

    assert_eq!(
        pause_inspection(State(state.clone()), signals("unknown")).await,
        StatusCode::NOT_FOUND
    );
    assert!(state.inspection.is_enabled());
    assert_eq!(
        pause_inspection(State(state.clone()), signals("known")).await,
        StatusCode::NO_CONTENT
    );
    assert!(!state.inspection.is_enabled());
    let paused = state.render_live("known", 1).await;
    assert!(paused.contains("data-inspection-paused=\"true\""));
    assert!(paused.contains("Inspector paused"));
    assert_eq!(
        resume_inspection(State(state.clone()), signals("known")).await,
        StatusCode::NO_CONTENT
    );
    assert!(state.inspection.is_enabled());
    let resumed = state.render_live("known", 2).await;
    assert!(resumed.contains("data-inspection-paused=\"false\""));
    assert!(!resumed.contains("Inspector paused"));
}

#[tokio::test]
async fn dashboard_mitm_policy_is_session_authenticated_and_deny_wins() {
    let state = test_state();
    state.ensure_session("known");
    let update = |session: &str| {
        Json(MitmPolicyUpdate {
            session: NonEmptyStr::try_from(session).ok(),
            allow: vec!["example.test".to_owned()],
            deny: vec!["private.example.test".to_owned()],
            mode: ScopeMode::All,
        })
    };
    assert_eq!(
        update_mitm_policy(State(state.clone()), update("unknown"))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        update_mitm_policy(State(state.clone()), update("known"))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert!(
        state
            .mitm_policy
            .should_inspect_host(&rama::net::address::Host::try_from("api.example.test").unwrap())
    );
    assert!(
        !state.mitm_policy.should_inspect_host(
            &rama::net::address::Host::try_from("private.example.test").unwrap()
        )
    );
    assert!(
        !state
            .mitm_policy
            .should_inspect_host(&rama::net::address::Host::try_from("other.test").unwrap())
    );
}

#[tokio::test]
async fn traffic_policy_requires_a_live_dashboard_session_and_rejects_stale_writes() {
    let state = test_state();
    state.ensure_session("known");
    let config = || ControlConfig {
        enabled: true,
        ..Default::default()
    };
    let request = |session: &str, revision| {
        Json(ControlConfigUpdate {
            session: NonEmptyStr::try_from(session).ok(),
            revision,
            config: config(),
            apply_rule: None,
        })
    };
    assert_eq!(
        control_config(State(state.clone()), request("unknown", 0))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert!(!state.capture.control().snapshot().config.enabled);
    assert_eq!(
        control_config(State(state.clone()), request("known", 0))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        control_config(State(state.clone()), request("known", 0))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(state.capture.control().snapshot().revision, 1);
}

#[test]
fn optional_sessions_reject_explicit_empty_values() {
    serde_json::from_str::<UiSignals>(r#"{"session":""}"#).unwrap_err();
    assert!(
        serde_json::from_str::<UiSignals>("{}")
            .unwrap()
            .session
            .is_none()
    );
    assert_eq!(
        serde_json::from_str::<UiSignals>(r#"{"session":"known"}"#)
            .unwrap()
            .session
            .as_deref(),
        Some("known")
    );
}
