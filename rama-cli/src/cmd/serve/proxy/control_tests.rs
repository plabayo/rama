use super::*;

fn control() -> Control {
    let control = Control::new(InspectionState::default());
    control
        .configure(
            0,
            Config {
                enabled: true,
                ..Default::default()
            },
        )
        .unwrap();
    control
}
fn request() -> Message {
    Message {
        protocol: "https".into(),
        direction: "request".into(),
        method: "GET".into(),
        host: "example.test".into(),
        path: "/api/data".into(),
        url: "https://example.test/api/data".into(),
        ..Default::default()
    }
}
async fn pending(control: &Control, count: usize) -> Vec<u64> {
    let mut changes = control.subscribe();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let state = control.snapshot();
            if state.pending.len() == count {
                return state.pending.iter().map(|p| p.id).collect();
            }
            changes.changed().await.unwrap();
        }
    })
    .await
    .expect("pending queue did not reach expected length")
}
fn spawn(
    control: &Control,
    connection: &ControlConnection,
    message: Message,
) -> tokio::task::JoinHandle<(Decision, Option<String>)> {
    let (control, connection) = (control.clone(), connection.clone());
    tokio::spawn(async move { control.decide(&connection, message).await })
}
fn rule(action: Action, matcher: Matcher) -> Rule {
    Rule {
        name: "test rule".into(),
        enabled: true,
        matcher,
        action,
    }
}

#[tokio::test]
async fn default_is_automatic_but_enabled_intercepts_future_protocols() {
    let control = Control::new(InspectionState::default());
    let connection = ControlConnection::new(1);
    assert!(matches!(
        control.decide(&connection, request()).await.0,
        Decision::Forward { .. }
    ));
    control
        .configure(
            0,
            Config {
                enabled: true,
                ..Default::default()
            },
        )
        .unwrap();
    let task = spawn(
        &control,
        &connection,
        Message {
            protocol: "future-protocol".into(),
            direction: "ingress".into(),
            ..Default::default()
        },
    );
    let id = pending(&control, 1).await[0];
    assert!(!task.is_finished());
    control.resolve(id, Decision::forward()).unwrap();
    assert!(matches!(task.await.unwrap().0, Decision::Forward { .. }));
}

#[tokio::test]
async fn queue_is_ordered_and_decisions_are_single_use() {
    let control = control();
    let connection = ControlConnection::new(1);
    let first = spawn(&control, &connection, request());
    let first_id = pending(&control, 1).await[0];
    let second = spawn(&control, &connection, request());
    let ids = pending(&control, 2).await;
    assert_eq!(ids[0], first_id);
    assert!(ids[1] > ids[0]);
    control.resolve(ids[1], Decision::Block).unwrap();
    assert!(matches!(
        second.await.unwrap().0,
        Decision::Respond {
            response: ResponseSpec { status: 403, .. }
        }
    ));
    assert!(control.resolve(ids[1], Decision::forward()).is_err());
    assert!(!first.is_finished());
    control.resolve(first_id, Decision::forward()).unwrap();
    first.await.unwrap();
}

#[tokio::test]
async fn connection_release_edits_current_and_releases_both_directions() {
    let control = control();
    let connection = ControlConnection::new(1);
    let a = spawn(&control, &connection, request());
    let id = pending(&control, 1).await[0];
    let b = spawn(
        &control,
        &connection,
        Message {
            direction: "response".into(),
            status: Some(200),
            ..request()
        },
    );
    pending(&control, 2).await;
    control
        .resolve(
            id,
            Decision::Connection {
                headers: Some(vec![("x-test".into(), "edited".into())]),
                status: None,
                payload: None,
            },
        )
        .unwrap();
    assert!(matches!(
        a.await.unwrap().0,
        Decision::Forward {
            headers: Some(_),
            ..
        }
    ));
    assert!(matches!(
        b.await.unwrap().0,
        Decision::Forward { headers: None, .. }
    ));
    assert!(control.snapshot().pending.is_empty());
    assert!(matches!(
        control.decide(&connection, request()).await.0,
        Decision::Forward { .. }
    ));
    control.resume_connection(1);
    let task = spawn(&control, &connection, request());
    let id = pending(&control, 1).await[0];
    control.resolve(id, Decision::forward()).unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn block_rules_precede_connection_bypass_and_protocol_rules_are_generic() {
    let control = control();
    let connection = ControlConnection::new(1);
    connection.0.automatic.store(true, Ordering::Release);
    control
        .configure(
            1,
            Config {
                enabled: true,
                rules: vec![rule(
                    Action::Respond {
                        response: ResponseSpec::default(),
                    },
                    Matcher {
                        host: "example.test".into(),
                        path: "/api/*".into(),
                        ..Default::default()
                    },
                )],
                ..Default::default()
            },
        )
        .unwrap();
    assert!(matches!(
        control.decide(&connection, request()).await.0,
        Decision::Respond { .. }
    ));
    assert!(matches!(
        control
            .decide(
                &connection,
                Message {
                    host: "other.test".into(),
                    ..request()
                }
            )
            .await
            .0,
        Decision::Forward { .. }
    ));
    control
        .configure(
            2,
            Config {
                enabled: true,
                rules: vec![rule(
                    Action::Forward,
                    Matcher {
                        protocol: "future-protocol".into(),
                        ..Default::default()
                    },
                )],
                ..Default::default()
            },
        )
        .unwrap();
    connection.0.automatic.store(false, Ordering::Release);
    assert!(matches!(
        control
            .decide(
                &connection,
                Message {
                    protocol: "future-protocol".into(),
                    ..request()
                }
            )
            .await
            .0,
        Decision::Forward { .. }
    ));
}

#[tokio::test]
async fn cancellation_overflow_and_timeout_never_release_traffic() {
    let control = control();
    control
        .configure(
            1,
            Config {
                enabled: true,
                queue_limit: 1,
                timeout_seconds: 1,
                ..Default::default()
            },
        )
        .unwrap();
    let connection = ControlConnection::new(1);
    let task = spawn(&control, &connection, request());
    pending(&control, 1).await;
    assert!(matches!(
        control.decide(&connection, request()).await.0,
        Decision::Respond {
            response: ResponseSpec { status: 503, .. }
        }
    ));
    task.abort();
    _ = task.await;
    pending(&control, 0).await;
    assert_eq!(control.0.state.lock().bytes, 0);
    assert!(matches!(
        control.decide(&connection, request()).await.0,
        Decision::Respond {
            response: ResponseSpec { status: 504, .. }
        }
    ));
    assert!(control.snapshot().pending.is_empty());
}

#[tokio::test]
async fn turning_off_preserves_pending_and_forward_all_drains_them() {
    let control = control();
    let connection = ControlConnection::new(1);
    let task = spawn(&control, &connection, request());
    pending(&control, 1).await;
    control.configure(1, Config::default()).unwrap();
    assert_eq!(control.snapshot().pending.len(), 1);
    assert!(!task.is_finished());
    assert!(matches!(
        control.decide(&connection, request()).await.0,
        Decision::Forward { .. }
    ));
    control.stop_and_forward();
    task.await.unwrap();
    assert!(control.snapshot().pending.is_empty());
}

#[tokio::test]
async fn host_counts_are_per_connection_and_recording_pause_freezes_observations() {
    let recording = InspectionState::default();
    let control = Control::new(recording.clone());
    let a = ControlConnection::new(1);
    let b = ControlConnection::new(2);
    control.observe(&a, "EXAMPLE.test.", false, "CONNECT", "excluded");
    control.observe(&a, "example.test", false, "CONNECT", "excluded");
    let before = control.snapshot().hosts;
    assert_eq!(before[0].connections, 1);
    assert_eq!(before[0].bypassed, 1);
    recording.pause().await;
    control.observe(&b, "example.test", false, "CONNECT", "excluded");
    control.observe(&b, "new.test", false, "CONNECT", "excluded");
    assert_eq!(control.snapshot().hosts.len(), 1);
    assert_eq!(control.snapshot().hosts[0].last_seen, before[0].last_seen);
    recording.resume().await;
    control.observe(&b, "example.test", true, "SNI", "selected");
    assert_eq!(control.snapshot().hosts[0].connections, 2);
    assert_eq!(control.snapshot().hosts[0].bypassed, 1);
    control.clear_hosts();
    control.observe(&a, "example.test", false, "CONNECT", "excluded");
    assert_eq!(control.snapshot().hosts[0].connections, 1);
}

#[test]
fn config_roundtrip_and_validation_do_not_replace_good_policy() {
    let control = control();
    let config = Config {
        rules: vec![rule(
            Action::Respond {
                response: ResponseSpec::default(),
            },
            Matcher::default(),
        )],
        ..Default::default()
    };
    let config: Config = serde_json::from_value(serde_json::to_value(config).unwrap()).unwrap();
    control.configure(1, config).unwrap();
    assert!(control.configure(1, Config::default()).is_err());
    assert!(
        control
            .configure(
                2,
                Config {
                    rules: vec![rule(
                        Action::Forward,
                        Matcher {
                            host: " ".into(),
                            ..Default::default()
                        }
                    )],
                    ..Default::default()
                }
            )
            .is_err()
    );
    assert_eq!(control.snapshot().revision, 2);
}

#[test]
fn headers_preserve_duplicates_and_reject_framing_and_routing_edits() {
    let original = Message {
        headers: vec![
            ("content-length".into(), "10".into()),
            ("host".into(), "example.test".into()),
        ],
        ..request()
    };
    let mut edited = original.headers.clone();
    edited.extend([
        ("x-test".into(), "one".into()),
        ("x-test".into(), "two".into()),
    ]);
    Decision::Forward {
        headers: Some(edited.clone()),
        status: None,
        payload: None,
    }
    .validate(&original)
    .unwrap();
    assert_eq!(
        parse_headers(&edited)
            .unwrap()
            .get_all("x-test")
            .iter()
            .count(),
        2
    );
    edited[0].1 = "20".into();
    assert!(
        Decision::Forward {
            headers: Some(edited),
            status: None,
            payload: None
        }
        .validate(&original)
        .is_err()
    );
    parse_headers(&[("x-test".into(), "ok\r\ninjected: bad".into())]).unwrap_err();
}

#[tokio::test]
async fn synthetic_responses_have_correct_framing_and_conditional_semantics() {
    use rama::http::body::util::BodyExt as _;
    for status in [204, 205, 304] {
        assert!(
            ResponseSpec {
                status,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }
    assert!(
        ResponseSpec {
            status: 307,
            body: String::new(),
            headers: vec![]
        }
        .validate()
        .is_err()
    );
    let spec = ResponseSpec::default();
    let response = spec.build(&Message {
        method: "HEAD".into(),
        ..request()
    });
    assert_eq!(
        response.headers()[header::CONTENT_LENGTH],
        spec.body.len().to_string()
    );
    assert!(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty()
    );
    let response = spec.build(&Message {
        http2: true,
        ..request()
    });
    assert!(!response.headers().contains_key(header::CONNECTION));
    let spec = ResponseSpec {
        status: 304,
        body: String::new(),
        headers: vec![],
    };
    assert!(
        Decision::Respond {
            response: spec.clone()
        }
        .validate(&request())
        .is_err()
    );
    let message = Message {
        conditional: true,
        ..request()
    };
    let response = spec.build(&message);
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert!(!response.headers().contains_key(header::CONTENT_LENGTH));
    assert!(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty()
    );
}

#[tokio::test]
async fn apply_rule_resolves_only_matching_queued_messages() {
    let control = control();
    let connection = ControlConnection::new(1);
    let a = spawn(&control, &connection, request());
    pending(&control, 1).await;
    let b = spawn(
        &control,
        &connection,
        Message {
            host: "other.test".into(),
            ..request()
        },
    );
    pending(&control, 2).await;
    control
        .configure(
            1,
            Config {
                enabled: true,
                rules: vec![rule(
                    Action::Respond {
                        response: ResponseSpec::default(),
                    },
                    Matcher {
                        host: "example.test".into(),
                        ..Default::default()
                    },
                )],
                ..Default::default()
            },
        )
        .unwrap();
    control.apply_rule(0, 2).unwrap();
    assert!(matches!(a.await.unwrap().0, Decision::Respond { .. }));
    assert!(!b.is_finished());
    let id = pending(&control, 1).await[0];
    control.resolve(id, Decision::forward()).unwrap();
    b.await.unwrap();
}

#[test]
fn rule_conditions_combine_protocol_port_kind_and_header_patterns() {
    let compiled = CompiledRule::new(rule(
        Action::Intercept,
        Matcher {
            host: ".example.test".into(),
            path: "/api/*".into(),
            protocol: "ws".into(),
            direction: "ingress".into(),
            port: Some(8080),
            kind: "binary".into(),
            headers: vec![("x-mode".into(), "test-*".into())],
            ..Default::default()
        },
    ))
    .unwrap();
    let message = Message {
        host: "sub.example.test".into(),
        protocol: "ws".into(),
        direction: "ingress".into(),
        port: Some(8080),
        kind: "binary".into(),
        headers: vec![("X-Mode".into(), "test-one".into())],
        ..request()
    };
    assert!(compiled.matches(&message));
    for other in [
        Message {
            port: Some(80),
            ..message.clone()
        },
        Message {
            kind: "text".into(),
            ..message.clone()
        },
        Message {
            headers: vec![],
            ..message
        },
    ] {
        assert!(!compiled.matches(&other));
    }
}

#[tokio::test]
async fn oversized_items_fail_closed_without_retaining_queue_memory() {
    let control = control();
    let connection = ControlConnection::new(1);
    let result = control
        .decide(
            &connection,
            Message {
                oversized: true,
                ..request()
            },
        )
        .await
        .0;
    assert!(matches!(
        result,
        Decision::Respond {
            response: ResponseSpec { status: 503, .. }
        }
    ));
    let result = control
        .decide(
            &connection,
            Message {
                oversized: true,
                direction: "ingress".into(),
                protocol: "ws".into(),
                ..Default::default()
            },
        )
        .await
        .0;
    assert!(matches!(result, Decision::Close { code: 1013, .. }));
    assert_eq!(control.0.state.lock().bytes, 0);
    assert!(control.snapshot().pending.is_empty());
}

#[tokio::test]
async fn competing_approvals_have_one_winner() {
    let control = control();
    let connection = ControlConnection::new(1);
    let task = spawn(&control, &connection, request());
    let id = pending(&control, 1).await[0];
    let (a, b) = tokio::join!(async { control.resolve(id, Decision::forward()) }, async {
        control.resolve(id, Decision::Block)
    });
    assert_ne!(a.is_ok(), b.is_ok());
    task.await.unwrap();
    assert_eq!(control.0.state.lock().bytes, 0);
}

#[test]
fn host_passthrough_outcome_corrects_the_initial_eligibility_count_once() {
    let control = control();
    let connection = ControlConnection::new(1);
    control.observe(&connection, "example.test", true, "target", "eligible");
    control.observe(
        &connection,
        "example.test",
        false,
        "target",
        "uninspected protocol",
    );
    control.observe(
        &connection,
        "example.test",
        false,
        "target",
        "uninspected protocol",
    );
    let host = &control.snapshot().hosts[0];
    assert_eq!(host.connections, 1);
    assert_eq!(host.bypassed, 1);
}

#[tokio::test]
async fn manual_block_uses_the_current_default_and_stale_rule_application_is_rejected() {
    let control = control();
    let connection = ControlConnection::new(1);
    let task = spawn(&control, &connection, request());
    let id = pending(&control, 1).await[0];
    control
        .configure(
            1,
            Config {
                enabled: true,
                default_response: ResponseSpec::error(451, "custom response"),
                rules: vec![rule(Action::Forward, Matcher::default())],
                ..Default::default()
            },
        )
        .unwrap();
    control.apply_rule(0, 1).unwrap_err();
    assert!(!task.is_finished());
    control.resolve(id, Decision::Block).unwrap();
    assert!(matches!(
        task.await.unwrap().0,
        Decision::Respond {
            response: ResponseSpec { status: 451, .. }
        }
    ));
}

#[tokio::test]
async fn pause_bypasses_rules_and_holds_without_waiting_for_pending_approval() {
    let control = control();
    let recording = control.0.recording.clone();
    let connection = ControlConnection::new(1);
    let task = spawn(&control, &connection, request());
    pending(&control, 1).await;
    tokio::time::timeout(Duration::from_secs(1), recording.pause())
        .await
        .unwrap();
    control.stop_and_forward();
    assert!(matches!(task.await.unwrap().0, Decision::Forward { .. }));
    assert!(control.snapshot().pending.is_empty());
    let mut config = control.snapshot().config;
    config.enabled = true;
    assert!(
        control
            .configure(control.snapshot().revision, config.clone())
            .is_err()
    );
    config.enabled = false;
    config.rules = vec![rule(
        Action::Respond {
            response: ResponseSpec::default(),
        },
        Matcher::default(),
    )];
    control
        .configure(control.snapshot().revision, config)
        .unwrap();
    assert!(!control.is_active());
    assert!(matches!(
        control.decide(&connection, request()).await.0,
        Decision::Forward { .. }
    ));
    recording.resume().await;
    assert!(control.is_active());
    assert!(matches!(
        control.decide(&connection, request()).await.0,
        Decision::Respond { .. }
    ));
    assert!(!control.snapshot().config.enabled);
}
