use rama_net::client::ConnectorTarget;
use rama_utils::str::NonEmptyStr;

use super::*;
use crate::body::util::BodyExt as _;

fn headers(values: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        headers.append(name.parse::<HeaderName>().unwrap(), value.parse().unwrap());
    }
    headers
}

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
        protocol: "https".parse().unwrap(),
        direction: "ingress".parse().unwrap(),
        method: "GET".parse().unwrap(),
        host: Some("example.test".parse().unwrap()),
        url: "https://example.test/api/data".parse().unwrap(),
        ..Default::default()
    }
}

async fn pending(control: &Control, count: usize) -> Vec<u64> {
    let mut changes = control.subscribe_changes();
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
            protocol: "future-protocol".parse().unwrap(),
            direction: "ingress".parse().unwrap(),
            kind: Some(rama_utils::str::non_empty_str!("message")),
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
            response: ResponseSpec {
                status: StatusCode::FORBIDDEN,
                ..
            }
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
            direction: "egress".parse().unwrap(),
            status: Some(StatusCode::OK),
            ..request()
        },
    );
    pending(&control, 2).await;
    control
        .resolve(
            id,
            Decision::Connection {
                headers: Some(headers(&[("x-test", "edited")])),
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
                    host: Some("other.test".parse().unwrap()),
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
                    protocol: "future-protocol".parse().unwrap(),
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
            response: ResponseSpec {
                status: StatusCode::SERVICE_UNAVAILABLE,
                ..
            }
        }
    ));
    task.abort();
    _ = task.await;
    pending(&control, 0).await;
    assert!(matches!(
        control.decide(&connection, request()).await.0,
        Decision::Respond {
            response: ResponseSpec {
                status: StatusCode::GATEWAY_TIMEOUT,
                ..
            }
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
    control.observe(
        &a,
        &"EXAMPLE.test.".parse().unwrap(),
        false,
        "CONNECT",
        "excluded",
    );
    control.observe(
        &a,
        &"example.test".parse().unwrap(),
        false,
        "CONNECT",
        "excluded",
    );
    let before = control.snapshot().hosts;
    assert_eq!(before[0].connections, 1);
    assert_eq!(before[0].bypassed, 1);
    recording.pause().await;
    control.observe(
        &b,
        &"example.test".parse().unwrap(),
        false,
        "CONNECT",
        "excluded",
    );
    control.observe(
        &b,
        &"new.test".parse().unwrap(),
        false,
        "CONNECT",
        "excluded",
    );
    assert_eq!(control.snapshot().hosts.len(), 1);
    assert_eq!(control.snapshot().hosts[0].last_seen, before[0].last_seen);
    recording.resume().await;
    control.observe(
        &b,
        &"example.test".parse().unwrap(),
        true,
        "SNI",
        "selected",
    );
    assert_eq!(control.snapshot().hosts[0].connections, 2);
    assert_eq!(control.snapshot().hosts[0].bypassed, 1);
    control.clear_hosts();
    control.observe(
        &a,
        &"example.test".parse().unwrap(),
        false,
        "CONNECT",
        "excluded",
    );
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
fn close_decisions_and_rules_reject_codes_unsupported_by_the_adapter() {
    let message = Message {
        kind: Some("text".parse().unwrap()),
        ..request()
    };
    Decision::Close {
        code: 1013,
        reason: String::new(),
    }
    .validate(&message)
    .unwrap();
    Decision::Close {
        code: 1014,
        reason: String::new(),
    }
    .validate(&message)
    .unwrap_err();
    let control = control();
    control
        .configure(
            1,
            Config {
                rules: vec![rule(
                    Action::Close {
                        code: 1014,
                        reason: String::new(),
                    },
                    Matcher::default(),
                )],
                ..Config::default()
            },
        )
        .unwrap_err();
    assert_eq!(control.snapshot().revision, 1);
}

#[test]
fn headers_preserve_duplicates_and_reject_framing_and_routing_edits() {
    let original = Message {
        headers: headers(&[("content-length", "10"), ("host", "example.test")]),
        ..request()
    };
    let mut edited = original.headers.clone();
    edited.append("x-test", "one".parse().unwrap());
    edited.append("x-test", "two".parse().unwrap());
    Decision::Forward {
        headers: Some(edited.clone()),
        status: None,
        payload: None,
    }
    .validate(&original)
    .unwrap();
    assert_eq!(
        validate_headers(&edited)
            .unwrap()
            .get_all("x-test")
            .iter()
            .count(),
        2
    );
    edited.insert(header::CONTENT_LENGTH, "20".parse().unwrap());
    assert!(
        Decision::Forward {
            headers: Some(edited),
            status: None,
            payload: None
        }
        .validate(&original)
        .is_err()
    );
    serde_json::from_value::<HeaderMap>(serde_json::json!([["x-test", "ok\r\ninjected: bad"]]))
        .unwrap_err();
}

#[test]
fn header_edits_preserve_connection_nominated_fields() {
    let original = Message {
        headers: headers(&[
            ("connection", "upgrade, x-hop, invalid token"),
            ("connection", "X-Other"),
            ("upgrade", "websocket"),
            ("x-hop", "one"),
            ("x-hop", "two"),
            ("x-other", "three"),
        ]),
        ..request()
    };
    for name in ["x-hop", "x-other"] {
        for replacement in [Some("changed"), None] {
            let mut edited = original.headers.clone();
            if let Some(value) = replacement {
                edited.insert(name, value.parse().unwrap());
            } else {
                edited.remove(name);
            }
            Decision::Forward {
                headers: Some(edited),
                status: None,
                payload: None,
            }
            .validate(&original)
            .unwrap_err();
        }
    }
    let mut edited = original.headers.clone();
    edited.insert("x-end-to-end", "allowed".parse().unwrap());
    Decision::Forward {
        headers: Some(edited),
        status: None,
        payload: None,
    }
    .validate(&original)
    .unwrap();
}

#[tokio::test]
async fn synthetic_responses_have_correct_framing_and_conditional_semantics() {
    for status in [
        StatusCode::NO_CONTENT,
        StatusCode::RESET_CONTENT,
        StatusCode::NOT_MODIFIED,
    ] {
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
            status: StatusCode::TEMPORARY_REDIRECT,
            body: String::new(),
            headers: HeaderMap::new()
        }
        .validate()
        .is_err()
    );
    let spec = ResponseSpec::default();
    let response = spec.build(&Message {
        method: "HEAD".parse().unwrap(),
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
        http_version: Version::HTTP_2,
        ..request()
    });
    assert!(!response.headers().contains_key(header::CONNECTION));
    let spec = ResponseSpec {
        status: StatusCode::NOT_MODIFIED,
        body: String::new(),
        headers: HeaderMap::new(),
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
            host: Some("other.test".parse().unwrap()),
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
fn http_message_rules_use_the_resolved_authority() {
    for (uri, host_header, protocol, host, port) in [
        ("/api", "localhost:8080", Protocol::HTTP, "localhost", 8080),
        (
            "/api",
            "example.test:8443",
            Protocol::HTTPS,
            "example.test",
            8443,
        ),
        ("/api", "[::1]:8080", Protocol::HTTP, "::1", 8080),
        ("/api", "example.test", Protocol::HTTP, "example.test", 80),
        ("/api", "example.test", Protocol::HTTPS, "example.test", 443),
        (
            "https://origin.test:9443/api",
            "other.test:8080",
            Protocol::HTTP,
            "origin.test",
            9443,
        ),
    ] {
        let (parts, ()) = crate::Request::builder()
            .uri(uri)
            .header(header::HOST, host_header)
            .extension(protocol)
            .extension(ConnectorTarget("127.0.0.1:3128".parse().unwrap()))
            .body(())
            .unwrap()
            .into_parts();
        let message = http_message(&parts);
        assert_eq!(message.host, Some(host.parse().unwrap()));
        assert_eq!(message.port, Some(port));
        let compiled = CompiledRule::new(rule(
            Action::Intercept,
            Matcher {
                port: Some(port),
                ..Default::default()
            },
        ))
        .unwrap();
        assert!(compiled.matches(&message));
        assert!(!compiled.matches(&Message {
            port: Some(port + 1),
            ..message
        }));
    }
}

#[test]
fn http_message_retains_an_authority_without_a_known_protocol_port() {
    let (parts, ()) = crate::Request::builder()
        .uri("/path")
        .header(header::HOST, "example.test")
        .extension(Protocol::from_static("custom"))
        .body(())
        .unwrap()
        .into_parts();
    let message = http_message(&parts);
    assert_eq!(message.host, Some("example.test".parse().unwrap()));
    assert_eq!(message.port, None);
}

#[test]
fn rule_conditions_combine_protocol_port_kind_and_header_patterns() {
    let compiled = CompiledRule::new(rule(
        Action::Intercept,
        Matcher {
            host: ".example.test".into(),
            path: "/api/*".into(),
            protocol: "ws".into(),
            direction: "ingress".parse().unwrap(),
            port: Some(8080),
            kind: "binary".into(),
            headers: vec![("x-mode".into(), "test-*".into())],
            ..Default::default()
        },
    ))
    .unwrap();
    let message = Message {
        host: Some("sub.example.test".parse().unwrap()),
        protocol: "ws".parse().unwrap(),
        direction: "ingress".parse().unwrap(),
        port: Some(8080),
        kind: Some(rama_utils::str::non_empty_str!("binary")),
        headers: headers(&[("X-Mode", "ignored"), ("X-Mode", "test-one")]),
        ..request()
    };
    assert!(compiled.matches(&message));
    for other in [
        Message {
            port: Some(80),
            ..message.clone()
        },
        Message {
            kind: Some(rama_utils::str::non_empty_str!("text")),
            ..message.clone()
        },
        Message {
            headers: headers(&[]),
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
            response: ResponseSpec {
                status: StatusCode::PAYLOAD_TOO_LARGE,
                ..
            }
        }
    ));
    let result = control
        .decide(
            &connection,
            Message {
                oversized: true,
                direction: "ingress".parse().unwrap(),
                protocol: "ws".parse().unwrap(),
                kind: Some(rama_utils::str::non_empty_str!("text")),
                ..Default::default()
            },
        )
        .await
        .0;
    assert!(
        matches!(result, Decision::Close { code: 1009, reason } if reason.contains("editor limit"))
    );
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
}

#[test]
fn host_passthrough_outcome_corrects_the_initial_eligibility_count_once() {
    let control = control();
    let connection = ControlConnection::new(1);
    control.observe(
        &connection,
        &"example.test".parse().unwrap(),
        true,
        "target",
        "eligible",
    );
    control.observe(
        &connection,
        &"example.test".parse().unwrap(),
        false,
        "target",
        "uninspected protocol",
    );
    control.observe(
        &connection,
        &"example.test".parse().unwrap(),
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
                default_response: ResponseSpec::error(
                    StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                    "custom response",
                ),
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
            response: ResponseSpec {
                status: StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                ..
            }
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

#[test]
fn host_eligibility_tracks_the_latest_observation() {
    let control = control();
    let connection = ControlConnection::new(1);
    let host = "example.test".parse().unwrap();
    control.observe(&connection, &host, false, "scope", "excluded");
    assert!(!control.snapshot().hosts[0].eligible);
    control.observe(&connection, &host, true, "scope", "included");
    assert!(control.snapshot().hosts[0].eligible);
}

#[test]
fn rule_selectors_are_parsed_once_and_canonicalize_known_directions() {
    let rule = CompiledRule::new(Rule {
        name: "typed rule".into(),
        enabled: true,
        action: Action::Intercept,
        matcher: Matcher {
            direction: "InGrEsS".into(),
            protocol: "HTTP".into(),
            method: "GET".into(),
            ..Matcher::default()
        },
    })
    .unwrap();
    assert!(rule.matches(&Message::default()));
    let mut invalid = rule.rule;
    invalid.matcher.method = "invalid method".into();
    CompiledRule::new(invalid).err().unwrap();
    "custom-adapter-direction".parse::<Direction>().unwrap_err();
    serde_json::from_str::<Direction>("\"unknown\"").unwrap_err();
}

#[test]
fn rules_reject_misspelled_standard_methods_and_preserve_custom_case() {
    let make_rule = |method: &str| Rule {
        name: "method rule".into(),
        enabled: true,
        action: Action::Intercept,
        matcher: Matcher {
            method: method.into(),
            ..Matcher::default()
        },
    };
    for method in ["get", "pOsT", "Head", "connect"] {
        let error = CompiledRule::new(make_rule(method)).err().unwrap();
        assert!(error.to_string().contains("canonical HTTP rule method"));
    }
    let rule = CompiledRule::new(make_rule("Custom-Method")).unwrap();
    assert!(rule.matches(&Message {
        method: "Custom-Method".parse().unwrap(),
        ..Message::default()
    }));
    assert!(!rule.matches(&Message {
        method: "CUSTOM-METHOD".parse().unwrap(),
        ..Message::default()
    }));
}

#[test]
fn message_path_is_derived_from_uri_for_matching_and_serialization() {
    #[derive(Deserialize)]
    struct WireMessage {
        path: Uri,
        kind: Option<NonEmptyStr>,
    }
    for (url, expected) in [
        (
            "https://example.test/api/a%2Fb?q=1".parse().unwrap(),
            "/api/a%2Fb",
        ),
        ("https://example.test".parse().unwrap(), "/"),
        (Uri::parse_authority_form("example.test:443").unwrap(), "/"),
    ] {
        let message = Message { url, ..request() };
        assert_eq!(message.path().as_encoded_str(), expected);
        let wire: WireMessage =
            serde_json::from_slice(&serde_json::to_vec(&message).unwrap()).unwrap();
        assert_eq!(wire.path.as_str(), expected);
        assert_eq!(wire.kind, None);
    }
    let mut message = request();
    message.url = "https://example.test/new/path".parse().unwrap();
    let compiled = CompiledRule::new(Rule {
        name: "new path".into(),
        enabled: true,
        matcher: Matcher {
            path: "/new/*".into(),
            ..Default::default()
        },
        action: Action::Intercept,
    })
    .unwrap();
    assert!(compiled.matches(&message));
}
