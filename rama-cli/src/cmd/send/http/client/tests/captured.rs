use super::*;
use crate::cmd::send::http::request::build as build_request;
use rama::{
    http::{HeaderMap, HeaderValue, Method, Version},
    ua::{
        UserAgent,
        profile::{
            capture::{
                completeness::ProfileCaptureCompleteness,
                headers::HeaderCapturePolicy,
                joint::{
                    CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits,
                },
                observation::ProfileCapture,
                order::{OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture},
            },
            evidence::{
                ProfileEvidence, ProfileScopeEvidence,
                ingestion::ObservationId,
                window::{ProfileWindowLimits, RetainedBucketWindow},
            },
            format::{
                archive::{ProfileArchiveEntry, ProfileArchiveLimits, ProfileArchiveWriter},
                canonical::CanonicalDomain,
            },
            model::{
                identity::{ConnectionContext, FlowKey, ProfileKey},
                runtime_hints::RequestInitiator,
            },
            selection::{
                DrawKey, ProfileSeed,
                capabilities::CapabilitySet,
                database::UserAgentDatabase,
                variants::{EmulationContext, ProfileSelector, SelectionRequest, VariantPins},
            },
        },
    },
};

fn captured_archive(unsupported_connection: bool) -> Vec<u8> {
    captured_archive_for_flow(unsupported_connection, None, Method::GET)
}

fn captured_archive_for_flow(
    unsupported_connection: bool,
    initiator: Option<RequestInitiator>,
    method: Method,
) -> Vec<u8> {
    let profile = ProfileKey::from_user_agent(&UserAgent::new(CUSTOM_PROFILE_USER_AGENT));
    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("capture.invalid"));
    headers.insert("accept", HeaderValue::from_static("application/pr10-test"));
    headers.insert(
        "user-agent",
        HeaderValue::from_static(CUSTOM_PROFILE_USER_AGENT),
    );
    headers.insert("accept-language", HeaderValue::from_static("en-GB"));
    let policy = HeaderCapturePolicy::default();
    let request = ProfileCapture {
        profile: profile.clone(),
        flow: Some(FlowKey::Http {
            version: Version::HTTP_11,
            method,
            initiator,
            fetch: None,
            connection: ConnectionContext::default(),
        }),
        connection: ConnectionContext::default(),
        joint: JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Request,
            slots: vec![CapturedSlot {
                kind: CapturedSlotKind::Headers,
                value: policy
                    .capture(
                        ProfileCaptureCompleteness::Complete,
                        Version::HTTP_11,
                        &headers,
                        None,
                    )
                    .unwrap()
                    .canonical(&policy)
                    .unwrap(),
            }]
            .into(),
        },
    };
    let connection = ProfileCapture {
        profile: profile.clone(),
        flow: None,
        connection: ConnectionContext::default(),
        joint: JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Connection,
            slots: if unsupported_connection {
                vec![CapturedSlot {
                    kind: CapturedSlotKind::QuicVersions,
                    value: OrderedProtocolCapture::capture(
                        ProfileCaptureCompleteness::Complete,
                        OrderNamespace::QuicVersion,
                        [(1, [])],
                        OrderCaptureLimits::default(),
                    )
                    .unwrap()
                    .canonical(OrderCaptureLimits::default())
                    .unwrap(),
                }]
                .into()
            } else {
                Box::default()
            },
        },
    };
    let mut scopes = Vec::new();
    for capture in [connection, request] {
        let prepared = capture
            .prepare(false, JointCaptureLimits::default())
            .unwrap();
        for input in prepared.buckets {
            let mut window = RetainedBucketWindow::new(
                input.value.validated_domain(65536).unwrap(),
                input.scope.id,
                [3; 32],
                ProfileWindowLimits::default(),
            )
            .unwrap();
            window
                .observe(
                    100,
                    100,
                    ObservationId {
                        run: [1; 16],
                        sequence: 1,
                    },
                    &input.value,
                )
                .unwrap();
            scopes.push(ProfileScopeEvidence {
                scope: input.scope,
                flow: prepared.flow.clone(),
                structure: input.structure,
                window: window.snapshot(),
            });
        }
    }
    scopes.sort_unstable_by_key(|scope| scope.scope.id);
    ProfileArchiveWriter::new(Vec::new(), false, 100, 14, ProfileArchiveLimits::default())
        .unwrap()
        .write_profile(ProfileArchiveEntry {
            evidence: ProfileEvidence {
                format_version: 1,
                profile: profile.canonical(65536).unwrap(),
                scopes: scopes.into(),
            },
            sampler_seed: [3; 32],
        })
        .unwrap()
        .finish()
        .unwrap()
}

#[derive(Debug)]
struct AbortCapturedServer(tokio::task::AbortHandle);
impl Drop for AbortCapturedServer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn captured_server_is_aborted_when_replay_panics() {
    struct Finished(Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for Finished {
        fn drop(&mut self) {
            if let Some(tx) = self.0.take() {
                let _send_result = tx.send(());
            }
        }
    }
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _finished = Finished(Some(finished_tx));
        let _send_result = started_tx.send(());
        std::future::pending::<()>().await;
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), started_rx)
        .await
        .unwrap()
        .unwrap();
    let result = std::panic::catch_unwind(|| {
        let _abort = AbortCapturedServer(task.abort_handle());
        panic!("simulated captured replay failure");
    });
    assert!(result.is_err());
    tokio::time::timeout(std::time::Duration::from_secs(1), finished_rx)
        .await
        .expect("captured server reaped after panic")
        .unwrap();
    assert!(task.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn captured_archive_replays_headers_through_real_send_stack() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let directory = rama::utils::fs::tempdir().unwrap();
        let archive = directory.path().join("captured.json");
        tokio::fs::write(&archive, captured_archive(false))
            .await
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            tokio::time::timeout(std::time::Duration::from_secs(5), async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let head = read_http_head(&mut stream).await;
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
                head
            })
            .await
            .expect("bounded captured replay server")
        });
        let _abort_server = AbortCapturedServer(server.abort_handle());
        let uri = format!("http://{address}/replayed");
        let output = directory.path().join("response");
        let cfg = send_cfg(&[
            &format!("--emulate={}", archive.display()),
            "--http1.1",
            "--output",
            output.to_str().unwrap(),
            &uri,
        ]);
        let client = new_hermetic(&cfg).await.unwrap();
        let response = client
            .serve(
                Request::builder()
                    .uri(uri.as_str())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let head = server.await.unwrap();
        assert!(head.starts_with("GET /replayed HTTP/1.1\r\n"), "{head}");
        let lower = head.to_ascii_lowercase();
        assert!(lower.contains(&format!("host: {address}\r\n")), "{head}");
        assert!(!head.contains("capture.invalid"));
        let accept = head.find("application/pr10-test").unwrap();
        let ua = head.find(CUSTOM_PROFILE_USER_AGENT).unwrap();
        let language = head.find("en-GB").unwrap();
        assert!(accept < ua && ua < language, "{head}");
    })
    .await
    .expect("bounded captured replay");
}

#[tokio::test]
async fn captured_http3_connector_checks_preservation_before_sending() {
    // Exercise the connector boundary directly with a valid selected context.
    // The unsupported connection component must fail before QUIC sends a packet.
    let database = UserAgentDatabase::try_from_json_slice(&captured_archive(true)).unwrap();
    let selected = database
        .select(
            &SelectionRequest {
                client: ProfileSelector::default(),
                required: CapabilitySet {
                    h1: true,
                    ..CapabilitySet::default()
                },
                flow: FlowKey::Http {
                    version: Version::HTTP_11,
                    method: Method::GET,
                    initiator: None,
                    fetch: None,
                    connection: ConnectionContext::default(),
                },
                pins: VariantPins::default(),
            },
            ProfileSeed([1; 32]),
            DrawKey([2; 32]),
        )
        .unwrap();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let uri = format!("https://{}/", socket.local_addr().unwrap());
    let cfg = send_cfg(&["--http3", "--connect-timeout", "1", &uri]);
    let client = new_inner_client(&cfg, Executor::default(), true)
        .await
        .unwrap();
    let request = Request::builder()
        .uri(uri.as_str())
        .body(Body::empty())
        .unwrap();
    request
        .extensions()
        .insert(rama::http::conn::TargetHttpVersion(Version::HTTP_3));
    Arc::new(selected)
        .emulation_context(ProfileSeed([1; 32]), DrawKey([2; 32]), DrawKey([3; 32]))
        .publish(request.extensions());
    let error = client.serve(request).await.unwrap_err();
    assert!(format!("{error:?}").contains("QuicVersions"), "{error:?}");
    let mut buffer = [0; 2048];
    assert_eq!(
        socket.try_recv(&mut buffer).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn captured_draw_cli_requires_complete_exact_width_coordinates() {
    let value = "ab".repeat(32);
    let flags = [
        "--emulate-seed",
        "--emulate-connection-key",
        "--emulate-request-key",
    ];
    let mut args = vec![
        "rama-send-test",
        "--emulate=archive.json",
        "http://example.test",
    ];
    for flag in flags {
        args.extend([flag, value.as_str()]);
    }
    for pin in ["--emulate-connection-variant", "--emulate-request-variant"] {
        for mask in 0..8 {
            let mut pinned = vec![
                "rama-send-test",
                "--emulate=archive.json",
                "http://example.test",
                pin,
                value.as_str(),
            ];
            for (index, flag) in flags.iter().enumerate() {
                if mask & (1 << index) != 0 {
                    pinned.extend([*flag, value.as_str()]);
                }
            }
            assert_eq!(
                TestCli::try_parse_from(pinned).is_ok(),
                mask == 7,
                "{pin} requires all three coordinates (mask={mask})"
            );
        }
    }
    let cfg = TestCli::try_parse_from(&args).unwrap().send;
    assert_eq!(cfg.emulate_seed.unwrap().0, [0xab; 32]);
    assert_eq!(cfg.emulate_connection_key.unwrap().0, [0xab; 32]);
    assert_eq!(cfg.emulate_request_key.unwrap().0, [0xab; 32]);
    for flag in flags {
        assert!(
            TestCli::try_parse_from([
                "rama-send-test",
                "--emulate=archive.json",
                flag,
                &value,
                "http://example.test"
            ])
            .is_err()
        );
    }
    for invalid in [
        "ab".repeat(31),
        "ab".repeat(33),
        "zz".repeat(32),
        format!("0x{value}"),
        format!(" {value}"),
    ] {
        let mut invalid_args = args.clone();
        invalid_args[4] = &invalid;
        assert!(TestCli::try_parse_from(invalid_args).is_err());
    }
    let without_emulate: Vec<_> = args
        .iter()
        .copied()
        .filter(|value| !value.starts_with("--emulate="))
        .collect();
    assert!(TestCli::try_parse_from(without_emulate).is_err());
}

#[tokio::test]
async fn captured_draw_cli_publishes_all_coordinates_and_variant_pins() {
    let database =
        Arc::new(UserAgentDatabase::try_from_json_slice(&captured_archive(false)).unwrap());
    let captured = database.iter().next().unwrap().captured.as_ref().unwrap();
    let mut pins = VariantPins::default();
    for scope in &captured.scopes {
        if scope.observations.domain != CanonicalDomain::Joint {
            continue;
        }
        let value = &scope.observations.variants[0].value;
        match JointCapture::from_canonical(value, JointCaptureLimits::default())
            .unwrap()
            .level
        {
            CaptureLevel::Connection => pins.connection = Some(value.id),
            CaptureLevel::Request => pins.request = Some(value.id),
            CaptureLevel::Legacy => panic!("fresh fixture must not contain legacy tuples"),
        }
    }
    let connection = rama::utils::fmt::hex(&pins.connection.unwrap().0).to_string();
    let request = rama::utils::fmt::hex(&pins.request.unwrap().0).to_string();
    let cfg = send_cfg(&[
        "--emulate=archive.json",
        "--emulate-seed",
        &"01".repeat(32),
        "--emulate-connection-key",
        &"02".repeat(32),
        "--emulate-request-key",
        &"03".repeat(32),
        "--emulate-connection-variant",
        &connection,
        "--emulate-request-variant",
        &request,
        "http://example.test",
    ]);
    let service = captured_emulation_layer(&cfg, database).into_layer(service_fn(
        move |req: Request<()>| async move {
            let context = EmulationContext::of(req.extensions()).unwrap();
            assert_eq!(context.seed, ProfileSeed([1; 32]));
            assert_eq!(context.connection_key, DrawKey([2; 32]));
            assert_eq!(context.request_key, DrawKey([3; 32]));
            assert_eq!(context.pins, pins);
            Ok::<_, Infallible>(())
        },
    ));
    service
        .serve(
            Request::builder()
                .uri("http://example.test")
                .body(())
                .unwrap(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn captured_draw_cli_rejects_legacy_profile_coordinates() {
    let cfg = send_cfg(&[
        "--emulate",
        "--emulate-seed",
        &"01".repeat(32),
        "--emulate-connection-key",
        &"02".repeat(32),
        "--emulate-request-key",
        &"03".repeat(32),
        "http://example.test",
    ]);
    let result = new_hermetic(&cfg).await;
    assert!(matches!(result, Err(error) if error.to_string().contains("captured profile archive")));
}

#[tokio::test]
async fn captured_draw_cli_real_stack_rejects_unknown_variant_pins() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let directory = rama::utils::fs::tempdir().unwrap();
        let archive = directory.path().join("captured.json");
        tokio::fs::write(&archive, captured_archive(false))
            .await
            .unwrap();
        for flag in ["--emulate-connection-variant", "--emulate-request-variant"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let _head = read_http_head(&mut stream).await;
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
            });
            let _abort_server = AbortCapturedServer(server.abort_handle());
            let uri = format!("http://{address}/");
            let output = directory.path().join("response");
            let cfg = send_cfg(&[
                &format!("--emulate={}", archive.display()),
                "--emulate-seed",
                &"01".repeat(32),
                "--emulate-connection-key",
                &"02".repeat(32),
                "--emulate-request-key",
                &"03".repeat(32),
                flag,
                &"ff".repeat(32),
                "--output",
                output.to_str().unwrap(),
                &uri,
            ]);
            let client = new_hermetic(&cfg).await.unwrap();
            assert!(
                client
                    .serve(
                        Request::builder()
                            .uri(uri.as_str())
                            .body(Body::empty())
                            .unwrap()
                    )
                    .await
                    .is_err(),
                "{flag} was ignored"
            );
        }
    })
    .await
    .expect("bounded unknown-pin check");
}

#[test]
fn captured_flow_cli_rejects_unknown_and_unscoped_initiators() {
    for flow in ["navigate", "fetch", "xhr", "form", "ws", " FETCH "] {
        assert!(
            TestCli::try_parse_from([
                "rama-send-test",
                "--emulate-initiator",
                flow,
                "http://example.test"
            ])
            .is_err()
        );
        TestCli::try_parse_from([
            "rama-send-test",
            "--emulate=archive.json",
            "--emulate-initiator",
            flow,
            "http://example.test",
        ])
        .unwrap();
    }
    for flow in ["", "unknown", "fetch,xhr"] {
        assert!(
            TestCli::try_parse_from([
                "rama-send-test",
                "--emulate=archive.json",
                "--emulate-initiator",
                flow,
                "http://example.test"
            ])
            .is_err()
        );
    }
}

#[tokio::test]
async fn captured_flow_cli_binds_websocket_scheme_and_default() {
    for version in ["--http1.1", "--http2", "--http3"] {
        for scheme in ["ws", "wss"] {
            if scheme == "ws" && version == "--http3" {
                continue;
            }
            let uri = format!("{scheme}://example.test/socket");
            let cfg = send_cfg(&["--emulate=archive.json", version, &uri]);
            let request = build_request(&cfg, true).await.unwrap();
            assert_eq!(
                request.extensions().get_ref::<RequestInitiator>().copied(),
                Some(RequestInitiator::Ws)
            );
            for flow in ["navigate", "fetch", "xhr", "form"] {
                let cfg = send_cfg(&[
                    "--emulate=archive.json",
                    "--emulate-initiator",
                    flow,
                    version,
                    &uri,
                ]);
                build_request(&cfg, true).await.unwrap_err();
            }
        }
        let cfg = send_cfg(&[
            "--emulate=archive.json",
            "--emulate-initiator",
            "ws",
            version,
            "https://example.test/socket",
        ]);
        build_request(&cfg, false).await.unwrap_err();
    }
    let cfg = send_cfg(&["--emulate=archive.json", "http://example.test"]);
    assert!(
        build_request(&cfg, false)
            .await
            .unwrap()
            .extensions()
            .get_ref::<RequestInitiator>()
            .is_none()
    );
    let cfg = send_cfg(&["ws://example.test/socket"]);
    assert!(
        build_request(&cfg, true)
            .await
            .unwrap()
            .extensions()
            .get_ref::<RequestInitiator>()
            .is_none()
    );
}

#[tokio::test]
async fn captured_flow_cli_replays_each_selected_http_flow() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        for (flow, method) in [
            (RequestInitiator::Navigate, Method::GET),
            (RequestInitiator::Fetch, Method::POST),
            (RequestInitiator::Xhr, Method::POST),
            (RequestInitiator::Form, Method::POST),
        ] {
            let directory = rama::utils::fs::tempdir().unwrap();
            let archive = directory.path().join("captured.json");
            tokio::fs::write(
                &archive,
                captured_archive_for_flow(false, Some(flow), method.clone()),
            )
            .await
            .unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                tokio::time::timeout(std::time::Duration::from_secs(5), async move {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let head = read_http_head(&mut stream).await;
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .unwrap();
                    head
                })
                .await
                .expect("bounded flow replay server")
            });
            let _abort_server = AbortCapturedServer(server.abort_handle());
            let uri = format!("http://{address}/replayed");
            let output = directory.path().join("response");
            let cfg = send_cfg(&[
                &format!("--emulate={}", archive.display()),
                "--emulate-initiator",
                flow.as_str(),
                "--http1.1",
                "--request",
                method.as_str(),
                "--output",
                output.to_str().unwrap(),
                &uri,
            ]);
            let client = new_hermetic(&cfg).await.unwrap();
            let request = build_request(&cfg, false).await.unwrap();
            let response = client.serve(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let head = server.await.unwrap();
            assert!(
                head.starts_with(&format!("{method} /replayed HTTP/1.1\r\n")),
                "{flow}: {head}"
            );
            assert!(head.contains("application/pr10-test"), "{flow}: {head}");
            assert!(
                head.to_ascii_lowercase()
                    .contains(&format!("host: {address}\r\n")),
                "{flow}: {head}"
            );
        }
    })
    .await
    .expect("bounded CLI flow matrix");
}
