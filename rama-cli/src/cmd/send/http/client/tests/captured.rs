use super::*;
use rama::{
    extensions::ExtensionsRef as _,
    http::{HeaderMap, HeaderValue, Method, Version},
    ua::{UserAgent, profile::*},
};

fn captured_archive(unsupported_connection: bool) -> Vec<u8> {
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
            method: Method::GET,
            initiator: None,
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
