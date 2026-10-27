use rama_core::{
    bytes::Bytes,
    extensions::{Extensions, ExtensionsRef},
    futures::{SinkExt as _, stream},
    io::BridgeIo,
    layer::{ArcLayer, MapInputLayer, MapOutputLayer},
    rt::spawn,
};
use rama_http::{
    HeaderMap, HeaderValue, StatusCode, Version,
    body::{
        Frame,
        util::{BodyExt as _, StreamBody},
    },
    datagram::{
        DatagramTransport, HttpDatagramSession, SessionConfig, SessionEvent,
        capsule::UnknownCapsules,
    },
    headers::Priority,
    io::upgrade::{Upgraded, handle_upgrade},
    proto::{
        capsule::CapsuleType,
        ext::{HttpDatagrams, Protocol},
    },
};
use rama_http_types::proto::h3::{FrameHeader, FrameType, SettingId, Settings, StreamType};
use rama_net::{address::SocketAddress, uri::Uri};
use rama_quic::{
    ClientConfig, Connection, ConnectionError, Endpoint, ServerConfig, TransportConfig,
    tls::TlsOptions,
};
use rama_quic_proto::coding::Codec as _;
use rama_tls::{
    client::TlsClientConfig,
    server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
};
use rama_udp::test_utils::MemoryDatagramSocket;
use rama_utils::octets::{kib, kib_u64, mib, mib_u64};
use rama_ws::{
    AsyncWebSocket, Message,
    protocol::{PerMessageDeflateConfig, Role, WebSocketConfig},
};
use std::{
    io,
    num::NonZeroUsize,
    pin::Pin,
    sync::atomic::{AtomicU8, AtomicUsize, Ordering},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf},
    sync::oneshot,
    time::timeout,
};

use super::*;

const LIMIT: Duration = Duration::from_secs(20);

#[tokio::test(start_paused = true)]
async fn custom_datagram_relay_filters_using_request_local_policy() {
    #[derive(Debug, Clone, Extension)]
    struct FilterPayload(bool);
    timeout(LIMIT, async {
        let (browser_endpoint, ingress_endpoint, browser, ingress) = hop().await;
        let (egress_endpoint, origin_endpoint, egress, origin) = hop().await;
        let config = Config { extended_connect: true, ..Config::default() };
        let (mut origin, origin_driver) = server::handshake(origin, config.clone()).unwrap();
        let origin_driver = spawn(origin_driver.run());
        // A caller can supply an ordinary service, using the session API to apply
        // per-datagram policy. The relay engine need not know this application's rules.
        let custom = service_fn(|BridgeIo(ingress, egress): BridgeIo<Upgraded, Upgraded>| async move {
            let filter = ingress.extensions().get_ref::<FilterPayload>().unwrap().0;
            assert!(!egress.extensions().contains::<FilterPayload>());
            let mut ingress = HttpDatagramSession::new(ingress);
            let mut egress = HttpDatagramSession::new(egress);
            while let Some(event) = ingress.recv().await? {
                let SessionEvent::Datagram { payload, transport } = event else { panic!("expected test datagram") };
                if filter && payload == b"denied"[..] { continue; }
                match transport {
                    DatagramTransport::Native => { egress.send_datagram(payload).await?; }
                    DatagramTransport::Capsule => egress.send_capsule(CapsuleType::DATAGRAM, payload).await?,
                }
            }
            egress.close().await?;
            assert_eq!(egress.recv().await?, None);
            ingress.close().await?;
            Ok::<_, BoxError>(())
        });
        let relay = spawn(async move {
            Http3MitmRelay::new(Executor::new())
                .with_datagram_relay(custom)
                .with_http_middleware((
                    MapInputLayer::new(|request: Request| {
                        request.extensions().insert(HttpDatagrams);
                        request.extensions().self_get_ref_or_insert(HttpUpgradeMitmRelayExtensions::default)
                            .0.insert(FilterPayload(request.uri().path_or_root().as_ref() == "/filtered"));
                        request
                    }),
                    MapOutputLayer::new(|response: Response| {
                        assert!(response.status().is_success());
                        response.extensions().insert(HttpDatagrams);
                        response
                    }),
                    ArcLayer::new(),
                ))
                .serve(BridgeIo(ingress, egress)).await
        });
        let (mut browser, browser_driver) = client::handshake::<Body, _>(browser, config, Executor::new()).unwrap();
        let browser_driver = spawn(browser_driver.run());
        // Both requests share a connection. A previous request's policy must not leak.
        for filtered in [true, false] {
            let request = Request::builder().method(Method::CONNECT).version(Version::HTTP_3)
                .uri(if filtered { "https://localhost/filtered" } else { "https://localhost/open" })
                .body(Body::empty()).unwrap();
            request.extensions().insert(Protocol::CONNECT_UDP);
            request.extensions().insert(HttpDatagrams);
            let (response, origin_io) = tokio::join!(browser.send_request(request), async {
                let (request, response) = origin.accept().await.unwrap().resolve().await.unwrap();
                let upgrade = handle_upgrade(&request);
                let accepted = Response::new(Body::empty());
                accepted.extensions().insert(HttpDatagrams);
                response.send_response(accepted).await.unwrap();
                upgrade.await.unwrap()
            });
            let mut browser_io = HttpDatagramSession::new(handle_upgrade(&response.unwrap()).await.unwrap());
            let mut origin_io = HttpDatagramSession::new(origin_io);
            for native in [false, true] {
                for payload in [b"denied".as_slice(), b"allowed".as_slice()] {
                    if native { browser_io.send_datagram(Bytes::copy_from_slice(payload)).await.unwrap(); }
                    else { browser_io.send_capsule(CapsuleType::DATAGRAM, Bytes::copy_from_slice(payload)).await.unwrap(); }
                    if filtered && payload == b"denied" {
                        timeout(Duration::from_millis(50), origin_io.recv()).await.unwrap_err();
                    } else {
                        assert!(matches!(origin_io.recv().await.unwrap(), Some(SessionEvent::Datagram { payload: received, transport }) if received == payload && transport == if native { DatagramTransport::Native } else { DatagramTransport::Capsule }));
                    }
                }
            }
            browser_io.close().await.unwrap();
            assert_eq!(origin_io.recv().await.unwrap(), None);
            origin_io.close().await.unwrap();
            assert_eq!(browser_io.recv().await.unwrap(), None);
        }
        origin.shutdown().unwrap();
        relay.await.unwrap().unwrap();
        for endpoint in [&browser_endpoint, &ingress_endpoint, &egress_endpoint, &origin_endpoint] { endpoint.close(0u32, b"done"); }
        tokio::join!(browser_endpoint.shutdown(), ingress_endpoint.shutdown(), egress_endpoint.shutdown(), origin_endpoint.shutdown());
        let _drivers = tokio::join!(browser_driver, origin_driver);
    }).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_request_marker_alone_does_not_select_a_datagram_relay() {
    timeout(LIMIT, async {
        let (browser_endpoint, ingress_endpoint, browser, ingress) = hop().await;
        let (egress_endpoint, origin_endpoint, egress, origin) = hop().await;
        let config = Config { extended_connect: true, ..Config::default() };
        let (mut origin, origin_driver) = server::handshake(origin, config.clone()).unwrap();
        let origin_driver = spawn(origin_driver.run());
        let relay = spawn(async move {
            Http3MitmRelay::new(Executor::new())
                .with_datagram_relay(service_fn(|_: BridgeIo<Upgraded, Upgraded>| async {
                    panic!("an inherited request marker selected the datagram relay");
                    #[expect(unreachable_code, reason = "fix the service result type")]
                    Ok::<_, BoxError>(())
                }))
                .with_http_middleware((
                    MapInputLayer::new(|request: Request| {
                        request.extensions().insert(HttpDatagrams);
                        request
                    }),
                    MapOutputLayer::new(|response: Response| {
                        assert!(response.extensions().contains::<HttpDatagrams>());
                        assert!(!response.extensions().self_contains::<HttpDatagrams>());
                        response
                    }),
                    ArcLayer::new(),
                ))
                .serve(BridgeIo(ingress, egress)).await
        });
        let (mut browser, browser_driver) = client::handshake::<Body, _>(browser, config, Executor::new()).unwrap();
        let browser_driver = spawn(browser_driver.run());
        let request = Request::builder().method(Method::CONNECT).version(Version::HTTP_3)
            .uri("https://localhost/any-template").body(Body::empty()).unwrap();
        request.extensions().insert(Protocol::CONNECT_UDP);
        request.extensions().insert(HttpDatagrams);
        let (response, origin_io) = tokio::join!(browser.send_request(request), async {
            let (request, response) = origin.accept().await.unwrap().resolve().await.unwrap();
            let upgrade = handle_upgrade(&request);
            let accepted = Response::new(Body::empty());
            accepted.extensions().insert(HttpDatagrams);
            response.send_response(accepted).await.unwrap();
            upgrade.await.unwrap()
        });
        let mut browser_io = HttpDatagramSession::new(handle_upgrade(&response.unwrap()).await.unwrap());
        let mut origin_io = HttpDatagramSession::new(origin_io);
        browser_io.send_capsule(CapsuleType::DATAGRAM, Bytes::from_static(b"reliable")).await.unwrap();
        assert!(matches!(origin_io.recv().await.unwrap(), Some(SessionEvent::Datagram { payload, transport: DatagramTransport::Capsule }) if payload == b"reliable"[..]));
        assert_eq!(browser_io.send_datagram(Bytes::from_static(b"native must not pass")).await.unwrap(), DatagramTransport::Native);
        timeout(Duration::from_millis(50), origin_io.recv()).await.unwrap_err();
        browser_io.close().await.unwrap();
        assert_eq!(origin_io.recv().await.unwrap(), None);
        origin_io.close().await.unwrap();
        assert_eq!(browser_io.recv().await.unwrap(), None);
        origin.shutdown().unwrap();
        relay.await.unwrap().unwrap();
        for endpoint in [&browser_endpoint, &ingress_endpoint, &egress_endpoint, &origin_endpoint] { endpoint.close(0u32, b"done"); }
        tokio::join!(browser_endpoint.shutdown(), ingress_endpoint.shutdown(), egress_endpoint.shutdown(), origin_endpoint.shutdown());
        let _drivers = tokio::join!(browser_driver, origin_driver);
    }).await.unwrap();
}

async fn hop() -> (Endpoint, Endpoint, Connection, Connection) {
    hop_with_early_data(false).await
}

async fn hop_with_early_data(early_data: bool) -> (Endpoint, Endpoint, Connection, Connection) {
    hop_with_transports(early_data, None, None).await
}

async fn hop_with_transports(
    early_data: bool,
    client_transport: Option<Arc<TransportConfig>>,
    server_transport: Option<Arc<TransportConfig>>,
) -> (Endpoint, Endpoint, Connection, Connection) {
    let identity = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
    let server_tls = TlsServerConfig::new()
        .with_alpn([b"h3".as_slice().into()].into_iter().collect())
        .with_server_auth(identity.clone());
    let client_tls = TlsClientConfig::new()
        .with_alpn([b"h3".as_slice().into()].into_iter().collect())
        .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
        .unwrap();
    let options = TlsOptions::default().with_early_data(early_data);
    let mut server_config = ServerConfig::try_from_rama_tls(&server_tls, options).unwrap();
    let mut client_config = ClientConfig::try_from_rama_tls(&client_tls, options).unwrap();
    if let Some(transport) = server_transport {
        server_config.set_transport_config(transport);
    }
    if let Some(transport) = client_transport {
        client_config.set_transport_config(transport);
    }
    let (server_socket, client_socket) = MemoryDatagramSocket::pair(
        SocketAddress::local_ipv4(443),
        SocketAddress::local_ipv4(444),
        NonZeroUsize::MIN,
    );
    let server_endpoint = Endpoint::build(Executor::new())
        .with_server_config(server_config)
        .with_datagram_socket(server_socket)
        .unwrap();
    let mut client_endpoint = Endpoint::build(Executor::new())
        .with_datagram_socket(client_socket)
        .unwrap();
    client_endpoint.set_default_client_config(client_config.clone());
    let (client, server) = tokio::join!(
        client_endpoint
            .connect_with(
                client_config,
                server_endpoint.local_addr().unwrap(),
                "localhost"
            )
            .unwrap(),
        async { server_endpoint.accept().await.unwrap().await },
    );
    (
        client_endpoint,
        server_endpoint,
        client.unwrap(),
        server.unwrap(),
    )
}

/// A hop resumed from an earlier session's ticket, so both peers hold installed early-data keys.
async fn resumed_hop() -> (Endpoint, Endpoint, Connection, Connection) {
    let (client_endpoint, server_endpoint, client, server) = hop_with_early_data(true).await;
    let mut send = server.open_uni().await.unwrap();
    send.write_all(b"ticket delivery barrier").await.unwrap();
    send.finish().unwrap();
    client
        .accept_uni()
        .await
        .unwrap()
        .read_to_end(128)
        .await
        .unwrap();
    client.close(0u32, b"resume next session");
    server.closed().await;
    let connecting = client_endpoint
        .connect(server_endpoint.local_addr().unwrap(), "localhost")
        .unwrap();
    let Ok((client, accepted)) = connecting.into_0rtt() else {
        panic!("the first session must provide resumption keys");
    };
    let server = server_endpoint.accept().await.unwrap().await.unwrap();
    assert!(accepted.await.unwrap());
    tokio::try_join!(client.handshake_confirmed(), server.handshake_confirmed()).unwrap();
    assert!(client.early_data_keys_enabled() && server.early_data_keys_enabled());
    (client_endpoint, server_endpoint, client, server)
}

/// A literal SETTINGS profile `config` accepts, extended with `extra` entries.
fn settings_profile(config: &Config, extra: &[(SettingId, u64)]) -> Arc<Settings> {
    let mut settings = Settings::new();
    settings
        .set(
            SettingId::QPACK_MAX_TABLE_CAPACITY,
            config.decoder.max_table_capacity,
        )
        .unwrap();
    settings
        .set(
            SettingId::QPACK_BLOCKED_STREAMS,
            config.decoder.max_blocked_streams,
        )
        .unwrap();
    for &(id, value) in extra {
        settings.set(id, value).unwrap();
    }
    Arc::new(settings)
}

fn ordinary_config() -> Config {
    Config {
        datagrams: None,
        ..Config::default()
    }
}

#[tokio::test(start_paused = true)]
async fn native_h3_mitm_streams_bodies_trailers_and_drains_on_upstream_goaway() {
    timeout(LIMIT, async {
        let (browser_endpoint, ingress_endpoint, browser, ingress) = hop().await;
        let (egress_endpoint, origin_endpoint, egress, origin) = hop().await;
        let (mut origin, origin_driver) = server::handshake(origin, ordinary_config()).unwrap();
        let origin_driver = spawn(origin_driver.run());
        let relay = Http3MitmRelay::new(Executor::new());
        let relay = spawn(async move {
            relay
                .with_ingress_config(ordinary_config())
                .with_egress_config(ordinary_config())
                .serve(BridgeIo(ingress, egress))
                .await
        });
        let (mut browser, browser_driver) =
            client::handshake::<Body, _>(browser, ordinary_config(), Executor::new()).unwrap();
        let browser_driver = spawn(browser_driver.run());
        let request = Request::builder()
            .method(Method::POST)
            .version(Version::HTTP_3)
            .uri("https://localhost/message")
            .body(Body::from("request bytes"))
            .unwrap();
        let (received, sent) = tokio::join!(browser.send_request(request), async {
            let (request, response) = origin.accept().await.unwrap().resolve().await.unwrap();
            assert_eq!(request.method(), Method::POST);
            assert_eq!(
                request.into_body().collect().await.unwrap().to_bytes(),
                "request bytes"
            );
            let mut trailers = HeaderMap::new();
            trailers.insert("x-final", HeaderValue::from_static("finished"));
            let frames = stream::iter([
                Ok::<_, Infallible>(Frame::data("response bytes".into())),
                Ok(Frame::trailers(trailers)),
            ]);
            response
                .send_response(Response::new(Body::new(StreamBody::new(frames))))
                .await
        });
        sent.unwrap();
        let response = received.unwrap();
        assert_eq!(response.version(), Version::HTTP_3);
        let body = response.into_body().collect().await.unwrap();
        assert_eq!(body.trailers().unwrap()["x-final"], "finished");
        assert_eq!(body.to_bytes(), "response bytes");
        origin.shutdown().unwrap();
        browser.closed_or_draining().await;
        relay.await.unwrap().unwrap();
        for endpoint in [
            &browser_endpoint,
            &ingress_endpoint,
            &egress_endpoint,
            &origin_endpoint,
        ] {
            endpoint.close(0u32, b"complete");
        }
        tokio::join!(
            browser_endpoint.shutdown(),
            ingress_endpoint.shutdown(),
            egress_endpoint.shutdown(),
            origin_endpoint.shutdown()
        );
        let _drivers = tokio::join!(browser_driver, origin_driver);
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn native_h3_mitm_cancellation_before_first_poll_closes_both_hops() {
    timeout(LIMIT, async {
        let (browser_endpoint, ingress_endpoint, browser, ingress) = hop().await;
        let (egress_endpoint, origin_endpoint, egress, origin) = hop().await;
        // Handles the producer keeps must not keep either hop open.
        let _retained = (ingress.clone(), egress.clone());
        let relay = Http3MitmRelay::new(Executor::new());
        drop(
            relay
                .with_ingress_config(ordinary_config())
                .with_egress_config(ordinary_config())
                .serve(BridgeIo(ingress, egress)),
        );
        assert_relay_ended([&browser, &origin]).await;
        for endpoint in [
            &browser_endpoint,
            &ingress_endpoint,
            &egress_endpoint,
            &origin_endpoint,
        ] {
            endpoint.close(0u32, b"complete");
        }
        tokio::join!(
            browser_endpoint.shutdown(),
            ingress_endpoint.shutdown(),
            egress_endpoint.shutdown(),
            origin_endpoint.shutdown()
        );
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn native_h3_mitm_binds_authority_before_and_after_middleware() {
    timeout(LIMIT, async {
        let (browser_endpoint, ingress_endpoint, browser, ingress) = hop().await;
        let (egress_endpoint, origin_endpoint, egress, origin) = hop().await;
        let (mut origin, origin_driver) = server::handshake(origin, ordinary_config()).unwrap();
        let origin_driver = spawn(origin_driver.run());
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let origin_requests = spawn(async move {
            while let Ok(stream) = origin.accept().await {
                let (request, response) = stream.resolve().await.unwrap();
                observed.fetch_add(1, Ordering::SeqCst);
                request.into_body().collect().await.unwrap();
                response
                    .send_response(Response::new(Body::empty()))
                    .await
                    .unwrap();
            }
        });
        let relay = Http3MitmRelay::new(Executor::new())
            .with_bound_authority(BoundAuthority::https(
                "localhost:443".parse().unwrap(),
                true,
            ))
            .with_http_middleware((
                MapInputLayer::new(|mut request: Request| {
                    match request
                        .headers()
                        .get("x-action")
                        .and_then(|value| value.to_str().ok())
                    {
                        Some("repair") => {
                            *request.uri_mut() = "https://localhost/".parse().unwrap()
                        }
                        Some("change") => {
                            *request.uri_mut() = "https://other.example/".parse().unwrap()
                        }
                        _ => {}
                    }
                    request
                }),
                ArcLayer::new(),
            ));
        let relay = spawn(async move {
            relay
                .with_ingress_config(ordinary_config())
                .with_egress_config(ordinary_config())
                .serve(BridgeIo(ingress, egress))
                .await
        });
        let (mut browser, browser_driver) =
            client::handshake::<Body, _>(browser, ordinary_config(), Executor::new()).unwrap();
        let browser_driver = spawn(browser_driver.run());
        for (host, action, status) in [
            ("other.example", "repair", StatusCode::MISDIRECTED_REQUEST),
            ("localhost", "change", StatusCode::MISDIRECTED_REQUEST),
            ("localhost", "keep", StatusCode::OK),
        ] {
            let request = Request::builder()
                .version(Version::HTTP_3)
                .uri(format!("https://{host}/"))
                .header("x-action", action)
                .body(Body::empty())
                .unwrap();
            let response = browser.send_request(request).await.unwrap();
            assert_eq!(response.status(), status);
            response.into_body().collect().await.unwrap();
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
        for endpoint in [
            &browser_endpoint,
            &ingress_endpoint,
            &egress_endpoint,
            &origin_endpoint,
        ] {
            endpoint.close(0u32, b"complete");
        }
        tokio::join!(
            browser_endpoint.shutdown(),
            ingress_endpoint.shutdown(),
            egress_endpoint.shutdown(),
            origin_endpoint.shutdown()
        );
        let _results = tokio::join!(browser_driver, origin_driver, origin_requests, relay);
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn native_h3_mitm_rejects_only_proven_unprocessed_post() {
    timeout(LIMIT, async {
        for (code, rejected) in [
            (Code::H3_REQUEST_REJECTED, true),
            (Code::H3_REQUEST_CANCELLED, false),
        ] {
            let (browser_endpoint, ingress_endpoint, browser, ingress) = hop().await;
            let (egress_endpoint, origin_endpoint, egress, origin) = hop().await;
            let (mut origin, origin_driver) = server::handshake(origin, ordinary_config()).unwrap();
            let origin_driver = spawn(origin_driver.run());
            let relay = Http3MitmRelay::new(Executor::new());
            let relay = spawn(async move {
                relay
                    .with_ingress_config(ordinary_config())
                    .with_egress_config(ordinary_config())
                    .serve(BridgeIo(ingress, egress))
                    .await
            });
            let (mut browser, browser_driver) =
                client::handshake::<Body, _>(browser, ordinary_config(), Executor::new()).unwrap();
            let browser_driver = spawn(browser_driver.run());
            let request = Request::builder()
                .method(Method::POST)
                .version(Version::HTTP_3)
                .uri("https://localhost/change")
                .body(Body::from("one change"))
                .unwrap();
            let (result, ()) = tokio::join!(browser.send_request(request), async {
                let (request, response) = origin.accept().await.unwrap().resolve().await.unwrap();
                response.reset(code).unwrap();
                drop(request);
            });
            if rejected {
                assert!(result.unwrap_err().is_rejected());
            } else {
                let response = result.unwrap();
                assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
                response.into_body().collect().await.unwrap();
            }
            for endpoint in [
                &browser_endpoint,
                &ingress_endpoint,
                &egress_endpoint,
                &origin_endpoint,
            ] {
                endpoint.close(0u32, b"complete");
            }
            tokio::join!(
                browser_endpoint.shutdown(),
                ingress_endpoint.shutdown(),
                egress_endpoint.shutdown(),
                origin_endpoint.shutdown()
            );
            let _results = tokio::join!(browser_driver, origin_driver, relay);
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn native_h3_mitm_waits_past_the_deadline_for_client_settings_without_control_output() {
    timeout(LIMIT, async {
        let (_browser_endpoint, _ingress_endpoint, browser, ingress) = hop().await;
        let (_egress_endpoint, _origin_endpoint, egress, origin) = hop().await;
        let relay =
            Http3MitmRelay::new(Executor::new()).with_settings_timeout(Duration::from_secs(1));
        // Neither peer ever sends H3 SETTINGS.
        let relay = relay
            .with_ingress_config(ordinary_config())
            .with_egress_config(ordinary_config());
        let mut pending = Box::pin(relay.serve(BridgeIo(ingress, egress)));
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(
            tokio::time::timeout(Duration::from_secs(5), &mut pending)
                .await
                .is_err(),
            "the relay keeps ingress open for the client's SETTINGS"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), browser.accept_uni())
                .await
                .is_err(),
            "no control output before the client's SETTINGS"
        );
        drop(pending);
        assert_relay_ended([&browser, &origin]).await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn native_h3_mitm_forwards_priority_before_headers_and_during_body() {
    timeout(LIMIT, async {
        let (browser_endpoint, ingress_endpoint, browser, ingress) = hop().await;
        let (egress_endpoint, origin_endpoint, egress, origin) = hop().await;
        let (mut origin, origin_driver) = server::handshake(origin, ordinary_config()).unwrap();
        let origin_driver = spawn(origin_driver.run());
        let relay = Http3MitmRelay::new(Executor::new());
        let relay = spawn(async move {
            relay
                .with_ingress_config(ordinary_config())
                .with_egress_config(ordinary_config())
                .serve(BridgeIo(ingress, egress))
                .await
        });
        let (mut browser, browser_driver) =
            client::handshake::<Body, _>(browser, ordinary_config(), Executor::new()).unwrap();
        let browser_driver = spawn(browser_driver.run());
        let (opened, opened_stream) = oneshot::channel();
        let browser_request = spawn(async move {
            let request = Request::builder()
                .version(Version::HTTP_3)
                .uri("https://localhost/priority")
                .body(Body::empty())
                .unwrap();
            browser
                .send_request_with_priority(request, move |handle| {
                    opened.send(handle).unwrap();
                })
                .await
        });
        let (request, response) = origin.accept().await.unwrap().resolve().await.unwrap();
        drop(request);
        let handle = opened_stream.await.unwrap();
        let mut priority = response.peer_priority();
        assert_eq!(priority.changed().await.unwrap(), Priority::default());
        let urgent = Priority::new(0, true).unwrap();
        handle.update(urgent).unwrap();
        assert_eq!(priority.changed().await.unwrap(), urgent);
        assert!(!browser_request.is_finished());

        let (release_body, body_ready) = oneshot::channel();
        let body = StreamBody::new(stream::once(async move {
            body_ready.await.unwrap();
            Ok::<_, Infallible>(Frame::data("done".into()))
        }));
        let sent = spawn(response.send_response(Response::new(Body::new(body))));
        let received = browser_request.await.unwrap().unwrap();
        let background = Priority::new(7, false).unwrap();
        handle.update(background).unwrap();
        assert_eq!(priority.changed().await.unwrap(), background);
        release_body.send(()).unwrap();
        assert_eq!(
            received.into_body().collect().await.unwrap().to_bytes(),
            "done"
        );
        sent.await.unwrap().unwrap();

        for endpoint in [
            &browser_endpoint,
            &ingress_endpoint,
            &egress_endpoint,
            &origin_endpoint,
        ] {
            endpoint.close(0u32, b"complete");
        }
        tokio::join!(
            browser_endpoint.shutdown(),
            ingress_endpoint.shutdown(),
            egress_endpoint.shutdown(),
            origin_endpoint.shutdown()
        );
        let _results = tokio::join!(browser_driver, origin_driver, relay);
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn native_h3_mitm_tunnels_keep_bytes_half_closes_and_goaway() {
    timeout(LIMIT, async {
        for extended in [false, true] {
            let (browser_endpoint, ingress_endpoint, browser, ingress) = hop().await;
            let (egress_endpoint, origin_endpoint, egress, origin) = hop().await;
            let config = || Config {
                extended_connect: extended,
                ..ordinary_config()
            };
            let (mut origin, origin_driver) = server::handshake(origin, config()).unwrap();
            let origin_driver = spawn(origin_driver.run());
            let relay_config = config();
            let relay = spawn(async move {
                Http3MitmRelay::new(Executor::new())
                    .with_ingress_config(relay_config)
                    .with_egress_config(ordinary_config())
                    .serve(BridgeIo(ingress, egress))
                    .await
            });
            let (mut browser, browser_driver) =
                client::handshake::<Body, _>(browser, ordinary_config(), Executor::new()).unwrap();
            let browser_driver = spawn(browser_driver.run());
            let request = Request::builder()
                .method(Method::CONNECT)
                .version(Version::HTTP_3)
                .uri(if extended {
                    "https://localhost/tunnel".parse::<Uri>().unwrap()
                } else {
                    Uri::parse_authority_form("localhost:443").unwrap()
                })
                .body(Body::empty())
                .unwrap();
            if extended {
                request
                    .extensions()
                    .insert(Protocol::from_static("x-byte-test"));
            }
            let (read_finished, finished) = oneshot::channel();
            let (release, released) = oneshot::channel();
            let origin_task = spawn(async move {
                let (request, response) = origin.accept().await.unwrap().resolve().await.unwrap();
                assert_eq!(request.method(), Method::CONNECT);
                assert_eq!(request.extensions().contains::<Protocol>(), extended);
                let upgrade = handle_upgrade(&request);
                response
                    .send_response(Response::new(Body::empty()))
                    .await
                    .unwrap();
                let mut tunnel = upgrade.await.unwrap();
                let mut received = Vec::new();
                tunnel.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, vec![0x5a; kib(64)]);
                // The request half has ended, but GOAWAY must keep the response
                // half alive until the remaining tunnel bytes are acknowledged.
                origin.shutdown().unwrap();
                read_finished.send(()).unwrap();
                released.await.unwrap();
                tunnel.write_all(b"after peer FIN").await.unwrap();
                tunnel.shutdown().await.unwrap();
                origin.drained().await.unwrap();
            });
            let response = browser.send_request(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let mut tunnel = handle_upgrade(&response).await.unwrap();
            tunnel.write_all(&vec![0x5a; kib(64)]).await.unwrap();
            tunnel.shutdown().await.unwrap();
            finished.await.unwrap();
            browser.closed_or_draining().await;
            assert!(!relay.is_finished(), "GOAWAY must drain a live tunnel");
            release.send(()).unwrap();
            let mut response_bytes = Vec::new();
            tunnel.read_to_end(&mut response_bytes).await.unwrap();
            assert_eq!(response_bytes, b"after peer FIN");
            origin_task.await.unwrap();
            relay.await.unwrap().unwrap();
            for endpoint in [
                &browser_endpoint,
                &ingress_endpoint,
                &egress_endpoint,
                &origin_endpoint,
            ] {
                endpoint.close(0u32, b"complete");
            }
            tokio::join!(
                browser_endpoint.shutdown(),
                ingress_endpoint.shutdown(),
                egress_endpoint.shutdown(),
                origin_endpoint.shutdown()
            );
            let _drivers = tokio::join!(browser_driver, origin_driver);
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn native_h3_mitm_advertises_only_upstream_extended_connect_support() {
    timeout(LIMIT, async {
        for supported in [false, true] {
            let (browser_endpoint, ingress_endpoint, browser, ingress) = hop().await;
            let (egress_endpoint, origin_endpoint, egress, origin) = hop().await;
            let (mut origin, origin_driver) = server::handshake(
                origin,
                Config {
                    extended_connect: supported,
                    ..ordinary_config()
                },
            )
            .unwrap();
            let origin_driver = spawn(origin_driver.run());
            let relay = spawn(async move {
                Http3MitmRelay::new(Executor::new())
                    .with_ingress_config(Config {
                        extended_connect: true,
                        ..ordinary_config()
                    })
                    .with_egress_config(ordinary_config())
                    .serve(BridgeIo(ingress, egress))
                    .await
            });
            let (mut browser, browser_driver) =
                client::handshake::<Body, _>(browser, ordinary_config(), Executor::new()).unwrap();
            let browser_driver = spawn(browser_driver.run());
            assert_eq!(
                browser
                    .peer_settings()
                    .await
                    .unwrap()
                    .enable_connect_protocol(),
                supported
            );
            let request = Request::builder()
                .uri("https://localhost/")
                .body(Body::empty())
                .unwrap();
            let (sent, received) = tokio::join!(browser.send_request(request), async {
                let (_request, response) = origin.accept().await.unwrap().resolve().await.unwrap();
                response.send_response(Response::new(Body::empty())).await
            });
            received.unwrap();
            sent.unwrap().into_body().collect().await.unwrap();
            origin.shutdown().unwrap();
            relay.await.unwrap().unwrap();
            for endpoint in [
                &browser_endpoint,
                &ingress_endpoint,
                &egress_endpoint,
                &origin_endpoint,
            ] {
                endpoint.close(0u32, b"complete");
            }
            tokio::join!(
                browser_endpoint.shutdown(),
                ingress_endpoint.shutdown(),
                egress_endpoint.shutdown(),
                origin_endpoint.shutdown()
            );
            let _drivers = tokio::join!(browser_driver, origin_driver);
        }
    })
    .await
    .unwrap();
}

// Observe the first actual frame header on each leg. Configuring an endpoint
// for compression alone would not prove that compressed frames crossed IO.
struct FrameHeaders {
    io: Upgraded,
    received: Arc<AtomicU8>,
    sent: Arc<AtomicU8>,
}

impl FrameHeaders {
    fn new(io: Upgraded) -> Self {
        Self {
            io,
            received: Arc::new(AtomicU8::new(0)),
            sent: Arc::new(AtomicU8::new(0)),
        }
    }
}

impl ExtensionsRef for FrameHeaders {
    fn extensions(&self) -> &Extensions {
        self.io.extensions()
    }
}

impl AsyncRead for FrameHeaders {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.io).poll_read(cx, buffer);
        if buffer.filled().len() > before {
            let _previous_header = self.received.compare_exchange(
                0,
                buffer.filled()[before],
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
        result
    }
}

impl AsyncWrite for FrameHeaders {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.io).poll_write(cx, bytes);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
            let _previous_header =
                self.sent
                    .compare_exchange(0, bytes[0], Ordering::Relaxed, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[tokio::test(start_paused = true)]
async fn native_h3_mitm_websocket_deflate_crosses_both_quic_hops() {
    timeout(LIMIT, async {
        let (browser_endpoint, ingress_endpoint, browser, ingress) = hop().await;
        let (egress_endpoint, origin_endpoint, egress, origin) = hop().await;
        let config = || Config {
            extended_connect: true,
            ..ordinary_config()
        };
        let (mut origin, origin_driver) = server::handshake(origin, config()).unwrap();
        let origin_driver = spawn(origin_driver.run());
        let relay_config = config();
        let relay = spawn(async move {
            Http3MitmRelay::new(Executor::new())
                .with_ingress_config(relay_config)
                .with_egress_config(ordinary_config())
                .serve(BridgeIo(ingress, egress))
                .await
        });
        let (mut browser, browser_driver) =
            client::handshake::<Body, _>(browser, ordinary_config(), Executor::new()).unwrap();
        let browser_driver = spawn(browser_driver.run());
        let request = Request::builder()
            .method(Method::CONNECT)
            .version(Version::HTTP_3)
            .uri("https://localhost/compressed")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-extensions", "permessage-deflate")
            .body(Body::empty())
            .unwrap();
        request
            .extensions()
            .insert(Protocol::from_static("websocket"));
        let (response, origin_upgrade) = tokio::join!(browser.send_request(request), async {
            let (request, response) = origin.accept().await.unwrap().resolve().await.unwrap();
            assert_eq!(
                request.extensions().get_ref::<Protocol>(),
                Some(&Protocol::from_static("websocket"))
            );
            assert_eq!(
                request.headers()["sec-websocket-extensions"],
                "permessage-deflate"
            );
            let upgrade = handle_upgrade(&request);
            response
                .send_response(
                    Response::builder()
                        .header("sec-websocket-extensions", "permessage-deflate")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            upgrade.await.unwrap()
        });
        let response = response.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["sec-websocket-extensions"],
            "permessage-deflate"
        );
        let browser_io = FrameHeaders::new(handle_upgrade(&response).await.unwrap());
        let origin_io = FrameHeaders::new(origin_upgrade);
        let headers = [
            browser_io.sent.clone(),
            browser_io.received.clone(),
            origin_io.sent.clone(),
            origin_io.received.clone(),
        ];
        let config =
            WebSocketConfig::default().with_per_message_deflate(PerMessageDeflateConfig::default());
        let mut browser_ws =
            AsyncWebSocket::from_raw_socket(browser_io, Role::Client, Some(config)).await;
        let mut origin_ws =
            AsyncWebSocket::from_raw_socket(origin_io, Role::Server, Some(config)).await;
        for sequence in 0..3 {
            let text = Message::text(format!(
                "{sequence}:{}",
                "compress across two H3 hops ".repeat(512)
            ));
            browser_ws.send_message(text.clone()).await.unwrap();
            assert_eq!(origin_ws.recv_message().await.unwrap(), text);
            let binary = Message::binary(vec![b'A' + sequence; kib(8)]);
            origin_ws.send_message(binary.clone()).await.unwrap();
            assert_eq!(browser_ws.recv_message().await.unwrap(), binary);
        }
        for first_header in headers {
            assert_ne!(
                first_header.load(Ordering::Relaxed) & 0x40,
                0,
                "RSV1 proves compressed frames actually crossed each hop"
            );
        }
        browser_ws.close(None).await.unwrap();
        assert_eq!(
            origin_ws.recv_message().await.unwrap(),
            Message::Close(None)
        );
        origin_ws.flush().await.unwrap();
        assert_eq!(
            browser_ws.recv_message().await.unwrap(),
            Message::Close(None)
        );
        drop(browser_ws);
        drop(origin_ws);
        origin.shutdown().unwrap();
        relay.await.unwrap().unwrap();
        for endpoint in [
            &browser_endpoint,
            &ingress_endpoint,
            &egress_endpoint,
            &origin_endpoint,
        ] {
            endpoint.close(0u32, b"complete");
        }
        tokio::join!(
            browser_endpoint.shutdown(),
            ingress_endpoint.shutdown(),
            egress_endpoint.shutdown(),
            origin_endpoint.shutdown()
        );
        let _drivers = tokio::join!(browser_driver, origin_driver);
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn native_h3_mitm_datagrams_preserve_carriers_across_hops() {
    timeout(LIMIT, async {
        for (ingress_native, egress_native) in [(false, false), (true, false), (false, true), (true, true)] {
            let (browser_endpoint, ingress_endpoint, browser, ingress) = hop().await;
            let (egress_endpoint, origin_endpoint, egress, origin) = hop().await;
            let config = |native| Config {
                extended_connect: true,
                datagrams: if native { Config::default().datagrams } else { None },
                ..Config::default()
            };
            let (mut origin, origin_driver) = server::handshake(origin, config(egress_native)).unwrap();
            let origin_driver = spawn(origin_driver.run());
            let relay_ingress = config(true);
            let relay_egress = config(true);
            let (trigger, signal) = oneshot::channel();
            let shutdown = rama_core::graceful::Shutdown::new(async move { _ = signal.await; });
            let exec = Executor::graceful(shutdown.guard());
            let relay = spawn(async move {
                Http3MitmRelay::new(exec).with_http_middleware((
                    MapInputLayer::new(|request: Request| {
                        if request.extensions().get_ref::<Protocol>() == Some(&Protocol::from_static("x-datagram-test")) {
                            request.extensions().insert(HttpDatagrams);
                        }
                        request
                    }),
                    MapOutputLayer::new(|response: Response| {
                        assert!(response.status().is_success());
                        response.extensions().insert(HttpDatagrams);
                        response
                    }),
                    ArcLayer::new(),
                )).with_ingress_config(relay_ingress).with_egress_config(relay_egress).serve(BridgeIo(ingress, egress)).await
            });
            let browser_connection = browser.clone();
            let (mut browser, browser_driver) =
                client::handshake::<Body, _>(browser, config(ingress_native), Executor::new()).unwrap();
            let browser_driver = spawn(browser_driver.run());
            let request = Request::builder().method(Method::CONNECT)
                .version(Version::HTTP_3).uri("https://localhost/datagrams")
                .body(Body::empty()).unwrap();
            request.extensions().insert(Protocol::from_static("x-datagram-test"));
            request.extensions().insert(HttpDatagrams);
            let (response, origin_upgrade) = tokio::join!(browser.send_request(request), async {
                let (request, response) = origin.accept().await.unwrap().resolve().await.unwrap();
                let upgrade = handle_upgrade(&request);
                let accepted = Response::new(Body::empty());
                accepted.extensions().insert(HttpDatagrams);
                response.send_response(accepted).await.unwrap();
                upgrade.await.unwrap()
            });
            let response = response.unwrap();
            let mut session = SessionConfig::default();
            session.capsules.unknown = UnknownCapsules::Forward;
            let mut browser_session = HttpDatagramSession::with_config(handle_upgrade(&response).await.unwrap(), session.clone());
            let mut origin_session = HttpDatagramSession::with_config(origin_upgrade, session);
            // Each hop mirrors the other peer's SETTINGS, so a hop is native only when both are.
            let native = if ingress_native && egress_native { DatagramTransport::Native } else { DatagramTransport::Capsule };
            let sent = browser_session.send_datagram(Bytes::from_static(b"up")).await.unwrap();
            assert_eq!(sent, native);
            assert_eq!(origin_session.recv().await.unwrap(), Some(SessionEvent::Datagram {
                payload: Bytes::from_static(b"up"),
                transport: if ingress_native && egress_native { DatagramTransport::Native } else { DatagramTransport::Capsule },
            }));
            let sent = origin_session.send_datagram(Bytes::from_static(b"down")).await.unwrap();
            assert_eq!(sent, native);
            assert_eq!(browser_session.recv().await.unwrap(), Some(SessionEvent::Datagram {
                payload: Bytes::from_static(b"down"),
                transport: if ingress_native && egress_native { DatagramTransport::Native } else { DatagramTransport::Capsule },
            }));
            // Even when both peers negotiated native datagrams, a reliable
            // capsule must remain reliable through the intermediary.
            browser_session.send_capsule(CapsuleType::DATAGRAM, Bytes::from_static(b"reliable")).await.unwrap();
            assert_eq!(origin_session.recv().await.unwrap(), Some(SessionEvent::Datagram {
                payload: Bytes::from_static(b"reliable"), transport: DatagramTransport::Capsule,
            }));
            let unknown = CapsuleType::new(0x4242).unwrap();
            origin_session.send_capsule(unknown, Bytes::from_static(b"opaque control")).await.unwrap();
            assert!(matches!(browser_session.recv().await.unwrap(), Some(SessionEvent::UnknownCapsule(header)) if header.ty == unknown));
            let mut value = Vec::new();
            while value.len() < b"opaque control".len() {
                let Some(SessionEvent::UnknownCapsuleData(chunk)) = browser_session.recv().await.unwrap() else { panic!("expected opaque capsule value") };
                value.extend_from_slice(&chunk);
            }
            assert_eq!(value, b"opaque control");
            trigger.send(()).unwrap();
            let shutdown = spawn(shutdown.shutdown_with_limit(LIMIT));
            browser.closed_or_draining().await;
            assert!(!relay.is_finished(), "the default relay must drain an open tunnel on shutdown");
            origin_session.send_capsule(CapsuleType::DATAGRAM, Bytes::from_static(b"after GOAWAY")).await.unwrap();
            assert!(matches!(browser_session.recv().await.unwrap(), Some(SessionEvent::Datagram { payload, .. }) if payload == b"after GOAWAY"[..]));
            browser_session.close().await.unwrap();
            assert_eq!(origin_session.recv().await.unwrap(), None);
            origin_session.close().await.unwrap();
            // After the last tunnel drains, a native receiver may observe the
            // connection closing before it consumes the stream's FIN. Reliable
            // payload delivery after GOAWAY was asserted above.
            match browser_session.recv().await {
                Ok(None) => (),
                Err(rama_http::datagram::SessionError::NativeRecv(rama_http::datagram::NativeRecvError::Lost)) => {
                    let closed = browser_connection.closed().await;
                    assert!(matches!(&closed, ConnectionError::ApplicationClosed(close)
                        if close.error_code == VarInt::from_u32(Code::H3_NO_ERROR.value() as u32)), "{closed:?}");
                },
                result => panic!("unexpected end after graceful drain: {result:?}"),
            }
            origin.shutdown().unwrap();
            relay.await.unwrap().unwrap();
            for endpoint in [&browser_endpoint, &ingress_endpoint, &egress_endpoint, &origin_endpoint] { endpoint.close(0u32, b"complete"); }
            tokio::join!(browser_endpoint.shutdown(), ingress_endpoint.shutdown(), egress_endpoint.shutdown(), origin_endpoint.shutdown());
            let _drivers = tokio::join!(browser_driver, origin_driver);
            shutdown.await.unwrap().unwrap();
        }
    }).await.unwrap();
}

#[tokio::test]
async fn native_h3_mitm_ignores_origin_settings_it_does_not_understand() {
    timeout(LIMIT, async {
        let (browser_endpoint, ingress_endpoint, browser, ingress) = hop().await;
        let (egress_endpoint, origin_endpoint, egress, origin) = hop().await;
        let mut origin_config = ordinary_config();
        // WebTransport and the draft HTTP datagram identifier: extensions nothing here knows.
        origin_config.settings_profile = Some(settings_profile(
            &origin_config,
            &[
                (SettingId::new(0x2b60_3742), 1),
                (SettingId::new(0xff_d277), 1),
            ],
        ));
        let (mut origin, origin_driver) = server::handshake(origin, origin_config).unwrap();
        let origin_driver = spawn(origin_driver.run());
        let relay = spawn(async move {
            Http3MitmRelay::new(Executor::new())
                .with_ingress_config(ordinary_config())
                .with_egress_config(ordinary_config())
                .serve(BridgeIo(ingress, egress))
                .await
        });
        let (mut browser, browser_driver) =
            client::handshake::<Body, _>(browser, ordinary_config(), Executor::new()).unwrap();
        let browser_driver = spawn(browser_driver.run());
        let seen = browser.peer_settings().await.unwrap();
        for unknown in [SettingId::new(0x2b60_3742), SettingId::new(0xff_d277)] {
            assert_eq!(
                seen.get(unknown),
                None,
                "{unknown:?} is the origin's, not the relay's"
            );
        }
        let request = Request::builder()
            .uri("https://localhost/")
            .body(Body::empty())
            .unwrap();
        let (sent, received) = tokio::join!(browser.send_request(request), async {
            let (_request, response) = origin.accept().await.unwrap().resolve().await.unwrap();
            response.send_response(Response::new(Body::empty())).await
        });
        received.unwrap();
        assert_eq!(sent.unwrap().status(), StatusCode::OK);
        origin.shutdown().unwrap();
        relay.await.unwrap().unwrap();
        for endpoint in [
            &browser_endpoint,
            &ingress_endpoint,
            &egress_endpoint,
            &origin_endpoint,
        ] {
            endpoint.close(0u32, b"complete");
        }
        tokio::join!(
            browser_endpoint.shutdown(),
            ingress_endpoint.shutdown(),
            egress_endpoint.shutdown(),
            origin_endpoint.shutdown()
        );
        let _drivers = tokio::join!(browser_driver, origin_driver);
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn native_h3_mitm_lowers_early_data_and_push_instead_of_refusing() {
    timeout(LIMIT, async {
        let with_pushes = || Config {
            max_pushes: 1,
            ..ordinary_config()
        };
        let cases: [(&str, bool, bool, Config, Config); 4] = [
            (
                "early ingress",
                true,
                false,
                ordinary_config(),
                ordinary_config(),
            ),
            (
                "early egress",
                false,
                true,
                ordinary_config(),
                ordinary_config(),
            ),
            (
                "ingress push",
                false,
                false,
                with_pushes(),
                ordinary_config(),
            ),
            (
                "egress push",
                false,
                false,
                ordinary_config(),
                with_pushes(),
            ),
        ];
        for (name, early_ingress, early_egress, ingress_config, egress_config) in cases {
            let (browser_endpoint, ingress_endpoint, browser, ingress) = if early_ingress {
                resumed_hop().await
            } else {
                hop().await
            };
            let (egress_endpoint, origin_endpoint, egress, origin) = if early_egress {
                resumed_hop().await
            } else {
                hop().await
            };
            let (mut origin, origin_driver) = server::handshake(origin, ordinary_config()).unwrap();
            let origin_driver = spawn(origin_driver.run());
            let relay = spawn(async move {
                Http3MitmRelay::new(Executor::new())
                    .with_ingress_config(ingress_config)
                    .with_egress_config(egress_config)
                    .serve(BridgeIo(ingress, egress))
                    .await
            });
            let (mut browser, browser_driver) =
                client::handshake::<Body, _>(browser, ordinary_config(), Executor::new()).unwrap();
            let browser_driver = spawn(browser_driver.run());
            let (sent, received) = tokio::join!(
                browser.send_request(
                    Request::builder()
                        .uri("https://localhost/")
                        .body(Body::empty())
                        .unwrap()
                ),
                async {
                    let (_request, response) =
                        origin.accept().await.unwrap().resolve().await.unwrap();
                    response.send_response(Response::new(Body::empty())).await
                },
            );
            received.unwrap();
            assert_eq!(sent.unwrap().status(), StatusCode::OK, "{name}");
            origin.shutdown().unwrap();
            relay.await.unwrap().unwrap();
            for endpoint in [
                &browser_endpoint,
                &ingress_endpoint,
                &egress_endpoint,
                &origin_endpoint,
            ] {
                endpoint.close(0u32, b"complete");
            }
            let _drivers = tokio::join!(origin_driver, browser_driver);
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn native_h3_mitm_refuses_swapped_sides_before_any_control_output() {
    timeout(LIMIT, async {
        let (_browser_endpoint, _ingress_endpoint, browser, ingress) = hop().await;
        let (_egress_endpoint, _origin_endpoint, egress, _origin) = hop().await;
        let error = Http3MitmRelay::new(Executor::new())
            .with_ingress_config(ordinary_config())
            .with_egress_config(ordinary_config())
            .serve(BridgeIo(egress, ingress))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("server ingress"), "{error}");
        assert!(browser.accept_uni().await.is_err(), "control output");
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn native_h3_mitm_bounds_ingress_field_sections_by_the_origin() {
    const ORIGIN_LIMIT: usize = 1024;
    timeout(LIMIT, async {
        let (browser_endpoint, ingress_endpoint, browser, ingress) = hop().await;
        let (egress_endpoint, origin_endpoint, egress, origin) = hop().await;
        let mut origin_config = ordinary_config();
        origin_config.decoder.max_field_section_size = ORIGIN_LIMIT;
        let (mut origin, origin_driver) = server::handshake(origin, origin_config).unwrap();
        let origin_driver = spawn(origin_driver.run());
        let relay = spawn(async move {
            Http3MitmRelay::new(Executor::new())
                .with_ingress_config(ordinary_config())
                .with_egress_config(ordinary_config())
                .serve(BridgeIo(ingress, egress))
                .await
        });
        let (mut browser, browser_driver) =
            client::handshake::<Body, _>(browser, ordinary_config(), Executor::new()).unwrap();
        let browser_driver = spawn(browser_driver.run());
        let advertised = browser
            .peer_settings()
            .await
            .unwrap()
            .max_field_section_size();
        assert_eq!(advertised, Some(ORIGIN_LIMIT as u64));
        let request = Request::builder()
            .uri("https://localhost/")
            .header("x-oversized", "x".repeat(2 * ORIGIN_LIMIT))
            .body(Body::empty())
            .unwrap();
        browser.send_request(request).await.unwrap_err();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), origin.accept())
                .await
                .is_err(),
            "the origin saw an oversized request"
        );
        origin.shutdown().unwrap();
        relay.await.unwrap().unwrap();
        for endpoint in [
            &browser_endpoint,
            &ingress_endpoint,
            &egress_endpoint,
            &origin_endpoint,
        ] {
            endpoint.close(0u32, b"complete");
        }
        tokio::join!(
            browser_endpoint.shutdown(),
            ingress_endpoint.shutdown(),
            egress_endpoint.shutdown(),
            origin_endpoint.shutdown()
        );
        let _drivers = tokio::join!(browser_driver, origin_driver);
    })
    .await
    .unwrap();
}

async fn assert_relay_ended(peers: [&Connection; 2]) {
    let internal = VarInt::from_u32(Code::H3_INTERNAL_ERROR.value() as u32);
    for peer in peers {
        let closed = peer.closed().await;
        assert!(
            matches!(&closed, ConnectionError::ApplicationClosed(close) if close.error_code == internal),
            "{closed:?}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn native_h3_mitm_failure_and_cancellation_end_both_hops_as_internal_errors() {
    timeout(LIMIT, async {
        for cancel in [false, true] {
            let (_browser_endpoint, _ingress_endpoint, browser, ingress) = hop().await;
            let (_egress_endpoint, _origin_endpoint, egress, origin) = hop().await;
            let (_origin, origin_driver) =
                server::handshake(origin.clone(), ordinary_config()).unwrap();
            let _origin_driver = spawn(origin_driver.run());
            let mut ingress_config = ordinary_config();
            if !cancel {
                // Fails the ingress HTTP/3 handshake after the egress one succeeded.
                ingress_config.decoder.max_table_capacity = u64::MAX;
            }
            let relay = spawn(async move {
                Http3MitmRelay::new(Executor::new())
                    .with_ingress_config(ingress_config)
                    .with_egress_config(ordinary_config())
                    .serve(BridgeIo(ingress, egress))
                    .await
            });
            // The browser's client lives until the assertion, so it cannot close its own hop.
            let (sender, driver) =
                client::handshake::<Body, _>(browser.clone(), ordinary_config(), Executor::new())
                    .unwrap();
            let _driver = spawn(driver.run());
            if cancel {
                sender.peer_settings().await.unwrap();
                relay.abort();
            } else {
                relay.await.unwrap().unwrap_err();
            }
            assert_relay_ended([&browser, &origin]).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn native_h3_mitm_mirrors_initial_client_settings() {
    timeout(LIMIT, async {
        for extra in [
            None,
            Some(SettingId::FIRST_RESERVED),
            Some(SettingId::ENABLE_CONNECT_PROTOCOL),
        ] {
            let (browser_endpoint, ingress_endpoint, browser, ingress) = hop().await;
            let (egress_endpoint, origin_endpoint, egress, origin) = hop().await;
            let (mut origin, origin_driver) = server::handshake(origin, ordinary_config()).unwrap();
            let origin_driver = spawn(origin_driver.run());
            let mut ceiling = Config::default();
            ceiling.decoder.max_field_section_size = mib(10);
            ceiling.max_frame_size = mib(10);
            let mut literal = Settings::new();
            literal
                .set(SettingId::MAX_FIELD_SECTION_SIZE, mib_u64(10))
                .unwrap();
            literal.set(SettingId::H3_DATAGRAM, 1).unwrap();
            if let Some(id) = extra {
                literal.set(id, 1).unwrap();
            }
            let browser_config = ceiling
                .try_with_client_settings(Arc::new(literal.clone()))
                .unwrap();
            let relay = spawn(async move {
                Http3MitmRelay::new(Executor::new())
                    .with_ingress_config(Config::default())
                    .with_egress_config(ceiling)
                    .serve(BridgeIo(ingress, egress))
                    .await
            });
            let (mut browser, browser_driver) =
                client::handshake::<Body, _>(browser, browser_config, Executor::new()).unwrap();
            let browser_driver = spawn(browser_driver.run());
            let actual = origin.peer_settings().await.unwrap();
            assert_eq!(
                actual, literal,
                "origin did not receive the client's ordered SETTINGS"
            );
            assert!(actual.get(SettingId::QPACK_MAX_TABLE_CAPACITY).is_none());
            assert!(actual.get(SettingId::QPACK_BLOCKED_STREAMS).is_none());
            assert!(
                !browser
                    .peer_settings()
                    .await
                    .unwrap()
                    .enable_connect_protocol(),
                "client advertisement must not authorize server Extended CONNECT"
            );
            let (sent, received) = tokio::join!(
                browser.send_request(
                    Request::builder()
                        .uri("https://localhost/")
                        .body(Body::empty())
                        .unwrap()
                ),
                async {
                    let (_request, response) =
                        origin.accept().await.unwrap().resolve().await.unwrap();
                    response.send_response(Response::new(Body::empty())).await
                },
            );
            received.unwrap();
            sent.unwrap().into_body().collect().await.unwrap();
            origin.shutdown().unwrap();
            relay.await.unwrap().unwrap();
            for endpoint in [
                &browser_endpoint,
                &ingress_endpoint,
                &egress_endpoint,
                &origin_endpoint,
            ] {
                endpoint.close(0u32, b"complete");
            }
            origin_driver.await.unwrap().unwrap();
            browser_driver.await.unwrap().unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn native_h3_mitm_fits_client_settings_to_egress_budgets_and_capabilities() {
    timeout(LIMIT, async {
        for case in [
            "field limit",
            "table capacity",
            "blocked streams",
            "datagrams",
            "extension",
            "egress profile",
        ] {
            let (browser_endpoint, ingress_endpoint, browser, ingress) = hop().await;
            let (egress_endpoint, origin_endpoint, egress, origin) = hop().await;
            let (origin, origin_driver) = server::handshake(origin, ordinary_config()).unwrap();
            let _origin_driver = spawn(origin_driver.run());
            let mut literal = Settings::new();
            let mut client_ceiling = Config::default();
            client_ceiling.decoder.max_table_capacity = 65536;
            client_ceiling.decoder.max_blocked_streams = 100;
            client_ceiling.decoder.max_field_section_size = mib(10);
            let mut egress_config = ordinary_config();
            let local = egress_config.decoder;
            // What the origin must see instead: lowered to the egress budget, or dropped.
            let mut expected = Settings::new();
            match case {
                "field limit" => {
                    literal
                        .set(SettingId::MAX_FIELD_SECTION_SIZE, mib_u64(10))
                        .unwrap();
                    expected
                        .set(
                            SettingId::MAX_FIELD_SECTION_SIZE,
                            local.max_field_section_size as u64,
                        )
                        .unwrap();
                }
                "table capacity" => {
                    literal
                        .set(SettingId::QPACK_MAX_TABLE_CAPACITY, 65536)
                        .unwrap();
                    expected
                        .set(
                            SettingId::QPACK_MAX_TABLE_CAPACITY,
                            local.max_table_capacity,
                        )
                        .unwrap();
                }
                "blocked streams" => {
                    literal.set(SettingId::QPACK_BLOCKED_STREAMS, 100).unwrap();
                    expected
                        .set(SettingId::QPACK_BLOCKED_STREAMS, local.max_blocked_streams)
                        .unwrap();
                }
                "datagrams" => literal.set(SettingId::H3_DATAGRAM, 1).unwrap(),
                "extension" => literal.set(SettingId::new(0xface), 1).unwrap(),
                "egress profile" => {
                    let profile =
                        settings_profile(&egress_config, &[(SettingId::FIRST_RESERVED, 1)]);
                    expected = Settings::clone(&profile);
                    egress_config.settings_profile = Some(profile);
                }
                _ => panic!("unknown native SETTINGS fitting test case: {case}"),
            }
            assert!(
                local.max_field_section_size < mib(10)
                    && local.max_table_capacity < 65536
                    && local.max_blocked_streams < 100,
                "{case}: the egress budget must be the lower one"
            );
            let client_config = client_ceiling
                .try_with_client_settings(Arc::new(literal))
                .unwrap();
            let relay = spawn(async move {
                Http3MitmRelay::new(Executor::new())
                    .with_ingress_config(ordinary_config())
                    .with_egress_config(egress_config)
                    .serve(BridgeIo(ingress, egress))
                    .await
            });
            let (sender, driver) =
                client::handshake::<Body, _>(browser, client_config, Executor::new()).unwrap();
            let _driver = spawn(driver.run());
            assert_eq!(
                origin.peer_settings().await.unwrap(),
                expected,
                "{case}: origin SETTINGS"
            );
            relay.abort();
            drop(sender);
            for endpoint in [
                &browser_endpoint,
                &ingress_endpoint,
                &egress_endpoint,
                &origin_endpoint,
            ] {
                endpoint.close(0u32, b"complete");
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn native_h3_mitm_late_settings_leave_the_other_hop_on_its_own() {
    timeout(LIMIT, async {
        // One absolute deadline: an origin answering within a fresh budget after the
        // client's SETTINGS is still late.
        for (late, browser_delay, origin_delay) in [
            ("client", Duration::from_millis(1500), Duration::ZERO),
            (
                "origin",
                Duration::from_millis(500),
                Duration::from_millis(1200),
            ),
        ] {
            let (browser_endpoint, ingress_endpoint, browser, ingress) = hop().await;
            let (egress_endpoint, origin_endpoint, egress, origin) = hop().await;
            let extended = Config {
                extended_connect: true,
                ..ordinary_config()
            };
            let (mut origin, origin_driver) = server::handshake(origin, extended.clone()).unwrap();
            let origin_driver = spawn(async move {
                tokio::time::sleep(origin_delay).await;
                origin_driver.run().await
            });
            let mut literal = Settings::new();
            literal.set(SettingId::FIRST_RESERVED, 1).unwrap();
            let browser_config = ordinary_config()
                .try_with_client_settings(Arc::new(literal))
                .unwrap();
            let relay = spawn(async move {
                Http3MitmRelay::new(Executor::new())
                    .with_ingress_config(extended)
                    .with_egress_config(ordinary_config())
                    .with_settings_timeout(Duration::from_secs(1))
                    .serve(BridgeIo(ingress, egress))
                    .await
            });
            let (mut browser, browser_driver) =
                client::handshake::<Body, _>(browser, browser_config, Executor::new()).unwrap();
            let browser_driver = spawn(async move {
                tokio::time::sleep(browser_delay).await;
                browser_driver.run().await
            });
            let mirrored = origin.peer_settings().await.unwrap();
            assert_eq!(
                mirrored.get(SettingId::FIRST_RESERVED).is_some(),
                late != "client",
                "{late}: egress SETTINGS"
            );
            assert_eq!(
                browser
                    .peer_settings()
                    .await
                    .unwrap()
                    .enable_connect_protocol(),
                late != "origin",
                "{late}: ingress SETTINGS"
            );
            let (sent, received) = tokio::join!(
                browser.send_request(
                    Request::builder()
                        .uri("https://localhost/")
                        .body(Body::empty())
                        .unwrap()
                ),
                async {
                    let (_request, response) =
                        origin.accept().await.unwrap().resolve().await.unwrap();
                    response.send_response(Response::new(Body::empty())).await
                },
            );
            received.unwrap();
            assert_eq!(sent.unwrap().status(), StatusCode::OK, "{late}");
            origin.shutdown().unwrap();
            relay.await.unwrap().unwrap();
            for endpoint in [
                &browser_endpoint,
                &ingress_endpoint,
                &egress_endpoint,
                &origin_endpoint,
            ] {
                endpoint.close(0u32, b"complete");
            }
            let _drivers = tokio::join!(origin_driver, browser_driver);
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn native_h3_mitm_mirrors_known_origin_settings() {
    timeout(LIMIT, async {
        for case in ["go", "zero", "qpack", "omitted", "unknown"] {
            let (browser_endpoint, ingress_endpoint, browser, ingress) = hop().await;
            let (egress_endpoint, origin_endpoint, egress, origin) = hop().await;
            let mut ceiling = Config {
                extended_connect: true,
                ..Default::default()
            };
            ceiling.decoder.max_field_section_size = mib(1);
            ceiling.max_frame_size = mib(1);
            let mut expected = Settings::new();
            match case {
                "go" | "unknown" => {
                    expected
                        .set(SettingId::MAX_FIELD_SECTION_SIZE, mib_u64(1))
                        .unwrap();
                    expected.set(SettingId::H3_DATAGRAM, 1).unwrap();
                    expected.set(SettingId::ENABLE_CONNECT_PROTOCOL, 1).unwrap();
                }
                "zero" => {
                    expected.set(SettingId::H3_DATAGRAM, 0).unwrap();
                    expected.set(SettingId::ENABLE_CONNECT_PROTOCOL, 0).unwrap();
                    expected.set(SettingId::QPACK_BLOCKED_STREAMS, 0).unwrap();
                    expected
                        .set(SettingId::QPACK_MAX_TABLE_CAPACITY, 0)
                        .unwrap();
                }
                "qpack" => {
                    expected
                        .set(
                            SettingId::QPACK_BLOCKED_STREAMS,
                            ceiling.decoder.max_blocked_streams,
                        )
                        .unwrap();
                    expected
                        .set(
                            SettingId::QPACK_MAX_TABLE_CAPACITY,
                            ceiling.decoder.max_table_capacity,
                        )
                        .unwrap();
                    expected.set(SettingId::ENABLE_CONNECT_PROTOCOL, 0).unwrap();
                    expected
                        .set(SettingId::MAX_FIELD_SECTION_SIZE, 65536)
                        .unwrap();
                    expected.set(SettingId::H3_DATAGRAM, 0).unwrap();
                }
                "omitted" => {}
                _ => panic!("unknown origin SETTINGS test case: {case}"),
            }
            let mut advertised = Settings::new();
            if case == "unknown" {
                advertised.set(SettingId::new(0x2b60_3742), 1).unwrap();
            }
            for setting in expected.entries() {
                advertised.insert(*setting).unwrap();
            }
            if case == "unknown" {
                advertised.set(SettingId::FIRST_RESERVED, 17).unwrap();
                advertised.set(SettingId::new(0xff_d277), 1).unwrap();
            }
            let origin_config = ceiling
                .try_with_server_settings(Arc::new(advertised))
                .unwrap();
            let (mut origin, origin_driver) = server::handshake(origin, origin_config).unwrap();
            let origin_driver = spawn(origin_driver.run());
            let relay = spawn(async move {
                Http3MitmRelay::new(Executor::new())
                    .with_ingress_config(ceiling)
                    .with_egress_config(Config::default())
                    .serve(BridgeIo(ingress, egress))
                    .await
            });
            let (mut browser, browser_driver) =
                client::handshake::<Body, _>(browser, Config::default(), Executor::new()).unwrap();
            let browser_driver = spawn(browser_driver.run());
            if case == "unknown" {
                // Inert GREASE is kept in place, as in the client direction.
                expected.set(SettingId::FIRST_RESERVED, 17).unwrap();
            }
            let actual = browser.peer_settings().await.unwrap();
            assert_eq!(actual, expected, "{case}: actual ingress SETTINGS");
            for ignored in [SettingId::new(0x2b60_3742), SettingId::new(0xff_d277)] {
                assert_eq!(actual.get(ignored), None, "{case}: {ignored:?} advertised");
            }
            let (sent, received) = tokio::join!(
                browser.send_request(
                    Request::builder()
                        .uri("https://localhost/")
                        .header("x-order-probe", "known-origin-settings")
                        .body(Body::empty())
                        .unwrap()
                ),
                async {
                    let (request, response) =
                        origin.accept().await.unwrap().resolve().await.unwrap();
                    assert_eq!(request.headers()["x-order-probe"], "known-origin-settings");
                    response.send_response(Response::new(Body::empty())).await
                },
            );
            received.unwrap();
            sent.unwrap().into_body().collect().await.unwrap();
            origin.shutdown().unwrap();
            relay.await.unwrap().unwrap();
            for endpoint in [
                &browser_endpoint,
                &ingress_endpoint,
                &egress_endpoint,
                &origin_endpoint,
            ] {
                endpoint.close(0u32, b"complete");
            }
            tokio::join!(
                browser_endpoint.shutdown(),
                ingress_endpoint.shutdown(),
                egress_endpoint.shutdown(),
                origin_endpoint.shutdown()
            );
            browser_driver.await.unwrap().unwrap();
            origin_driver.await.unwrap().unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn native_h3_mitm_fits_origin_settings_to_ingress_and_both_hop_capabilities() {
    timeout(LIMIT, async {
        for case in [
            "field limit",
            "table capacity",
            "blocked streams",
            "connect grant",
            "ingress datagram policy",
            "egress datagram policy",
            "browser datagram transport",
            "ingress datagram transport",
            "egress datagram transport",
            "origin datagram transport",
            "ingress profile",
        ] {
            let disabled =
                Arc::new(TransportConfig::default().maybe_with_datagram_receive_buffer_size(None));
            let (browser_endpoint, ingress_endpoint, browser, ingress) = hop_with_transports(
                false,
                (case == "browser datagram transport").then(|| disabled.clone()),
                (case == "ingress datagram transport").then(|| disabled.clone()),
            )
            .await;
            let (egress_endpoint, origin_endpoint, egress, origin) = hop_with_transports(
                false,
                (case == "egress datagram transport").then(|| disabled.clone()),
                (case == "origin datagram transport").then(|| disabled.clone()),
            )
            .await;
            let mut ingress_config = Config::default();
            let mut egress_config = Config::default();
            let local = ingress_config.decoder;
            assert!(local.max_field_section_size < mib(1));
            let mut advertised = Settings::new();
            // What the browser must see instead: lowered to ingress budgets, grants dropped.
            let mut expected = Settings::new();
            let field_limit = if case == "field limit" {
                mib_u64(1)
            } else {
                kib_u64(1)
            };
            advertised
                .set(SettingId::MAX_FIELD_SECTION_SIZE, field_limit)
                .unwrap();
            expected
                .set(
                    SettingId::MAX_FIELD_SECTION_SIZE,
                    field_limit.min(local.max_field_section_size as u64),
                )
                .unwrap();
            match case {
                "field limit" | "ingress profile" => {}
                "table capacity" => {
                    advertised
                        .set(
                            SettingId::QPACK_MAX_TABLE_CAPACITY,
                            local.max_table_capacity + 1,
                        )
                        .unwrap();
                    expected
                        .set(
                            SettingId::QPACK_MAX_TABLE_CAPACITY,
                            local.max_table_capacity,
                        )
                        .unwrap();
                }
                "blocked streams" => {
                    advertised
                        .set(
                            SettingId::QPACK_BLOCKED_STREAMS,
                            local.max_blocked_streams + 1,
                        )
                        .unwrap();
                    expected
                        .set(SettingId::QPACK_BLOCKED_STREAMS, local.max_blocked_streams)
                        .unwrap();
                }
                "connect grant" => advertised
                    .set(SettingId::ENABLE_CONNECT_PROTOCOL, 1)
                    .unwrap(),
                _ => {
                    advertised.set(SettingId::H3_DATAGRAM, 1).unwrap();
                    if case == "ingress datagram policy" {
                        ingress_config.datagrams = None;
                    }
                    if case == "egress datagram policy" {
                        egress_config.datagrams = None;
                    }
                }
            }
            if case == "ingress profile" {
                // An explicit caller profile is advertised as configured.
                let profile = settings_profile(&ingress_config, &[]);
                expected = Settings::clone(&profile);
                ingress_config.settings_profile = Some(profile);
                ingress_config.datagrams = None;
            }
            let relay = spawn(async move {
                Http3MitmRelay::new(Executor::new())
                    .with_ingress_config(ingress_config)
                    .with_egress_config(egress_config)
                    .serve(BridgeIo(ingress, egress))
                    .await
            });
            let (sender, driver) =
                client::handshake::<Body, _>(browser, Config::default(), Executor::new()).unwrap();
            let _driver = spawn(driver.run());
            // Emit the origin's native SETTINGS directly so a missing QUIC DATAGRAM
            // capability can be tested without our server builder rejecting it first.
            let mut payload = Vec::new();
            advertised.encode_payload(&mut payload).unwrap();
            let mut bytes = Vec::new();
            VarInt::from_u64(StreamType::CONTROL.value())
                .unwrap()
                .encode(&mut bytes);
            FrameHeader::new(FrameType::SETTINGS, payload.len() as u64)
                .encode(&mut bytes)
                .unwrap();
            bytes.extend_from_slice(&payload);
            let mut control = origin.open_uni().await.unwrap();
            control.write_all(&bytes).await.unwrap();
            assert_eq!(
                sender.peer_settings().await.unwrap(),
                expected,
                "{case}: browser SETTINGS"
            );
            relay.abort();
            drop((sender, control));
            for endpoint in [
                &browser_endpoint,
                &ingress_endpoint,
                &egress_endpoint,
                &origin_endpoint,
            ] {
                endpoint.close(0u32, b"complete");
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn clean_carrier_close_drains_datagrams_through_the_mitm() {
    timeout(LIMIT, Box::pin(async {
        let count = 64;
        let (browser_endpoint, ingress_endpoint, browser, ingress) = hop().await;
        let (egress_endpoint, origin_endpoint, egress, origin) = hop().await;
        let config = Config {
            extended_connect: true,
            datagrams: Some(rama_http_core::h3::DatagramConfig {
                limits: rama_http_core::h3::DatagramLimits { queue_len: count, ..Default::default() },
                ..Default::default()
            }),
            ..Default::default()
        };
        let (mut origin_http, origin_driver) = server::handshake(origin, config.clone()).unwrap();
        let origin_driver = spawn(origin_driver.run());
        let browser_connection = browser.clone();
        let ingress_connection = ingress.clone();
        let relay = Http3MitmRelay::new(Executor::new())
            .with_ingress_config(config.clone()).with_egress_config(config.clone())
            .with_http_middleware((
                MapInputLayer::new(|request: Request| { request.extensions().insert(HttpDatagrams); request }),
                MapOutputLayer::new(|response: Response| { response.extensions().insert(HttpDatagrams); response }),
                ArcLayer::new(),
            ));
        let mut forwarding = pin!(relay.serve(BridgeIo(ingress, egress)));
        let (mut browser_http, browser_driver) = client::handshake::<Body, _>(browser, config, Executor::new()).unwrap();
        let browser_driver = spawn(browser_driver.run());
        let request = Request::builder().method(Method::CONNECT).uri("https://localhost/datagrams").body(Body::empty()).unwrap();
        request.extensions().insert(HttpDatagrams);
        request.extensions().insert(Protocol::CONNECT_UDP);
        let (browser_io, origin_io) = tokio::select! {
            tunnels = async {
                let (response, origin_io) = tokio::join!(browser_http.send_request(request), async {
                    let (request, response) = origin_http.accept().await.unwrap().resolve().await.unwrap();
                    let upgrade = handle_upgrade(&request);
                    let accepted = Response::new(Body::empty());
                    accepted.extensions().insert(HttpDatagrams);
                    response.send_response(accepted).await.unwrap();
                    upgrade.await.unwrap()
                });
                (handle_upgrade(&response.unwrap()).await.unwrap(), origin_io)
            } => tunnels,
            result = &mut forwarding => panic!("relay ended during setup: {result:?}"),
        };
        let mut browser_io = HttpDatagramSession::new(browser_io);
        let mut origin_io = HttpDatagramSession::new(origin_io);
        // Pause dispatch, but leave the lossless transport running.
        for index in 0..count { browser_io.send_datagram(Bytes::from(vec![index as u8])).await.unwrap(); }
        browser_io.close().await.unwrap();
        assert_eq!(ingress_connection.received_datagrams(), count);
        browser_connection.close(Code::H3_NO_ERROR.value() as u32, b"done");
        ingress_connection.closed().await;
        let delivered = async {
            for index in 0..count {
                assert!(matches!(origin_io.recv().await.unwrap(), Some(SessionEvent::Datagram { payload, .. }) if payload == [index as u8][..]), "payload {index}");
            }
            assert_eq!(origin_io.recv().await.unwrap(), None);
            origin_io.close().await.unwrap();
        };
        let (result, ()) = tokio::join!(forwarding, delivered);
        result.unwrap();
        for endpoint in [&browser_endpoint, &ingress_endpoint, &egress_endpoint, &origin_endpoint] { endpoint.close(0u32, b"done"); }
        tokio::join!(browser_endpoint.wait_idle(), ingress_endpoint.wait_idle(), egress_endpoint.wait_idle(), origin_endpoint.wait_idle());
        let _drivers = tokio::join!(browser_driver, origin_driver);
    })).await.unwrap();
}
