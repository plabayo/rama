//! A failed reply must not hide tunnel payloads already received by the carrier.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "integration fixture setup and protocol assertions"
)]

use rama_core::{bytes::Bytes, extensions::ExtensionsRef as _, rt::Executor, service::service_fn};
use rama_http::proto::{ext::HttpDatagrams, ext::Protocol, h3::Code};
use rama_http::{
    Body, Method, Request, Response, datagram::HttpDatagramSession, io::upgrade::handle_upgrade,
};
use rama_http_backend::server::HttpServer;
use rama_http_core::h3::{DatagramConfig, DatagramLimits, client, connection::Config};
use rama_masque::connect_udp::{ConnectUdpSocket, ConnectUdpSocketConfig, session_config};
use rama_net::address::SocketAddress;
use rama_quic::{ClientConfig, Endpoint, ServerConfig, TransportConfig, tls::TlsOptions};
use rama_tls::{
    client::TlsClientConfig,
    server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
};
use rama_udp::{
    DatagramError, DatagramSenderExt as _, DatagramSocket as _, DatagramSocketExt as _,
    SendDatagram, test_utils::MemoryDatagramSocket,
};
use std::{convert::Infallible, num::NonZeroUsize, pin::pin, sync::Arc, time::Duration};
use tokio::{sync::mpsc, time::timeout};

const LIMIT: Duration = Duration::from_secs(5);

#[tokio::test(start_paused = true)]
async fn received_datagrams_survive_a_failed_reply() {
    for native in [false, true] {
        for filed_first in [false, true] {
            failed_reply(native, filed_first).await;
        }
    }
}

async fn failed_reply(native: bool, filed_first: bool) {
    timeout(LIMIT, async {
        let (client_endpoint, server_endpoint, client_connection, server_connection) =
            connection_pair().await;
        // Exercise payloads filed both before and after the failed reply, on each carrier.
        let count = 4;
        let mut http = HttpServer::new_http3(Executor::new());
        http.http3_mut().extended_connect = true;
        http.http3_mut().datagrams = Some(DatagramConfig {
            limits: DatagramLimits {
                queue_len: count,
                ..Default::default()
            },
            ..Default::default()
        });
        if !native {
            http.http3_mut().datagrams = None;
        }
        let (upgrades, mut upgraded) = mpsc::unbounded_channel();
        let mut serving = pin!(http.serve(
            server_connection.clone(),
            service_fn(move |request: Request| {
                let upgrades = upgrades.clone();
                async move {
                    tokio::spawn(async move {
                        upgrades
                            .send(handle_upgrade(&request).await.unwrap())
                            .unwrap();
                    });
                    let response = Response::new(Body::empty());
                    response.extensions().insert(HttpDatagrams);
                    Ok::<_, Infallible>(response)
                }
            }),
        ));
        let (mut client, driver) = client::handshake::<Body>(
            client_connection.clone(),
            Config {
                datagrams: native.then(Default::default),
                ..Config::default()
            },
            Executor::new(),
        )
        .unwrap();
        let client_driver = tokio::spawn(driver.run());
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri("https://localhost/datagrams")
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(HttpDatagrams);
        request
            .extensions()
            .insert(Protocol::from_static("connect-udp"));
        let (client_io, server_io) = tokio::select! {
            sessions = async {
                let response = client.send_request(request).await.unwrap();
                (handle_upgrade(&response).await.unwrap(), upgraded.recv().await.unwrap())
            } => sessions,
            result = &mut serving => panic!("server ended during setup: {result:?}"),
        };
        let local = SocketAddress::local_ipv4(9);
        let peer = SocketAddress::local_ipv4(10);
        let mut socket = ConnectUdpSocket::new(
            &Executor::new(),
            HttpDatagramSession::with_config(server_io, session_config()),
            local,
            peer,
            ConnectUdpSocketConfig::default(),
        );
        let mut sender = HttpDatagramSession::new(client_io);
        for index in 0..count {
            sender
                .send_datagram(Bytes::from(vec![0, index as u8]))
                .await
                .unwrap();
        }
        sender.close().await.unwrap();
        assert_eq!(
            server_connection.received_datagrams(),
            if native { count } else { 0 }
        );
        client_connection.close(Code::H3_NO_ERROR.value() as u32, b"done");
        server_connection.closed().await;
        if filed_first {
            serving.as_mut().await.unwrap();
        }
        let mut replies = socket.create_sender();
        replies
            .send(SendDatagram::new(peer, b"origin reply"))
            .await
            .unwrap();
        // Wait for the pump's send failure without advancing paused time to its deadline.
        while !matches!(
            replies.send(SendDatagram::new(peer, b"reply")).await,
            Err(DatagramError::Closed)
        ) {
            tokio::task::yield_now().await;
        }
        if !filed_first {
            serving.await.unwrap();
        }
        assert_eq!(server_connection.received_datagrams(), 0);
        let mut buffer = [0u8; 64];
        for index in 0..count {
            let meta = socket
                .recv(&mut buffer)
                .await
                .expect("received payload survives failed send");
            assert_eq!(&buffer[..meta.len], &[index as u8]);
        }
        assert!(matches!(
            socket.recv(&mut buffer).await,
            Err(DatagramError::Closed)
        ));
        drop(socket);
        drop(client);
        client_driver.await.unwrap().unwrap();
        client_endpoint.close(0u32, b"done");
        server_endpoint.close(0u32, b"done");
        client_endpoint.wait_idle().await;
        server_endpoint.wait_idle().await;
    })
    .await
    .unwrap();
}

async fn connection_pair() -> (
    Endpoint,
    Endpoint,
    rama_quic::Connection,
    rama_quic::Connection,
) {
    let identity = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
    let alpn = || [b"h3".as_slice().into()].into_iter().collect();
    let server_tls = TlsServerConfig::new()
        .with_alpn(alpn())
        .with_server_auth(identity.clone());
    let client_tls = TlsClientConfig::new()
        .with_alpn(alpn())
        .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
        .unwrap();
    let transport = || {
        let mut transport = TransportConfig::default();
        Config::default()
            .configure_transport(&mut transport)
            .unwrap();
        Arc::new(transport)
    };
    let mut server_config =
        ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default()).unwrap();
    server_config.set_transport_config(transport());
    let mut client_config =
        ClientConfig::try_from_rama_tls(&client_tls, TlsOptions::default()).unwrap();
    client_config.set_transport_config(transport());
    let (server_socket, client_socket) = MemoryDatagramSocket::pair(
        SocketAddress::local_ipv4(443),
        SocketAddress::local_ipv4(444),
        NonZeroUsize::MIN,
    );
    let server_endpoint = Endpoint::build(Executor::new())
        .with_server_config(server_config)
        .with_datagram_socket(server_socket)
        .unwrap();
    let client_endpoint = Endpoint::build(Executor::new())
        .with_datagram_socket(client_socket)
        .unwrap();
    let (client_connection, server_connection) = tokio::join!(
        client_endpoint
            .connect_with(
                client_config,
                server_endpoint.local_addr().unwrap(),
                "localhost"
            )
            .unwrap(),
        async { server_endpoint.accept().await.unwrap().await },
    );
    let client_connection = client_connection.unwrap();
    let server_connection = server_connection.unwrap();

    (
        client_endpoint,
        server_endpoint,
        client_connection,
        server_connection,
    )
}

#[tokio::test(start_paused = true)]
async fn stop_sending_preserves_inbound_native_and_capsule_payloads() {
    use rama_core::bytes::BytesMut;
    use rama_http::proto::{
        capsule::CapsuleType,
        h3::{FrameHeader, FrameType, VarInt},
    };
    use rama_http_core::h3::{
        qpack::{Encoder, EncoderConfig},
        server,
    };
    use rama_quic_proto::coding::Codec as _;
    for native in [false, true] {
        for filed_first in [false, true] {
            timeout(LIMIT, async {
                let (client_endpoint, server_endpoint, client_connection, server_connection) =
                    connection_pair().await;
                let config = Config {
                    extended_connect: true,
                    datagrams: native.then(Default::default),
                    ..Config::default()
                };
                let (_server, server_driver) =
                    server::handshake(server_connection.clone(), config.clone()).unwrap();
                let server_driver = tokio::spawn(server_driver.run());
                let (mut client, client_driver) =
                    client::handshake::<Body>(client_connection.clone(), config, Executor::new())
                        .unwrap();
                let client_driver = tokio::spawn(client_driver.run());
                let request = Request::builder()
                    .method(Method::CONNECT)
                    .uri("https://localhost/udp")
                    .body(Body::empty())
                    .unwrap();
                request.extensions().insert(HttpDatagrams);
                request.extensions().insert(Protocol::CONNECT_UDP);
                let (response, (mut send, mut receive)) =
                    tokio::join!(client.send_request(request), async {
                        let (mut send, mut receive) = server_connection.accept_bi().await.unwrap();
                        receive.read_chunk(usize::MAX, true).await.unwrap().unwrap();
                        let headers = Encoder::before_peer_settings(EncoderConfig::default())
                            .encode(u64::from(send.id()), vec![(":status", "200")])
                            .unwrap();
                        let mut frame = BytesMut::new();
                        FrameHeader::new(FrameType::HEADERS, headers.len() as u64)
                            .encode(&mut frame)
                            .unwrap();
                        frame.extend_from_slice(&headers);
                        send.write_chunk(frame.freeze()).await.unwrap();
                        (send, receive)
                    });
                let peer = SocketAddress::local_ipv4(10);
                let mut socket = ConnectUdpSocket::new(
                    &Executor::new(),
                    HttpDatagramSession::with_config(
                        handle_upgrade(&response.unwrap()).await.unwrap(),
                        session_config(),
                    ),
                    SocketAddress::local_ipv4(9),
                    peer,
                    ConnectUdpSocketConfig::default(),
                );
                async fn payload(send: &mut rama_quic::SendStream, native: bool) {
                    let mut frame = BytesMut::new();
                    if native {
                        VarInt::from_u64(u64::from(send.id()) / 4)
                            .unwrap()
                            .encode(&mut frame);
                        frame.extend_from_slice(b"\0last payload");
                        send.handle().send_datagram(frame.freeze()).unwrap();
                    } else {
                        let capsule = rama_http::datagram::capsule::encode_capsule(
                            CapsuleType::DATAGRAM,
                            b"\0last payload",
                        )
                        .unwrap();
                        FrameHeader::new(FrameType::DATA, capsule.len() as u64)
                            .encode(&mut frame)
                            .unwrap();
                        frame.extend_from_slice(&capsule);
                        send.write_chunk(frame.freeze()).await.unwrap();
                    }
                }
                if filed_first {
                    payload(&mut send, native).await;
                }
                receive
                    .stop(VarInt::from_u32(Code::H3_NO_ERROR.value() as u32))
                    .unwrap();
                let mut replies = socket.create_sender();
                while !matches!(
                    replies.send(SendDatagram::new(peer, b"reply")).await,
                    Err(DatagramError::Closed)
                ) {
                    tokio::task::yield_now().await;
                }
                if !filed_first {
                    payload(&mut send, native).await;
                }
                send.finish().unwrap();
                send.stopped().await.unwrap();
                let mut buffer = [0; 64];
                let received = socket.recv(&mut buffer).await.unwrap();
                assert_eq!(&buffer[..received.len], b"last payload");
                assert!(matches!(
                    socket.recv(&mut buffer).await,
                    Err(DatagramError::Closed)
                ));
                drop(socket);
                client_connection.close(Code::H3_NO_ERROR.value() as u32, b"done");
                let _drivers = tokio::join!(client_driver, server_driver);
                client_endpoint.close(0u32, b"done");
                server_endpoint.close(0u32, b"done");
                tokio::join!(client_endpoint.wait_idle(), server_endpoint.wait_idle());
            })
            .await
            .unwrap();
        }
    }
}
