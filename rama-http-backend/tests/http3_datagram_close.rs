//! A server dispatch loop must let HTTP/3 drain received datagrams after a clean close.

use rama_core::{bytes::Bytes, extensions::ExtensionsRef as _, rt::Executor, service::service_fn};
use rama_http::{
    Body, Method, Request, Response,
    datagram::{DatagramTransport, HttpDatagramSession, SessionEvent},
    io::upgrade::handle_upgrade,
};
use rama_http_backend::server::HttpServer;
use rama_http_core::h3::{DatagramConfig, DatagramLimits, client, connection::Config};
use rama_http_types::proto::{ext::HttpDatagrams, ext::Protocol, h3::Code};
use rama_net::address::SocketAddress;
use rama_quic::{ClientConfig, Endpoint, ServerConfig, TransportConfig, tls::TlsOptions};
use rama_tls::{
    client::TlsClientConfig,
    server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
};
use rama_udp::test_utils::MemoryDatagramSocket;
use std::{convert::Infallible, num::NonZeroUsize, pin::pin, sync::Arc, time::Duration};
use tokio::{sync::mpsc, time::timeout};

const LIMIT: Duration = Duration::from_secs(5);

#[tokio::test(start_paused = true)]
async fn clean_close_does_not_cancel_the_servers_datagram_drain() {
    timeout(LIMIT, async {
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
        // Exceed the driver's cooperative quantum so even selecting the driver first
        // leaves accept() ready while its clean-close drain is still pending.
        let count = 64;
        let mut http = HttpServer::new_http3(Executor::new());
        http.http3_mut().extended_connect = true;
        http.http3_mut().datagrams = Some(DatagramConfig {
            limits: DatagramLimits {
                queue_len: count,
                ..Default::default()
            },
            ..Default::default()
        });
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
            Config::default(),
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
        let mut sender = HttpDatagramSession::new(client_io);
        let mut receiver = HttpDatagramSession::new(server_io);
        // HTTP dispatch is paused here; the transport keeps running on a lossless link.
        for index in 0..count {
            assert_eq!(
                sender
                    .send_datagram(Bytes::from(vec![index as u8]))
                    .await
                    .unwrap(),
                DatagramTransport::Native,
            );
        }
        sender.close().await.unwrap();
        assert_eq!(server_connection.received_datagrams(), count);
        client_connection.close(Code::H3_NO_ERROR.value() as u32, b"done");
        server_connection.closed().await;
        serving.await.unwrap();
        assert_eq!(server_connection.received_datagrams(), 0);
        for index in 0..count {
            assert_eq!(
                receiver.recv().await.unwrap(),
                Some(SessionEvent::Datagram {
                    payload: Bytes::from(vec![index as u8]),
                    transport: DatagramTransport::Native,
                })
            );
        }
        assert_eq!(receiver.recv().await.unwrap(), None);
        client_driver.await.unwrap().unwrap();
        client_endpoint.close(0u32, b"done");
        server_endpoint.close(0u32, b"done");
        client_endpoint.wait_idle().await;
        server_endpoint.wait_idle().await;
    })
    .await
    .unwrap();
}
