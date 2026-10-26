//! The CONNECT-UDP proxy example: HTTP/3 through its tunnels, and a clean shutdown.
use super::utils;
use rama::{
    Service,
    http::{Body, Request, Response, server::HttpServer},
    net::{
        address::SocketAddress, process::ProcessSocket, tls::ApplicationProtocol,
        transport::TransportProtocol,
    },
    quic::{Connection, ConnectionError, Endpoint, ServerConfig, tls::TlsOptions},
    rt::Executor,
    service::service_fn,
    tls::server::{ServerAuthData, TlsServerConfig},
};
use std::{convert::Infallible, time::Duration};
use tokio::{process::Command, sync::mpsc, time::timeout};

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_masque_connect_udp_proxy() {
    utils::init_tracing();
    // The origin answers every request with its version.
    let auth = ServerAuthData::new_self_signed_leaf(Default::default()).unwrap();
    let tls = TlsServerConfig::new()
        .with_server_auth(auth)
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let origin = Endpoint::build(Executor::new())
        .with_server_config(ServerConfig::try_from_rama_tls(&tls, TlsOptions::default()).unwrap())
        .bind_address(SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let h3 =
        HttpServer::new_http3(Executor::new()).service(service_fn(async |request: Request| {
            Ok::<_, Infallible>(Response::new(Body::from(format!(
                "{:?} origin",
                request.version()
            ))))
        }));
    // Every connection's end, to check that the client closed it.
    let (closed_tx, mut closed) = mpsc::unbounded_channel::<ConnectionError>();
    tokio::spawn(origin.clone().serve(
        Executor::new(),
        service_fn(move |connection: Connection| {
            let closed_tx = closed_tx.clone();
            let h3 = h3.clone();
            async move {
                let watched = connection.clone();
                tokio::spawn(async move { closed_tx.send(watched.closed().await) });
                h3.serve(connection).await
            }
        }),
    ));

    let mut proxy = utils::ExampleRunner::capturing(
        utils::example!("masque_connect_udp_proxy"),
        ["proxy", "--listen", "127.0.0.1:0", "--allow-private"],
    );
    // TLS over TCP and HTTP/3 over UDP on one port: both bound before any client starts.
    let address = proxy.tcp_listener_addr().await;
    utils::wait_for_socket(
        &mut proxy.server_process,
        ProcessSocket {
            protocol: TransportProtocol::Udp,
            local_addr: address,
        },
    )
    .await
    .unwrap();

    // The close races the proxy connection's: a few runs make a lost one show.
    for run in 0..5 {
        let mut command = Command::from(utils::ExampleRunner::command(utils::example!(
            "masque_connect_udp_proxy"
        )));
        command
            .kill_on_drop(true)
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG")
                    .unwrap_or_else(|_| "masque_connect_udp_proxy=info".into()),
            )
            .args([
                "client",
                "--proxy",
                &format!("masque://{address}"),
                "--insecure",
                "--url",
                &format!("https://127.0.0.1:{origin_port}/"),
            ]);
        let output = timeout(Duration::from_secs(30), command.output())
            .await
            .unwrap()
            .unwrap();
        let said = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success(), "{said}");
        assert!(said.contains("HTTP/3.0 origin"), "{said}");
        // Loaded CI runners take seconds; a lost close is never `ApplicationClosed`.
        let reason = timeout(Duration::from_secs(8), closed.recv())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "run {run}: the origin's connection is still open\nclient:\n{said}\nproxy:\n{}",
                    proxy.said()
                )
            })
            .unwrap();
        assert!(
            matches!(reason, ConnectionError::ApplicationClosed(_)),
            "{reason:?}"
        );
    }

    let status = proxy.interrupt_within(Duration::from_secs(10)).await;
    assert!(status.success(), "{}", proxy.said());
    origin.close(0u32, b"done");
}
