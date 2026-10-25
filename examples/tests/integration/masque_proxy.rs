//! The MASQUE proxy example: HTTP/3 through its CONNECT-UDP tunnels, and a clean shutdown.
use super::utils;
use rama::{
    Service,
    http::{Body, Request, Response, server::HttpServer},
    net::{address::SocketAddress, tls::ApplicationProtocol},
    quic::{Connection, ConnectionError, Endpoint, ServerConfig, tls::TlsOptions},
    rt::Executor,
    service::service_fn,
    tls::server::{ServerAuthData, TlsServerConfig},
};
use std::{convert::Infallible, net::SocketAddr, time::Duration};
use tokio::{process::Command, sync::mpsc, time::timeout};

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_masque_proxy() {
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
        utils::example!("masque_proxy"),
        ["proxy", "--listen", "127.0.0.1:0", "--allow-private"],
    );
    let line = proxy
        .wait_for_line("MASQUE proxy listening on ", Duration::from_secs(30))
        .await;
    let address: SocketAddr = line
        .split("MASQUE proxy listening on ")
        .nth(1)
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    // The close races the proxy connection's: a few runs make a lost one show.
    for _ in 0..5 {
        let mut command = Command::from(utils::ExampleRunner::command(utils::example!(
            "masque_proxy"
        )));
        command
            .kill_on_drop(true)
            .env("RUST_LOG", "masque_proxy=info")
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
        let reason = timeout(Duration::from_secs(2), closed.recv())
            .await
            .expect("the client closed its tunneled connection")
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
