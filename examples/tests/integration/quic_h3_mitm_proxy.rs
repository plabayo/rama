//! The conditional QUIC/H3 interception example, end to end: an intercepted name is
//! terminated and relayed as HTTP/3, any other is forwarded untouched.
use super::utils;
use rama::{
    crypto::{
        pem::PemEncode as _,
        pki_types::{CertificateDer, pem::PemObject as _},
    },
    http::core::h3::connection::Config as H3Config,
    http::{Body, Request, StatusCode, body::util::BodyExt as _, core::h3::client as h3_client},
    net::{address::SocketAddress, tls::ApplicationProtocol},
    quic::{ClientConfig, Endpoint, tls::TlsOptions},
    rt::Executor,
    tls::{client::TlsClientConfig, server::ServerAuthData},
    utils::fs::tempdir,
};
use std::{net::SocketAddr, path::Path, time::Duration};
use tokio::{fs, spawn, time::timeout};

const LIMIT: Duration = Duration::from_secs(30);

fn listening(line: &str, needle: &str) -> SocketAddr {
    line.split(needle).nth(1).unwrap().trim().parse().unwrap()
}

/// One GET through `proxy` for `localhost`, trusting `ca`: its status, the proxy's marker,
/// and the body.
async fn get(proxy: SocketAddr, ca: &Path) -> (StatusCode, Option<String>, String) {
    let ca = CertificateDer::from_pem_file(ca).unwrap();
    let endpoint = Endpoint::build(Executor::new())
        .bind_address(SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let tls = TlsClientConfig::new()
        .try_with_server_trust_anchors([ca])
        .unwrap()
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let config = ClientConfig::try_from_rama_tls(&tls, TlsOptions::default()).unwrap();
    let connection = timeout(
        LIMIT,
        endpoint.connect_with(config, proxy, "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut client, driver) =
        h3_client::handshake::<Body>(connection, H3Config::default(), Executor::new()).unwrap();
    let driver = spawn(driver.run());
    let request = Request::get(format!("https://localhost:{}/", proxy.port()))
        .body(Body::empty())
        .unwrap();
    let response = timeout(LIMIT, client.send_request(request))
        .await
        .unwrap()
        .unwrap();
    let status = response.status();
    let marker = response
        .headers()
        .get("x-rama-mitm")
        .map(|value| value.to_str().unwrap().to_owned());
    let body = timeout(LIMIT, response.into_body().collect())
        .await
        .unwrap()
        .unwrap()
        .to_bytes();
    drop(client);
    endpoint.close(0u32, b"done");
    endpoint.shutdown().await;
    driver.abort();
    (status, marker, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_quic_h3_mitm_proxy() {
    utils::init_tracing();
    let directory = tempdir().unwrap();
    let origin_auth = ServerAuthData::new_self_signed_leaf(Default::default()).unwrap();
    let origin_cert = directory.path().join("origin-cert.pem");
    let origin_key = directory.path().join("origin-key.pem");
    fs::write(&origin_cert, origin_auth.cert_chain[0].to_pem())
        .await
        .unwrap();
    fs::write(&origin_key, origin_auth.private_key.to_pem())
        .await
        .unwrap();
    let mut origin = utils::ExampleRunner::capturing(
        utils::example!("http3_client_server"),
        [
            "server",
            "--listen",
            "127.0.0.1:0",
            "--cert",
            origin_cert.to_str().unwrap(),
            "--key",
            origin_key.to_str().unwrap(),
        ],
    );
    let upstream = listening(
        &origin
            .wait_for_line("HTTP/3 listening on ", Duration::from_secs(60))
            .await,
        "HTTP/3 listening on ",
    );

    for intercept in [true, false] {
        let mitm_ca = directory.path().join(format!("mitm-ca-{intercept}.pem"));
        let mut args = vec![
            "--listen".to_owned(),
            "127.0.0.1:0".to_owned(),
            "--upstream".to_owned(),
            upstream.to_string(),
            "--upstream-ca".to_owned(),
            origin_cert.to_str().unwrap().to_owned(),
            "--ca-out".to_owned(),
            mitm_ca.to_str().unwrap().to_owned(),
        ];
        if intercept {
            // In another case than the client sends: names match case-insensitively.
            args.extend(["--intercept".to_owned(), "LocalHost".to_owned()]);
        }
        let mut proxy =
            utils::ExampleRunner::capturing(utils::example!("quic_h3_mitm_proxy"), args);
        let proxy_address = listening(
            &proxy
                .wait_for_line("QUIC MITM proxy listening on ", Duration::from_secs(60))
                .await,
            "QUIC MITM proxy listening on ",
        );
        // An intercepted client trusts the proxy's CA; a forwarded one, the origin itself.
        let trusted = if intercept { &mitm_ca } else { &origin_cert };
        let (status, marker, body) = get(proxy_address, trusted).await;
        assert_eq!(status, StatusCode::OK, "{}", proxy.said());
        assert_eq!(
            marker.as_deref(),
            intercept.then_some("h3"),
            "{}",
            proxy.said()
        );
        assert!(body.contains("hello over HTTP/3"), "{body}");
        let decision = if intercept {
            "intercepting"
        } else {
            "forwarding"
        };
        assert!(proxy.said().contains(decision), "{}", proxy.said());
        let status = proxy.interrupt_within(Duration::from_secs(20)).await;
        assert!(status.success(), "{}", proxy.said());
    }
    let status = origin.interrupt_within(Duration::from_secs(20)).await;
    assert!(status.success(), "{}", origin.said());
}
