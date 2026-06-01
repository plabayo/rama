//! Apple-FFI regression for #932: the MITM relay's h2 SETTINGS mirror
//! must propagate through the apple TLS layer end-to-end.
//!
//! Until this regression landed, the relay unconditionally advertised
//! the extended CONNECT protocol (RFC 8441) on its ingress regardless
//! of whether upstream supported it. That broke h2 WebSocket bootstrap
//! against upstreams that don't implement CONNECT (e.g. Discord). The
//! fix mirrors the upstream's initial SETTINGS frame onto the ingress
//! at handshake time.
//!
//! These tests use the no-CONNECT https fixture from
//! [`crate::shared::env`] to exercise the "upstream doesn't advertise"
//! branch through the actual apple tproxy → boring-TLS → HttpMitmRelay
//! stack, not just at the rama-http-backend layer.

use rama::extensions::{Extensions, ExtensionsRef as _};
use rama::http::Version;
use rama::http::conn::PeerH2Settings;
use rama::http::ws::handshake::client::HttpClientWebSocketExt as _;
use serial_test::serial;

use crate::shared::{
    clients::{build_http_client, fetch_response, websocket_echo},
    env::setup_env,
    ffi::load_mitm_ca_store,
    ingress::spawn_ingress_listener,
    types::{ProxyKind, localhost},
};

/// When the upstream h2 server omits `SETTINGS_ENABLE_CONNECT_PROTOCOL`
/// from its initial SETTINGS frame, the relay (acting as the h2 server
/// to our downstream client) must also omit it. This is #932's core
/// fix; this test pins it end-to-end through the apple FFI surface.
#[tokio::test]
#[serial]
async fn ffi_contract_mirror_omits_connect_when_upstream_does() {
    let env = setup_env().await;
    let ingress =
        spawn_ingress_listener(env.engine.clone(), localhost(env.ports.https_no_connect)).await;
    let ingress_addr = ingress.local_addr();
    let client = build_http_client(Some(load_mitm_ca_store()));

    // h2 GET against the no-CONNECT upstream, going through the apple
    // tproxy + TLS MITM. The response carries `PeerH2Settings` —
    // i.e. the SETTINGS frame the *relay* (not the upstream)
    // advertised to us — which is what we assert against.
    let resp = fetch_response(
        &client,
        &format!("https://127.0.0.1:{}/html", ingress_addr.port()),
        Version::HTTP_2,
        ProxyKind::None,
        localhost(env.ports.proxy),
    )
    .await;
    assert!(
        resp.status().is_success(),
        "h2 fetch through relay must succeed even when upstream omits CONNECT",
    );

    let peer = resp
        .extensions()
        .get_ref::<PeerH2Settings>()
        .expect("h2 response must carry PeerH2Settings");
    assert_eq!(
        peer.0.config.enable_connect_protocol, None,
        "relay must NOT advertise CONNECT downstream when upstream omits it",
    );

    drop(client);
    ingress.shutdown().await;
}

/// Counterpart: when the upstream h2 server DOES advertise CONNECT
/// (the default fixture), the relay must mirror that and advertise
/// CONNECT downstream. Confirms the mirror is not stuck at "off" for
/// every connection — i.e. it actually reads the upstream's value.
#[tokio::test]
#[serial]
async fn ffi_contract_mirror_advertises_connect_when_upstream_does() {
    let env = setup_env().await;
    let ingress = spawn_ingress_listener(env.engine.clone(), localhost(env.ports.https)).await;
    let ingress_addr = ingress.local_addr();
    let client = build_http_client(Some(load_mitm_ca_store()));

    let resp = fetch_response(
        &client,
        &format!("https://127.0.0.1:{}/html", ingress_addr.port()),
        Version::HTTP_2,
        ProxyKind::None,
        localhost(env.ports.proxy),
    )
    .await;
    assert!(resp.status().is_success());

    let peer = resp
        .extensions()
        .get_ref::<PeerH2Settings>()
        .expect("h2 response must carry PeerH2Settings");
    assert_eq!(
        peer.0.config.enable_connect_protocol,
        Some(1),
        "relay must mirror upstream's enable_connect_protocol=1",
    );

    drop(client);
    ingress.shutdown().await;
}

/// Behavioral consequence #1: when the relay's ingress h2 SETTINGS
/// omit CONNECT (mirrored from a no-CONNECT upstream), an attempt to
/// open a WebSocket via h2 Extended CONNECT MUST fail. The relay's
/// ingress h2 server rejects such requests because it never
/// advertised the capability. Pairs with the SETTINGS-frame inspection
/// in `ffi_contract_mirror_omits_connect_when_upstream_does` to lock
/// in #932 end-to-end through the apple FFI.
#[tokio::test]
#[serial]
async fn ffi_contract_websocket_h2_fails_when_upstream_omits_connect() {
    let env = setup_env().await;
    let ingress =
        spawn_ingress_listener(env.engine.clone(), localhost(env.ports.https_no_connect)).await;
    let ingress_addr = ingress.local_addr();
    let client = build_http_client(Some(load_mitm_ca_store()));

    let url = format!("wss://127.0.0.1:{}/ws", ingress_addr.port());
    let result = client
        .websocket_h2(url)
        .handshake(Extensions::new())
        .await;
    assert!(
        result.is_err(),
        "WS-over-h2 handshake MUST fail when upstream omits CONNECT \
         (the relay's ingress correctly didn't advertise it)",
    );

    drop(client);
    ingress.shutdown().await;
}

/// Behavioral consequence #2: against the same no-CONNECT upstream,
/// an h1 WebSocket handshake MUST succeed. This is the "browser-like
/// fallback" #932 was breaking — before the mirror landed, the relay
/// over-advertised CONNECT downstream, leading clients to prefer the
/// (broken) h2 path even though the upstream couldn't support it.
/// Now the relay honestly admits "no CONNECT," and clients picking up
/// the right path via h1 just works.
#[tokio::test]
#[serial]
async fn ffi_contract_websocket_h1_succeeds_when_upstream_omits_connect() {
    let env = setup_env().await;
    let ingress =
        spawn_ingress_listener(env.engine.clone(), localhost(env.ports.https_no_connect)).await;
    let ingress_addr = ingress.local_addr();
    let client = build_http_client(Some(load_mitm_ca_store()));

    websocket_echo(
        &client,
        format!("wss://127.0.0.1:{}/ws", ingress_addr.port()),
        Version::HTTP_11,
        ProxyKind::None,
        localhost(env.ports.proxy),
    )
    .await;

    drop(client);
    ingress.shutdown().await;
}
