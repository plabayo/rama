//! HTTP/2 E2E coverage.
//!
//! Matrix:
//! - target: `plain`, `tls`
//! - proxy: `direct`, `http`, `socks5`

use rama::{
    futures::future::join_all,
    http::{BodyExtractExt as _, Version},
};
use serial_test::serial;

use crate::shared::{
    clients::{build_http_client, fetch_response, fetch_text},
    env::setup_env,
    ffi::load_mitm_ca_store,
    ingress::spawn_ingress_listener,
    types::{BADGE_LABEL, HttpTargetKind, OBSERVED_HEADER, ProxyKind, localhost},
};

macro_rules! h2_html_smoke_test {
    ($name:ident, $target:expr, $proxy:expr) => {
        #[tokio::test]
        #[serial]
        async fn $name() {
            run_h2_html_smoke($target, $proxy).await;
        }
    };
}

macro_rules! h2_multi_stream_test {
    ($name:ident, $target:expr, $proxy:expr) => {
        #[tokio::test]
        #[serial]
        async fn $name() {
            run_h2_multi_stream_case($target, $proxy).await;
        }
    };
}

h2_html_smoke_test!(
    ffi_contract_http_h2_plain_direct_html_badge_and_observed_headers,
    HttpTargetKind::Plain,
    ProxyKind::None
);
h2_html_smoke_test!(
    ffi_contract_http_h2_plain_http_proxy_html_badge_and_observed_headers,
    HttpTargetKind::Plain,
    ProxyKind::Http
);
h2_html_smoke_test!(
    ffi_contract_http_h2_plain_socks5_proxy_html_badge_and_observed_headers,
    HttpTargetKind::Plain,
    ProxyKind::Socks5
);
h2_html_smoke_test!(
    ffi_contract_http_h2_tls_direct_html_badge_and_observed_headers,
    HttpTargetKind::Tls,
    ProxyKind::None
);
h2_html_smoke_test!(
    ffi_contract_http_h2_tls_http_proxy_html_badge_and_observed_headers,
    HttpTargetKind::Tls,
    ProxyKind::Http
);
h2_html_smoke_test!(
    ffi_contract_http_h2_tls_socks5_proxy_html_badge_and_observed_headers,
    HttpTargetKind::Tls,
    ProxyKind::Socks5
);

h2_multi_stream_test!(
    ffi_contract_http_h2_plain_direct_multi_stream_json_and_html,
    HttpTargetKind::Plain,
    ProxyKind::None
);
h2_multi_stream_test!(
    ffi_contract_http_h2_plain_http_proxy_multi_stream_json_and_html,
    HttpTargetKind::Plain,
    ProxyKind::Http
);
h2_multi_stream_test!(
    ffi_contract_http_h2_plain_socks5_proxy_multi_stream_json_and_html,
    HttpTargetKind::Plain,
    ProxyKind::Socks5
);
h2_multi_stream_test!(
    ffi_contract_http_h2_tls_direct_multi_stream_json_and_html,
    HttpTargetKind::Tls,
    ProxyKind::None
);
h2_multi_stream_test!(
    ffi_contract_http_h2_tls_http_proxy_multi_stream_json_and_html,
    HttpTargetKind::Tls,
    ProxyKind::Http
);
h2_multi_stream_test!(
    ffi_contract_http_h2_tls_socks5_proxy_multi_stream_json_and_html,
    HttpTargetKind::Tls,
    ProxyKind::Socks5
);

async fn run_h2_html_smoke(target: HttpTargetKind, proxy: ProxyKind) {
    let env = setup_env().await;
    let remote_port = match target {
        HttpTargetKind::Plain => env.ports.http,
        HttpTargetKind::Tls => env.ports.https,
    };
    let scheme = match target {
        HttpTargetKind::Plain => "http",
        HttpTargetKind::Tls => "https",
    };
    let observations = match target {
        HttpTargetKind::Plain => env.http_observations.clone(),
        HttpTargetKind::Tls => env.https_observations.clone(),
    };
    let ingress = spawn_ingress_listener(env.engine.clone(), localhost(remote_port)).await;
    let ingress_addr = ingress.local_addr();
    let client = build_http_client(match target {
        HttpTargetKind::Plain => None,
        HttpTargetKind::Tls => Some(load_mitm_ca_store()),
    });

    let response = fetch_response(
        &client,
        &format!("{scheme}://127.0.0.1:{}/html", ingress_addr.port()),
        Version::HTTP_2,
        proxy,
        localhost(env.ports.proxy),
    )
    .await;

    let observed_header = response
        .headers()
        .get(OBSERVED_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("response observed header");
    assert!(!observed_header.is_empty());

    let body = response.try_into_string().await.expect("html body");
    assert!(body.contains(BADGE_LABEL), "body = {body}");

    let observed = observations.lock().await;
    let html_observation = observed
        .iter()
        .find(|observation| observation.uri == "/html");
    let html_observation = html_observation.expect("server observed html request");
    assert!(html_observation.observed_header.is_some());
    drop(observed);
    ingress.shutdown().await;
}

async fn run_h2_multi_stream_case(target: HttpTargetKind, proxy: ProxyKind) {
    let env = setup_env().await;
    let remote_port = match target {
        HttpTargetKind::Plain => env.ports.http,
        HttpTargetKind::Tls => env.ports.https,
    };
    let scheme = match target {
        HttpTargetKind::Plain => "http",
        HttpTargetKind::Tls => "https",
    };
    let ingress = spawn_ingress_listener(env.engine.clone(), localhost(remote_port)).await;
    let ingress_addr = ingress.local_addr();
    let client = build_http_client(match target {
        HttpTargetKind::Plain => None,
        HttpTargetKind::Tls => Some(load_mitm_ca_store()),
    });
    let proxy_addr = localhost(env.ports.proxy);
    let base = format!("{scheme}://127.0.0.1:{}", ingress_addr.port());

    let results = join_all((0..8).map(|idx| {
        let client = &client;
        let url = if idx % 2 == 0 {
            format!("{base}/json?stream={idx}")
        } else {
            format!("{base}/html?stream={idx}")
        };
        async move { fetch_text(client, &url, Version::HTTP_2, proxy, proxy_addr).await }
    }))
    .await;

    for (idx, body) in results.into_iter().enumerate() {
        if idx % 2 == 0 {
            assert!(body.contains("\"observed\":true"), "json body = {body}");
        } else {
            assert!(body.contains(BADGE_LABEL), "html body = {body}");
        }
    }
    ingress.shutdown().await;
}
