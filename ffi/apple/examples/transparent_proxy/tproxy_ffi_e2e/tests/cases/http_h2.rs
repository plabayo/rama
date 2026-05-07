//! HTTP/2 E2E coverage.
//!
//! Matrix:
//! - target: `plain`, `tls`
//! - proxy: `direct`, `http`, `socks5`

use rama::{
    bytes::Bytes,
    futures::future::join_all,
    http::{BodyExtractExt as _, Version, body::util::BodyExt as _},
};
use serial_test::serial;
use std::time::Duration;

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

macro_rules! h2_large_body_test {
    ($name:ident, $target:expr, $proxy:expr, $size_kb:expr) => {
        #[tokio::test]
        #[serial]
        async fn $name() {
            run_h2_large_body_case($target, $proxy, $size_kb).await;
        }
    };
}

macro_rules! h2_concurrent_large_test {
    ($name:ident, $target:expr, $proxy:expr, $stream_count:expr, $size_kb:expr) => {
        #[tokio::test]
        #[serial]
        async fn $name() {
            run_h2_concurrent_large_case($target, $proxy, $stream_count, $size_kb).await;
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

// ── Large-body + many-concurrent-stream coverage ──────────────────────────────
//
// These exist specifically to pin the symmetric-backpressure fix for the
// Rust → Swift response direction: before the writer pumps were bounded
// (with `signal_*_drain` wired up) and `flow.write` ENOBUFS treated as
// transient, large h2 responses (e.g. `go mod download` of a multi-MB module
// zip) intermittently surfaced as "random" mid-stream errors as the per-flow
// NE kernel buffer overflowed. Plain/TLS × direct only — proxied variants
// are functionally equivalent for what we're verifying here.
h2_large_body_test!(
    ffi_contract_http_h2_plain_direct_large_response_body,
    HttpTargetKind::Plain,
    ProxyKind::None,
    8 * 1024
);
h2_large_body_test!(
    ffi_contract_http_h2_tls_direct_large_response_body,
    HttpTargetKind::Tls,
    ProxyKind::None,
    8 * 1024
);
h2_concurrent_large_test!(
    ffi_contract_http_h2_plain_direct_concurrent_large_streams,
    HttpTargetKind::Plain,
    ProxyKind::None,
    16,
    1024
);
h2_concurrent_large_test!(
    ffi_contract_http_h2_tls_direct_concurrent_large_streams,
    HttpTargetKind::Tls,
    ProxyKind::None,
    16,
    1024
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

async fn run_h2_large_body_case(target: HttpTargetKind, proxy: ProxyKind, size_kb: usize) {
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

    let url = format!(
        "{scheme}://127.0.0.1:{}/large?kb={size_kb}",
        ingress_addr.port()
    );

    // The wails-zip case took ~2 s end-to-end on a real network; locally we
    // expect well under that, but allow a generous budget so a CI hiccup
    // doesn't false-fail.
    let response = tokio::time::timeout(
        Duration::from_secs(30),
        fetch_response(
            &client,
            &url,
            Version::HTTP_2,
            proxy,
            localhost(env.ports.proxy),
        ),
    )
    .await
    .expect("fetch should not time out for large h2 body");

    assert!(
        response.status().is_success(),
        "status = {}",
        response.status()
    );

    let body: Bytes = tokio::time::timeout(Duration::from_secs(30), response.into_body().collect())
        .await
        .expect("body collect should not time out")
        .expect("body bytes")
        .to_bytes();
    let expected_bytes = size_kb * 1024;
    assert_eq!(
        body.len(),
        expected_bytes,
        "expected {expected_bytes} bytes, got {}",
        body.len()
    );

    ingress.shutdown().await;
}

async fn run_h2_concurrent_large_case(
    target: HttpTargetKind,
    proxy: ProxyKind,
    stream_count: usize,
    size_kb: usize,
) {
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
    let expected_bytes = size_kb * 1024;

    // `stream_count` simultaneous large bodies through the same TCP flow —
    // exercises h2 multiplexing through the bounded per-flow channel +
    // bounded writer-pump pending. Pre-fix this would either stall (one
    // slow stream backpressures every other stream) or fail with ENOBUFS.
    let results = tokio::time::timeout(
        Duration::from_secs(60),
        join_all((0..stream_count).map(|idx| {
            let client = &client;
            let url = format!("{base}/large?kb={size_kb}&stream={idx}");
            async move {
                let response =
                    fetch_response(client, &url, Version::HTTP_2, proxy, proxy_addr).await;
                response
                    .into_body()
                    .collect()
                    .await
                    .expect("body bytes")
                    .to_bytes()
            }
        })),
    )
    .await
    .expect("concurrent large streams should not time out");

    for (idx, body) in results.iter().enumerate() {
        assert_eq!(
            body.len(),
            expected_bytes,
            "stream {idx}: expected {expected_bytes} bytes, got {}",
            body.len()
        );
    }

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
