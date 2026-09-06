//! HTTP/1.1 E2E coverage.
//!
//! Matrix:
//! - target: `plain`, `tls`
//! - proxy: `direct`, `http`, `socks5`

use rama::http::{
    BodyExtractExt as _, Version, header::ACCEPT_ENCODING, service::client::HttpClientExt as _,
};
use serial_test::serial;
use std::time::Duration;
use tokio::{
    io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};

use crate::shared::{
    clients::{
        apply_http_version, apply_proxy_extensions, build_http_client, fetch_response, fetch_text,
    },
    env::setup_env,
    ffi::load_mitm_ca_store,
    ingress::spawn_ingress_listener,
    types::{BADGE_LABEL, HttpTargetKind, OBSERVED_HEADER, ProxyKind, localhost},
};

macro_rules! h1_html_smoke_test {
    ($name:ident, $target:expr, $proxy:expr) => {
        #[tokio::test]
        #[serial]
        async fn $name() {
            run_h1_html_smoke($target, $proxy).await;
        }
    };
}

macro_rules! h1_feature_test {
    ($name:ident, $target:expr, $proxy:expr) => {
        #[tokio::test]
        #[serial]
        async fn $name() {
            run_h1_feature_case($target, $proxy).await;
        }
    };
}

h1_html_smoke_test!(
    ffi_contract_http_h1_plain_direct_html_badge_and_observed_headers,
    HttpTargetKind::Plain,
    ProxyKind::None
);
h1_html_smoke_test!(
    ffi_contract_http_h1_plain_http_proxy_html_badge_and_observed_headers,
    HttpTargetKind::Plain,
    ProxyKind::Http
);
h1_html_smoke_test!(
    ffi_contract_http_h1_plain_socks5_proxy_html_badge_and_observed_headers,
    HttpTargetKind::Plain,
    ProxyKind::Socks5
);
h1_html_smoke_test!(
    ffi_contract_http_h1_tls_direct_html_badge_and_observed_headers,
    HttpTargetKind::Tls,
    ProxyKind::None
);
h1_html_smoke_test!(
    ffi_contract_http_h1_tls_http_proxy_html_badge_and_observed_headers,
    HttpTargetKind::Tls,
    ProxyKind::Http
);
h1_html_smoke_test!(
    ffi_contract_http_h1_tls_socks5_proxy_html_badge_and_observed_headers,
    HttpTargetKind::Tls,
    ProxyKind::Socks5
);

h1_feature_test!(
    ffi_contract_http_h1_plain_direct_chunked_sse_compressed_and_keep_alive,
    HttpTargetKind::Plain,
    ProxyKind::None
);
h1_feature_test!(
    ffi_contract_http_h1_plain_http_proxy_chunked_sse_compressed_and_keep_alive,
    HttpTargetKind::Plain,
    ProxyKind::Http
);
h1_feature_test!(
    ffi_contract_http_h1_plain_socks5_proxy_chunked_sse_compressed_and_keep_alive,
    HttpTargetKind::Plain,
    ProxyKind::Socks5
);
h1_feature_test!(
    ffi_contract_http_h1_tls_direct_chunked_sse_compressed_and_keep_alive,
    HttpTargetKind::Tls,
    ProxyKind::None
);
h1_feature_test!(
    ffi_contract_http_h1_tls_http_proxy_chunked_sse_compressed_and_keep_alive,
    HttpTargetKind::Tls,
    ProxyKind::Http
);
h1_feature_test!(
    ffi_contract_http_h1_tls_socks5_chunked_sse_compressed_and_keep_alive,
    HttpTargetKind::Tls,
    ProxyKind::Socks5
);

#[tokio::test]
#[serial]
async fn ffi_contract_http_h1_complete_response_after_client_write_eof() {
    let env = setup_env().await;
    let origin = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let ingress = spawn_ingress_listener(env.engine.clone(), origin.local_addr().unwrap()).await;
    let body: Vec<u8> = (0..rama::utils::octets::kib(256))
        .map(|i| (i % 251) as u8)
        .collect();
    let body_len = body.len();
    let (write_closed, after_write_close) = oneshot::channel();

    let client_exchange = async {
        let mut client = TcpStream::connect(ingress.local_addr()).await.unwrap();
        let headers = format!(
            "POST /half-close HTTP/1.1\r\nHost: upstream.test\r\n\
             Content-Type: application/octet-stream\r\nContent-Length: {body_len}\r\n\
             Connection: close\r\n\r\n"
        );
        client.write_all(headers.as_bytes()).await.unwrap();
        client.write_all(&body).await.unwrap();
        client.shutdown().await.unwrap();
        write_closed.send(()).unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let boundary = response
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("complete response headers after client write EOF");
        let headers = std::str::from_utf8(&response[..boundary]).unwrap();
        assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"), "{headers}");
        assert!(
            headers
                .to_ascii_lowercase()
                .contains(&format!("{OBSERVED_HEADER}:"))
        );
        assert_eq!(&response[boundary + 4..], body.as_slice());
    };
    let origin_exchange = async {
        let (stream, _) = origin.accept().await.unwrap();
        let mut stream = BufReader::new(stream);
        let mut headers = String::new();
        loop {
            let start = headers.len();
            assert_ne!(stream.read_line(&mut headers).await.unwrap(), 0);
            if &headers[start..] == "\r\n" {
                break;
            }
        }
        assert!(headers.starts_with("POST /half-close HTTP/1.1\r\n"));
        assert!(
            headers
                .to_ascii_lowercase()
                .contains(&format!("content-length: {body_len}\r\n"))
        );
        assert!(
            headers
                .to_ascii_lowercase()
                .contains(&format!("{OBSERVED_HEADER}:"))
        );
        let mut received = vec![0; body_len];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, body);
        after_write_close.await.unwrap();
        // Make the response unavailable until the complete request and the
        // client's write EOF have been sent through the real FFI composition.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
             Content-Length: {body_len}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(headers.as_bytes()).await.unwrap();
        stream.write_all(&received).await.unwrap();
        stream.shutdown().await.unwrap();
    };
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(client_exchange, origin_exchange);
    })
    .await;
    ingress.shutdown().await;
    result.expect("bounded HTTP half-close exchange");
}

async fn run_h1_html_smoke(target: HttpTargetKind, proxy: ProxyKind) {
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
        Version::HTTP_11,
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
    assert!(body.contains("rama-proxy-badge"), "body = {body}");

    let observed = observations.lock().await;
    let html_observation = observed
        .iter()
        .find(|observation| observation.uri == "/html");
    let html_observation = html_observation.expect("server observed html request");
    assert!(html_observation.observed_header.is_some());
    drop(observed);
    ingress.shutdown().await;
}

async fn run_h1_feature_case(target: HttpTargetKind, proxy: ProxyKind) {
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

    let chunked_body = fetch_text(
        &client,
        &format!("{scheme}://127.0.0.1:{}/chunked", ingress_addr.port()),
        Version::HTTP_11,
        proxy,
        proxy_addr,
    )
    .await;
    assert!(chunked_body.contains("chunk-0"));
    assert!(chunked_body.contains("chunk-1"));
    assert!(chunked_body.contains("chunk-2"));
    assert!(chunked_body.contains(BADGE_LABEL));

    let sse_body = fetch_text(
        &client,
        &format!("{scheme}://127.0.0.1:{}/sse", ingress_addr.port()),
        Version::HTTP_11,
        proxy,
        proxy_addr,
    )
    .await;
    assert!(sse_body.contains("event-0"));
    assert!(sse_body.contains("event-1"));
    assert!(sse_body.contains("event-2"));

    let identity_builder = client.get(format!("{scheme}://127.0.0.1:{}/html", ingress_addr.port()));
    let identity_builder =
        apply_http_version(identity_builder, Version::HTTP_11).header(ACCEPT_ENCODING, "identity");
    let identity_builder = apply_proxy_extensions(identity_builder, proxy, proxy_addr);
    let identity_body = identity_builder
        .send()
        .await
        .expect("identity request")
        .try_into_string()
        .await
        .expect("identity html body");
    assert!(identity_body.contains(BADGE_LABEL));

    let json_url = format!(
        "{scheme}://127.0.0.1:{}/json?case=keepalive",
        ingress_addr.port()
    );
    let first = fetch_text(&client, &json_url, Version::HTTP_11, proxy, proxy_addr).await;
    let second = fetch_text(&client, &json_url, Version::HTTP_11, proxy, proxy_addr).await;
    let third = fetch_text(&client, &json_url, Version::HTTP_11, proxy, proxy_addr).await;
    assert!(first.contains("\"observed\":true"));
    assert!(second.contains("\"observed\":true"));
    assert!(third.contains("\"observed\":true"));
    ingress.shutdown().await;
}
