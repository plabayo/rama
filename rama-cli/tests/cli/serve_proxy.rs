use rama::{
    Service,
    http::{Body, Request, Response, Version, server::HttpServer},
    net::{address::SocketAddress, tls::ApplicationProtocol},
    quic::{Connection, ConnectionError, Endpoint, ServerConfig, tls::TlsOptions},
    rt::Executor,
    service::service_fn,
    tls::server::{ServerAuthData, TlsServerConfig},
    ua::profile::selection::database::UserAgentDatabase,
};
use std::{convert::Infallible, time::Duration};
use tokio::{sync::mpsc, time::timeout};

use super::utils;

const CUSTOM_PROFILE_USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/987.0.0.0 Safari/537.36";
const CUSTOM_PROFILE_FIRST: &str = "rama-exported-profile-first-142ae981";
const CUSTOM_PROFILE_LAST: &str = "rama-exported-profile-last-7c30fb65";
const REQUEST_TIMEOUT_SECS: &str = "30";

fn assert_custom_profile_headers(headers: &[serde_json::Value]) {
    fn header_value(header: &serde_json::Value) -> &str {
        header
            .as_array()
            .and_then(|pair| pair.get(1))
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
    }
    let position = |expected: &str| {
        headers
            .iter()
            .position(|header| header_value(header) == expected)
            .unwrap_or_else(|| panic!("missing custom profile value {expected:?}: {headers:?}"))
    };
    let first = position(CUSTOM_PROFILE_FIRST);
    let user_agent = position(CUSTOM_PROFILE_USER_AGENT);
    let last = position(CUSTOM_PROFILE_LAST);
    assert!(
        first < user_agent && user_agent < last,
        "custom profile header order was not preserved: {headers:?}"
    );
}

fn assert_custom_profile_at_origin(stdout: &str, stderr: &str, phase: &str) {
    let response: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
        panic!("{phase}: invalid echo response: {error}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    let headers = response["http"]["headers"]
        .as_array()
        .expect("echo response contains ordered headers");
    assert_custom_profile_headers(headers);
}

#[tokio::test]
#[ignore = "spawns rama processes"]
async fn test_http_proxy_echo() {
    utils::init_tracing();

    let origin_server = utils::RamaService::serve_echo(0, utils::EchoMode::Http);
    let proxy_server = utils::RamaService::serve_proxy(0);
    let origin_port = origin_server.port();
    let proxy_port = proxy_server.port();

    let lines = utils::RamaService::http(vec![
        &format!("http://127.0.0.1:{origin_port}"),
        "-x",
        &format!("http://127.0.0.1:{proxy_port}"),
    ])
    .unwrap();
    assert!(lines.contains("HTTP/1.1 200 OK"), "lines: {lines:?}");
    assert!(lines.contains(r##""method":"GET""##), "lines: {lines:?}");
}

#[tokio::test]
#[ignore = "spawns rama processes"]
async fn test_https_proxy_echo() {
    utils::init_tracing();

    let origin_server = utils::RamaService::serve_echo(0, utils::EchoMode::Https);
    let proxy_server = utils::RamaService::serve_proxy(0);
    let origin_port = origin_server.port();
    let proxy_port = proxy_server.port();

    let lines = utils::RamaService::http(vec![
        &format!("https://127.0.0.1:{origin_port}"),
        "-x",
        &format!("http://127.0.0.1:{proxy_port}"),
    ])
    .unwrap();
    assert!(lines.contains("HTTP/2.0 200 OK"), "lines: {lines:?}");
    assert!(
        lines.contains("ALPN: server selected h2"),
        "lines: {lines:?}"
    );
    assert!(lines.contains(r##""method":"GET""##), "lines: {lines:?}");
}

async fn assert_icap_proxy_echo(tls: utils::IcapTlsMode) {
    let origin_server = utils::RamaService::serve_echo(0, utils::EchoMode::Http);
    let icap_server = utils::RamaService::serve_icap(0, tls);
    let origin_port = origin_server.port();
    let icap_port = icap_server.port();
    let scheme = match tls {
        utils::IcapTlsMode::Plain => "icap",
        utils::IcapTlsMode::SelfSigned | utils::IcapTlsMode::Files => "icaps",
    };
    let icap_uri = format!("{scheme}://127.0.0.1:{icap_port}/echo");
    let proxy_server = utils::RamaService::serve_proxy_icap(
        0,
        &icap_uri,
        !matches!(tls, utils::IcapTlsMode::Plain),
    );
    let proxy_port = proxy_server.port();
    let origin = format!("http://127.0.0.1:{origin_port}/icap-e2e");
    let proxy = format!("http://127.0.0.1:{proxy_port}");
    let (ok, stdout, stderr) = utils::RamaService::run_capture_isolated(
        &[
            "send",
            "--max-time",
            REQUEST_TIMEOUT_SECS,
            "--proxy",
            &proxy,
            &origin,
        ],
        None,
    )
    .unwrap();
    assert!(
        ok,
        "ICAP-adapted proxy request failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains(r##""method":"GET""##), "{stdout}");
    assert!(stdout.contains("/icap-e2e"), "{stdout}");
}

#[tokio::test]
#[ignore = "spawns rama processes"]
async fn test_proxy_icap_echo() {
    utils::init_tracing();
    assert_icap_proxy_echo(utils::IcapTlsMode::Plain).await;
}

#[tokio::test]
#[ignore = "spawns rama processes"]
async fn test_proxy_icaps_echo() {
    utils::init_tracing();
    assert_icap_proxy_echo(utils::IcapTlsMode::SelfSigned).await;
}

#[tokio::test]
#[ignore = "spawns rama processes"]
async fn test_mitm_capture_export_and_direct_cli_emulation() {
    utils::init_tracing();

    // Mirroring the shared RSA-4096 fixture can outlast the origin's first-request
    // idle deadline on Windows debug builds. This profile round trip needs TLS,
    // not a newly generated RSA-4096 key between the upstream handshake and GET.
    let origin_server = utils::RamaService::serve_echo(0, utils::EchoMode::HttpsWithGeneratedCert);
    let (proxy_server, inspector_address, inspector_token) = utils::RamaService::serve_proxy_mitm();
    let origin_port = origin_server.port();
    let proxy_port = proxy_server.port();
    let origin = format!("https://127.0.0.1:{origin_port}/profile");
    let proxy = format!("http://127.0.0.1:{proxy_port}");
    let user_agent_header = format!("User-Agent: {CUSTOM_PROFILE_USER_AGENT}");
    let first_header = format!("X-Rama-Profile-First: {CUSTOM_PROFILE_FIRST}");
    let last_header = format!("X-Rama-Profile-Last: {CUSTOM_PROFILE_LAST}");

    for version in ["--http1.1", "--http2"] {
        let (ok, stdout, stderr) = utils::RamaService::run_capture_isolated(
            &[
                "send",
                "--fail",
                "--verbose",
                "--max-time",
                REQUEST_TIMEOUT_SECS,
                "--insecure",
                version,
                "--header",
                &first_header,
                "--header",
                &user_agent_header,
                "--header",
                &last_header,
                "--header",
                "Sec-Fetch-Mode: navigate",
                "--proxy",
                &proxy,
                &origin,
            ],
            None,
        )
        .unwrap();
        assert!(
            ok,
            "{version}: capture request failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert_custom_profile_at_origin(&stdout, &stderr, version);
    }

    let directory = rama::utils::fs::tempdir().unwrap();
    let profile_path = directory.path().join("captured-profiles.json");
    let profile_path_arg = profile_path.to_string_lossy().into_owned();
    let export_uri = format!("http://{inspector_address}/api/profiles.json?ids=1,2");
    let inspector_cookie = format!("Cookie: rama-inspector={inspector_token}");
    let (ok, stdout, stderr) = utils::RamaService::run_capture_isolated(
        &[
            "send",
            "--fail",
            "--verbose",
            "--max-time",
            REQUEST_TIMEOUT_SECS,
            "--header",
            &inspector_cookie,
            "--output",
            &profile_path_arg,
            &export_uri,
        ],
        Some("127.0.0.1"),
    )
    .unwrap();
    assert!(
        ok,
        "profile export failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let profile_json = std::fs::read(&profile_path).unwrap();
    let database = UserAgentDatabase::try_from_json_slice(&profile_json).unwrap();
    let profile = database
        .get_exact_header_str(CUSTOM_PROFILE_USER_AGENT)
        .next()
        .expect("exported custom profile");
    let capabilities = profile.capabilities();
    assert!(capabilities.h1 && capabilities.h2 && capabilities.tls_tcp);
    let recorded = profile.recorded_request_headers();
    for version in [Version::HTTP_11, Version::HTTP_2] {
        let headers = recorded
            .iter()
            .find(|recorded| recorded.version == version)
            .unwrap_or_else(|| panic!("exported {version:?} request headers"));
        let pairs = headers
            .headers
            .iter()
            .map(|(name, value)| serde_json::json!([name.as_str(), value.to_str().unwrap()]))
            .collect::<Vec<_>>();
        assert_custom_profile_headers(&pairs);
    }

    let emulate_arg = format!("--emulate={profile_path_arg}");
    let direct_origin = format!("https://127.0.0.1:{origin_port}/profile-direct");
    let (ok, stdout, stderr) = utils::RamaService::run_capture_isolated(
        &[
            "send",
            "--fail",
            "--verbose",
            "--max-time",
            REQUEST_TIMEOUT_SECS,
            "--insecure",
            "--http2",
            &emulate_arg,
            &direct_origin,
        ],
        Some("127.0.0.1"),
    )
    .unwrap();
    assert!(
        ok,
        "custom-profile request failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_custom_profile_at_origin(&stdout, &stderr, "direct emulation");
}

/// `rama send` through `rama serve proxy --protocol masque`: HTTP/3 in CONNECT-UDP, HTTP/2 and
/// HTTP/1.1 and WebSockets in CONNECT, all on one MASQUE listener.
#[tokio::test]
#[ignore = "spawns rama processes"]
async fn test_masque_proxy_carries_every_workload_of_rama_send() {
    utils::init_tracing();

    let mut origin_server = utils::RamaService::serve_echo(0, utils::EchoMode::Https);
    let proxy_server = utils::RamaService::serve_proxy_with_args(
        0,
        &["--protocol", "masque", "--masque-allow-private"],
    );
    let origin = format!("https://127.0.0.1:{}", origin_server.port());
    let h3_origin = format!("https://127.0.0.1:{}", origin_server.http3_port());
    let proxy = format!("masque://127.0.0.1:{}", proxy_server.port());

    for (version_args, origin, expected) in [
        (&["--http3"][..], &h3_origin, "HTTP/3.0"),
        (&["--http2"][..], &origin, "HTTP/2.0"),
        (&["--http1.1"][..], &origin, "HTTP/1.1"),
    ] {
        let mut args = vec!["send", "-k", "--proxy-insecure", "--proxy", proxy.as_str()];
        args.extend_from_slice(version_args);
        args.push(origin.as_str());
        let lines = utils::RamaService::run(&args).unwrap();
        assert!(
            lines.contains(&format!(r#""version":"{expected}""#)),
            "{version_args:?}: {lines}"
        );
    }

    let ws = format!("wss://127.0.0.1:{}/", origin_server.port());
    let (ok, stdout, stderr) = utils::RamaService::run_capture_with_stdin(
        &["send", "-k", "--proxy-insecure", "--proxy", &proxy, &ws],
        b"through masque\n",
    )
    .unwrap();
    assert!(ok, "stdout: {stdout}\nstderr: {stderr}");
    assert!(
        stdout.contains("through masque"),
        "stdout: {stdout}\nstderr: {stderr}"
    );
}

/// `rama send` closes a connection it tunneled through a MASQUE proxy before its connection to
/// that proxy, so the origin learns of the close instead of waiting out its idle timeout.
// Multi-threaded: the origin keeps serving while `run` blocks on the process.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns rama processes"]
async fn test_rama_send_closes_its_tunneled_connection_at_the_origin() {
    utils::init_tracing();

    let (closed_tx, mut closed) = mpsc::unbounded_channel::<ConnectionError>();
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
    let h3 = HttpServer::new_http3(Executor::new()).service(service_fn(async |_: Request| {
        Ok::<_, Infallible>(Response::new(Body::from("h3 origin")))
    }));
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

    let proxy_server = utils::RamaService::serve_proxy_with_args(
        0,
        &["--protocol", "masque", "--masque-allow-private"],
    );
    let proxy = format!("masque://127.0.0.1:{}", proxy_server.port());
    let url = format!("https://127.0.0.1:{origin_port}/");
    // The close races the proxy connection's: a few runs make a lost one show.
    for run in 0..5 {
        let lines = utils::RamaService::run(&[
            "send",
            "-k",
            "--proxy-insecure",
            "--proxy",
            &proxy,
            "--http3",
            &url,
        ])
        .unwrap();
        assert!(lines.contains("h3 origin"), "run {run}: {lines}");
        // Loaded CI runners take seconds; a lost close is never `ApplicationClosed`.
        let reason = timeout(Duration::from_secs(8), closed.recv())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "run {run}: the origin's connection is still open\nclient:\n{lines}\nproxy:\n{}",
                    proxy_server.diagnostics()
                )
            })
            .unwrap();
        assert!(
            matches!(reason, ConnectionError::ApplicationClosed(_)),
            "run {run}: {reason:?}"
        );
    }
    origin.close(0u32, b"done");
}

/// A MASQUE listener needs its port on both TCP and UDP: either taken fails startup clearly.
#[tokio::test]
#[ignore = "spawns rama processes"]
async fn test_masque_proxy_refuses_to_start_when_its_port_is_taken() {
    utils::init_tracing();

    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    let bind = format!("127.0.0.1:{port}");
    let (ok, _stdout, stderr) = utils::RamaService::run_capture(&[
        "serve",
        "proxy",
        "--bind",
        &bind,
        "--protocol",
        "masque",
    ])
    .unwrap();
    assert!(!ok);
    assert!(
        stderr.contains("bind MASQUE HTTP/3 listener"),
        "stderr: {stderr}"
    );
    drop(udp);

    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bind = format!("127.0.0.1:{}", tcp.local_addr().unwrap().port());
    let (ok, _stdout, stderr) = utils::RamaService::run_capture(&[
        "serve",
        "proxy",
        "--bind",
        &bind,
        "--protocol",
        "masque",
    ])
    .unwrap();
    assert!(!ok);
    assert!(stderr.contains("bind proxy listener"), "stderr: {stderr}");
}

/// Invalid MASQUE configuration is refused before anything listens.
#[tokio::test]
#[ignore = "spawns rama processes"]
async fn test_masque_proxy_rejects_invalid_configuration_at_startup() {
    utils::init_tracing();

    for args in [
        &[
            "serve",
            "proxy",
            "--protocol",
            "masque",
            "--masque-template",
            "/masque/{target_host}",
        ][..],
        &[
            "serve",
            "proxy",
            "--protocol",
            "masque",
            "--masque-initial-mtu",
            "1100",
        ][..],
        &[
            "serve",
            "proxy",
            "--protocol",
            "masque",
            "--masque-tunnels",
            "connect-sctp",
        ][..],
        &["serve", "proxy", "--upstream-proxy-insecure"][..],
    ] {
        let (ok, _stdout, stderr) = utils::RamaService::run_capture(args).unwrap();
        assert!(!ok, "{args:?} must be refused");
        assert!(stderr.contains("error"), "{args:?}: {stderr}");
    }
}

/// An unreachable MASQUE upstream fails the request, not the proxy.
#[tokio::test]
#[ignore = "spawns rama processes"]
async fn test_masque_proxy_survives_an_unreachable_masque_upstream() {
    utils::init_tracing();

    let mut origin_server = utils::RamaService::serve_echo(0, utils::EchoMode::Https);
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = format!("masque://127.0.0.1:{}", closed.local_addr().unwrap().port());
    drop(closed);
    let mut proxy_server = utils::RamaService::serve_proxy_with_args(
        0,
        &[
            "--protocol",
            "masque",
            "--masque-allow-private",
            "--upstream-proxy",
            &upstream,
            "--upstream-proxy-insecure",
        ],
    );
    let origin = format!("https://127.0.0.1:{}", origin_server.port());
    let h3_origin = format!("https://127.0.0.1:{}", origin_server.http3_port());
    let proxy = format!("masque://127.0.0.1:{}", proxy_server.port());
    for (version, origin) in [("--http3", &h3_origin), ("--http2", &origin)] {
        let (ok, stdout, stderr) = utils::RamaService::run_capture(&[
            "send",
            "-k",
            "--proxy-insecure",
            "--proxy",
            &proxy,
            version,
            origin,
        ])
        .unwrap();
        assert!(!ok, "{version}: stdout: {stdout}\nstderr: {stderr}");
    }
    assert!(
        proxy_server.process_is_running(),
        "the proxy exited after an upstream failure"
    );
}
