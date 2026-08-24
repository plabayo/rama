use super::utils;

const EMULATED_USER_AGENT: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1";

#[tokio::test]
#[ignore]
async fn test_http_proxy_echo() {
    utils::init_tracing();

    let _guard = utils::RamaService::serve_echo(63125, utils::EchoMode::Http);
    let _guard = utils::RamaService::serve_proxy(63126);

    let lines = utils::RamaService::http(vec![
        "http://127.0.0.1:63125",
        "-x",
        "http://127.0.0.1:63126",
    ])
    .unwrap();
    assert!(lines.contains("HTTP/1.1 200 OK"), "lines: {lines:?}");
    assert!(lines.contains(r##""method":"GET""##), "lines: {lines:?}");
}

#[tokio::test]
#[ignore]
async fn test_https_proxy_echo() {
    utils::init_tracing();

    let _guard = utils::RamaService::serve_echo(63127, utils::EchoMode::Https);
    let _guard = utils::RamaService::serve_proxy(63128);

    let lines = utils::RamaService::http(vec![
        "https://127.0.0.1:63127",
        "-x",
        "http://127.0.0.1:63128",
    ])
    .unwrap();
    assert!(lines.contains("HTTP/2.0 200 OK"), "lines: {lines:?}");
    assert!(
        lines.contains("ALPN: server selected h2"),
        "lines: {lines:?}"
    );
    assert!(lines.contains(r##""method":"GET""##), "lines: {lines:?}");
}

#[tokio::test]
#[ignore]
async fn test_mitm_capture_export_and_direct_cli_emulation() {
    utils::init_tracing();

    let origin_port = utils::reserve_loopback_port();
    let proxy_port = utils::reserve_loopback_port();
    let inspector_port = utils::reserve_loopback_port();
    let _origin = utils::RamaService::serve_echo(origin_port, utils::EchoMode::Https);
    let _proxy = utils::RamaService::serve_proxy_mitm(proxy_port, inspector_port);
    let origin = format!("https://127.0.0.1:{origin_port}/profile");
    let proxy = format!("http://127.0.0.1:{proxy_port}");
    let user_agent_header = format!("User-Agent: {EMULATED_USER_AGENT}");

    for version in ["--http1.1", "--http2"] {
        let (ok, stdout, stderr) = utils::RamaService::run_capture_isolated(
            &[
                "send",
                "--max-time",
                "10",
                "--insecure",
                "--emulate",
                version,
                "--header",
                &user_agent_header,
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
            "capture request failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert!(
            stdout.contains(EMULATED_USER_AGENT),
            "origin did not observe selected embedded profile\n{stdout}"
        );
    }

    let directory = rama::utils::fs::tempdir().unwrap();
    let profile_path = directory.path().join("captured-profiles.json");
    let profile_path_arg = profile_path.to_string_lossy().into_owned();
    let export_uri = format!("http://127.0.0.1:{inspector_port}/api/profiles.json?ids=1,2");
    let (ok, stdout, stderr) = utils::RamaService::run_capture_isolated(
        &[
            "send",
            "--max-time",
            "10",
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
    let profiles: serde_json::Value = serde_json::from_slice(&profile_json).unwrap();
    let profile = &profiles.as_array().expect("profile export is an array")[0];
    assert_eq!(profile["uastr"], EMULATED_USER_AGENT);
    assert!(profile["h1_settings"].is_object());
    assert!(profile["h1_headers_navigate"].is_array());
    assert!(profile["h2_settings"].is_object());
    assert!(profile["h2_headers_navigate"].is_array());
    assert!(profile["tls_client_hello"].is_object());

    let emulate_arg = format!("--emulate={profile_path_arg}");
    let direct_origin = format!("https://127.0.0.1:{origin_port}/profile-direct");
    let (ok, stdout, stderr) = utils::RamaService::run_capture_isolated(
        &[
            "send",
            "--max-time",
            "10",
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
    assert!(
        stdout.contains(EMULATED_USER_AGENT),
        "direct origin did not observe the exported profile\n{stdout}"
    );
}
