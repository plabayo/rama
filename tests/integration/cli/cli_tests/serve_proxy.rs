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

fn assert_custom_profile_at_origin(stdout: &str) {
    let response: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|error| panic!("invalid echo response: {error}\n{stdout}"));
    let headers = response["http"]["headers"]
        .as_array()
        .expect("echo response contains ordered headers");
    assert_custom_profile_headers(headers);
}

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
    let (_proxy, inspector_token) =
        utils::RamaService::serve_proxy_mitm(proxy_port, inspector_port);
    let origin = format!("https://127.0.0.1:{origin_port}/profile");
    let proxy = format!("http://127.0.0.1:{proxy_port}");
    let user_agent_header = format!("User-Agent: {CUSTOM_PROFILE_USER_AGENT}");
    let first_header = format!("X-Rama-Profile-First: {CUSTOM_PROFILE_FIRST}");
    let last_header = format!("X-Rama-Profile-Last: {CUSTOM_PROFILE_LAST}");

    for version in ["--http1.1", "--http2"] {
        let (ok, stdout, stderr) = utils::RamaService::run_capture_isolated(
            &[
                "send",
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
            "capture request failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert_custom_profile_at_origin(&stdout);
    }

    let directory = rama::utils::fs::tempdir().unwrap();
    let profile_path = directory.path().join("captured-profiles.json");
    let profile_path_arg = profile_path.to_string_lossy().into_owned();
    let export_uri = format!("http://127.0.0.1:{inspector_port}/api/profiles.json?ids=1,2");
    let inspector_cookie = format!("Cookie: rama-inspector={inspector_token}");
    let (ok, stdout, stderr) = utils::RamaService::run_capture_isolated(
        &[
            "send",
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
    let profiles: serde_json::Value = serde_json::from_slice(&profile_json).unwrap();
    let profile = &profiles.as_array().expect("profile export is an array")[0];
    assert_eq!(profile["uastr"], CUSTOM_PROFILE_USER_AGENT);
    assert!(profile["h1_settings"].is_object());
    assert!(profile["h1_headers_navigate"].is_array());
    assert!(profile["h2_settings"].is_object());
    assert!(profile["h2_headers_navigate"].is_array());
    assert!(profile["tls_client_hello"].is_object());
    assert_custom_profile_headers(profile["h1_headers_navigate"].as_array().unwrap());
    assert_custom_profile_headers(profile["h2_headers_navigate"].as_array().unwrap());

    let emulate_arg = format!("--emulate={profile_path_arg}");
    let direct_origin = format!("https://127.0.0.1:{origin_port}/profile-direct");
    let (ok, stdout, stderr) = utils::RamaService::run_capture_isolated(
        &[
            "send",
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
    assert_custom_profile_at_origin(&stdout);
}
