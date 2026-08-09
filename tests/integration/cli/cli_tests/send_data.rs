//! E2E tests for `rama send data:...` — the self-contained URI
//! transport (RFC 2397), served by the client's data-uri layer.

use super::utils;

#[tokio::test]
#[ignore]
async fn test_send_data_plain_payload() {
    utils::init_tracing();

    let (ok, stdout, stderr) =
        utils::RamaService::run_capture(&["send", "data:,hello%20rama"]).expect("spawn rama send");
    assert!(ok, "rama send data: failed; stderr:\n{stderr}");
    assert_eq!(stdout, "hello rama", "stderr:\n{stderr}");
}

#[tokio::test]
#[ignore]
async fn test_send_data_base64_payload() {
    utils::init_tracing();

    // `SGVsbG8gUEFD` decodes to `Hello PAC`
    let (ok, stdout, stderr) =
        utils::RamaService::run_capture(&["send", "data:text/plain;base64,SGVsbG8gUEFD"])
            .expect("spawn rama send");
    assert!(ok, "rama send base64 data: failed; stderr:\n{stderr}");
    assert_eq!(stdout, "Hello PAC", "stderr:\n{stderr}");
}

#[tokio::test]
#[ignore]
async fn test_send_data_media_type_is_served() {
    utils::init_tracing();

    let (ok, stdout, stderr) = utils::RamaService::run_capture(&[
        "send",
        "data:application/x-ns-proxy-autoconfig,function FindProxyForURL(u, h) { return 'DIRECT'; }",
    ])
    .expect("spawn rama send");
    assert!(ok, "rama send typed data: failed; stderr:\n{stderr}");
    assert!(
        stdout.contains("FindProxyForURL"),
        "stdout mismatch: {stdout:?}; stderr:\n{stderr}"
    );
}

#[tokio::test]
#[ignore]
async fn test_send_data_payload_with_ternary_is_not_truncated() {
    utils::init_tracing();

    // the `?` of a ternary is payload, not a uri query
    let script = r#"function FindProxyForURL(u,h){return h=="a"?"DIRECT":"PROXY p:1";}"#;
    let uri = format!("data:application/x-ns-proxy-autoconfig,{script}");
    let (ok, stdout, stderr) =
        utils::RamaService::run_capture(&["send", uri.as_str()]).expect("spawn rama send");
    assert!(ok, "rama send data: with `?` failed; stderr:\n{stderr}");
    assert_eq!(stdout, script, "stderr:\n{stderr}");
}

#[tokio::test]
#[ignore]
async fn test_send_data_payload_with_dot_segments_is_not_mangled() {
    utils::init_tracing();

    // `a/../b` is payload: uri path canonicalization must not touch it
    let (ok, stdout, stderr) =
        utils::RamaService::run_capture(&["send", "data:,a/../b"]).expect("spawn rama send");
    assert!(ok, "rama send data: with `..` failed; stderr:\n{stderr}");
    assert_eq!(stdout, "a/../b", "stderr:\n{stderr}");
}

#[tokio::test]
#[ignore]
async fn test_send_data_payload_with_fragment_stops_at_the_fragment() {
    utils::init_tracing();

    // the `#` starts a uri fragment, so only `a` is payload
    let (ok, stdout, stderr) =
        utils::RamaService::run_capture(&["send", "data:,a#b"]).expect("spawn rama send");
    assert!(ok, "rama send data: with `#` failed; stderr:\n{stderr}");
    assert_eq!(stdout, "a", "stderr:\n{stderr}");
}

#[tokio::test]
#[ignore]
async fn test_send_data_base64_marker_is_case_insensitive() {
    utils::init_tracing();

    let (ok, stdout, stderr) =
        utils::RamaService::run_capture(&["send", "data:text/plain;BASE64,SGVsbG8gUEFD"])
            .expect("spawn rama send");
    assert!(ok, "rama send mixed-case base64 failed; stderr:\n{stderr}");
    assert_eq!(stdout, "Hello PAC", "stderr:\n{stderr}");
}

#[tokio::test]
#[ignore]
async fn test_send_data_malformed_errors() {
    utils::init_tracing();

    // no `,` separator: not a valid data: URI
    let (ok, _stdout, stderr) =
        utils::RamaService::run_capture(&["send", "data:text/plain"]).expect("spawn rama send");
    assert!(!ok, "malformed data: should exit non-zero");
    assert!(
        stderr.contains("payload separator"),
        "stderr should explain the missing separator, got:\n{stderr}"
    );
}

#[tokio::test]
#[ignore]
async fn test_send_data_invalid_base64_errors() {
    utils::init_tracing();

    let (ok, _stdout, stderr) =
        utils::RamaService::run_capture(&["send", "data:text/plain;base64,!!!nope!!!"])
            .expect("spawn rama send");
    assert!(!ok, "invalid base64 data: should exit non-zero");
    assert!(
        stderr.contains("base64"),
        "stderr should mention base64, got:\n{stderr}"
    );
}
