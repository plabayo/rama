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
