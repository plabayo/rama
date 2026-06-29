//! E2E tests for `rama send` JSON response selection.

use super::utils;
use std::process::Command;

#[tokio::test]
#[ignore]
async fn test_send_select_json_response() {
    utils::init_tracing();

    let _guard = utils::RamaService::serve_http_test(63142, false);

    let (ok, stdout, stderr) = run_built_rama_capture(&[
        "send",
        "--max-time",
        "5",
        "--json",
        "-d",
        "hello",
        "--select-json",
        "$.bytes",
        "http://127.0.0.1:63142/sink",
    ]);

    assert!(ok, "rama send failed; stderr:\n{stderr}");
    assert_eq!(stdout, "5\n");
}

fn run_built_rama_capture(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(format!(
        "./target/debug/rama{}",
        std::env::consts::EXE_SUFFIX
    ))
    .args(args)
    .output()
    .expect("spawn rama send");

    (
        output.status.success(),
        String::from_utf8(output.stdout).expect("stdout utf8"),
        String::from_utf8(output.stderr).expect("stderr utf8"),
    )
}
