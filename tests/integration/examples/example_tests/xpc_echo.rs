#![expect(clippy::expect_used, reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses")]

use super::utils;

#[tokio::test]
#[ignore]
async fn test_xpc_echo() {
    utils::init_tracing();

    // The example is self-contained: it creates an anonymous XPC channel, exchanges
    // messages between two in-process tokio tasks, then exits. We just verify it exits
    // successfully without panicking.
    let output = escargot::CargoBuild::new()
        .arg("--features=net-apple-xpc")
        .example("xpc_echo")
        .manifest_path("Cargo.toml")
        .target_dir("./target/")
        .run()
        .expect("cargo build xpc_echo")
        .command()
        .env(
            "RUST_LOG",
            std::env::var("RUST_LOG").unwrap_or_else(|_| "debug".into()),
        )
        .env("NO_COLOR", "1")
        .output()
        .expect("run xpc_echo");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");

    assert!(
        output.status.success(),
        "xpc_echo exited with status {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status,
    );

    assert!(
        combined.contains("xpc_echo::client: got reply"),
        "expected reply line in output:\n{combined}"
    );
}
