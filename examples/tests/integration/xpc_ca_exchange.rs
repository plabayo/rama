use super::utils;

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_xpc_ca_exchange() {
    utils::init_tracing();

    let output = utils::ExampleRunner::command(utils::example!("xpc_ca_exchange"))
        .env(
            "RUST_LOG",
            std::env::var("RUST_LOG").unwrap_or_else(|_| "debug".into()),
        )
        .env("NO_COLOR", "1")
        .output()
        .expect("run xpc_ca_exchange");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");

    assert!(
        output.status.success(),
        "xpc_ca_exchange exited with status {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status,
    );

    assert!(
        combined.contains("xpc_ca_exchange::client: received reply"),
        "expected reply line in output:\n{combined}"
    );
}
