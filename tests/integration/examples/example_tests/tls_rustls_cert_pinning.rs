use super::utils;

#[tokio::test]
#[ignore]
async fn test_tls_rustls_cert_pinning() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive_with_envs(
        "tls_rustls_dynamic_certs",
        Some("rustls,aws-lc"),
        [("RAMA_TLS_RUSTLS_DYNAMIC_CERTS_ADDR", "127.0.0.1:64902")],
    );
    runner.get("https://127.0.0.1:64902").send().await.unwrap();

    let secure_output = utils::ExampleRunner::run_with_args_output(
        "tls_rustls_cert_pinning",
        ["https://127.0.0.1:64902", "examples/assets/example.com.crt"],
    )
    .await;
    assert!(!secure_output.status.success(), "{secure_output:?}");

    let mismatch_output = utils::ExampleRunner::run_with_args_output(
        "tls_rustls_cert_pinning",
        [
            "--insecure",
            "https://127.0.0.1:64902",
            "examples/assets/second_example.com.crt",
        ],
    )
    .await;
    assert!(!mismatch_output.status.success(), "{mismatch_output:?}");

    // the standard key-pin string form of examples/assets/example.com.crt,
    // as printed by `rama probe tls`
    let output = utils::ExampleRunner::run_with_args_output(
        "tls_rustls_cert_pinning",
        [
            "--insecure",
            "https://127.0.0.1:64902",
            "sha256/xg6kqyS+uaJikboVvZPxNOYXMD3XPakJAakHSfGau/M=",
        ],
    )
    .await;

    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("https://127.0.0.1:64902: 200 OK"));
}
