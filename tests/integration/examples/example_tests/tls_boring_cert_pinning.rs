use super::utils;

#[tokio::test]
#[ignore]
async fn test_tls_boring_cert_pinning() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive_with_envs(
        "tls_boring_dynamic_certs",
        Some("boring"),
        [("RAMA_TLS_BORING_DYNAMIC_CERTS_ADDR", "127.0.0.1:64901")],
    );
    runner.get("https://127.0.0.1:64901").send().await.unwrap();

    let secure_output = utils::ExampleRunner::run_with_args_output(
        "tls_boring_cert_pinning",
        ["https://127.0.0.1:64901", "examples/assets/example.com.crt"],
    )
    .await;
    assert!(!secure_output.status.success(), "{secure_output:?}");

    let mismatch_output = utils::ExampleRunner::run_with_args_output(
        "tls_boring_cert_pinning",
        [
            "-k",
            "https://127.0.0.1:64901",
            "examples/assets/second_example.com.crt",
        ],
    )
    .await;
    assert!(!mismatch_output.status.success(), "{mismatch_output:?}");

    let output = utils::ExampleRunner::run_with_args_output(
        "tls_boring_cert_pinning",
        [
            "-k",
            "https://127.0.0.1:64901",
            "examples/assets/example.com.crt",
        ],
    )
    .await;

    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("served by boring tls terminator proxy")
    );
}
