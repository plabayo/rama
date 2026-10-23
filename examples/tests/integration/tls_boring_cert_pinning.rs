use super::utils;

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_tls_boring_cert_pinning() {
    utils::init_tracing();

    let mut runner = utils::ExampleRunner::interactive_with_envs(
        utils::example!("tls_boring_dynamic_certs"),
        [("RAMA_TLS_BORING_DYNAMIC_CERTS_ADDR", "127.0.0.1:0")],
    );
    let url = format!("https://{}", runner.tcp_listener_addr().await);

    let secure_output = utils::ExampleRunner::run_with_args_output(
        utils::example!("tls_boring_cert_pinning"),
        [url.as_str(), "examples/assets/example.com.crt"],
    )
    .await;
    assert!(!secure_output.status.success(), "{secure_output:?}");

    let mismatch_output = utils::ExampleRunner::run_with_args_output(
        utils::example!("tls_boring_cert_pinning"),
        ["-k", url.as_str(), "examples/assets/second_example.com.crt"],
    )
    .await;
    assert!(!mismatch_output.status.success(), "{mismatch_output:?}");

    let output = utils::ExampleRunner::run_with_args_output(
        utils::example!("tls_boring_cert_pinning"),
        ["-k", url.as_str(), "examples/assets/example.com.crt"],
    )
    .await;

    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains(&format!("{url}: 200 OK")));
}
