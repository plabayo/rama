use super::utils;

#[tokio::test]
#[ignore]
async fn test_grpc_echo() {
    utils::init_tracing();

    let mut runner = utils::ExampleRunner::interactive(utils::example!("grpc_echo_server"));
    runner.wait_for_tcp(([127, 0, 0, 1], 62072)).await;

    let output =
        utils::ExampleRunner::run_with_args_output(utils::example!("grpc_echo_client"), [""; 0])
            .await;
    assert!(output.status.success(), "grpc echo client failed");

    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "unary echo: \"hello rama\"\nstreaming echo: \"hello\"\nstreaming echo: \"rama\"\n",
    );
}
