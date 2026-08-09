use std::time::Duration;

use super::utils;

const ADDR: &str = "127.0.0.1:62072";

#[tokio::test]
#[ignore]
async fn test_grpc_echo() {
    utils::init_tracing();

    let _runner = utils::ExampleRunner::interactive("grpc_echo_server", Some("grpc"));

    // the example server binds asynchronously
    for i in 0..40u64 {
        if tokio::net::TcpStream::connect(ADDR).await.is_ok() {
            break;
        }
        assert!(i < 39, "grpc echo server never started listening");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let output = utils::ExampleRunner::run_with_args_output("grpc_echo_client", [""; 0]).await;
    assert!(output.status.success(), "grpc echo client failed");

    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "unary echo: \"hello rama\"\nstreaming echo: \"hello\"\nstreaming echo: \"rama\"\n",
    );
}
