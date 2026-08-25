use super::utils;
use std::time::{Duration, Instant};

#[tokio::test]
#[ignore]
async fn test_http_and_grpc_job_service() {
    utils::init_tracing();

    let _runner = utils::ExampleRunner::interactive("http_grpc_job_server", Some("grpc"));
    wait_for_server().await;

    // The client demo is the test driver: it calls HTTP health, gRPC health, submits and
    // streams a job over gRPC, then reads the completed job back over HTTP.
    let output = utils::ExampleRunner::run_with_args_output(
        "http_grpc_job_client",
        ["demo", "--task", "integration test job"],
    )
    .await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "HTTP + gRPC job client failed\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
    assert!(stdout.contains("HTTP health: ok\n"));
    assert!(stdout.contains("gRPC health: SERVING\n"));
    assert!(stdout.contains("gRPC submitted job 1: \"integration test job\"\n"));
    assert!(stdout.contains("gRPC job 1: 100% JOB_STATE_SUCCEEDED"));
    assert!(stdout.contains("HTTP job 1: 100% JOB_STATE_SUCCEEDED \"integration test job\"\n"));
}

async fn wait_for_server() {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match tokio::net::TcpStream::connect("127.0.0.1:62073").await {
            Ok(_) => return,
            Err(error) if Instant::now() >= deadline => {
                panic!("job server did not start before the deadline: {error}")
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
        }
    }
}
