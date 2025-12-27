use super::utils;
use rama::http::BodyExtractExt;
use serde_json::Value;

#[tokio::test]
#[ignore]
async fn test_tcp_listener_fd_passing() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("tcp_listener_fd_passing", None);

    // Retry until child process is serving (FD handoff takes variable time)
    let response = async {
        for i in 0..8 {
            match runner.get("http://127.0.0.1:62046").send().await {
                Ok(r) => return Some(r),
                Err(e) => {
                    eprintln!("attempt {i}: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(200 + 150 * i)).await;
                }
            }
        }
        None
    }
    .await
    .expect("child process to become ready");

    let first = response.try_into_json::<Value>().await.unwrap();
    assert_eq!(first["message"], "Hello from child process!");
    assert_eq!(first["zero_downtime"], true);
    let pid = first["pid"].as_u64().expect("pid should be a number");
    assert!(pid > 0);

    // Second request to verify same child process is still serving
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let second = runner
        .get("http://127.0.0.1:62046")
        .send()
        .await
        .unwrap()
        .try_into_json::<Value>()
        .await
        .unwrap();

    assert_eq!(
        second["pid"].as_u64().unwrap(),
        pid,
        "same child should serve both requests"
    );
}
