use super::utils;
use rama::{http::StatusCode, service::Context};
use std::sync::Arc;

#[tokio::test]
#[ignore]
async fn test_http_rate_limit() {
    utils::init_tracing();

    let runner: Arc<utils::ExampleRunner<()>> =
        Arc::new(utils::ExampleRunner::interactive("http_rate_limit"));

    const ADDRESS: &str = "http://127.0.0.1:62008";

    assert_endpoint_concurrent_runs(runner.clone(), 3, format!("{ADDRESS}/limit"), 3).await;
    assert_endpoint_concurrent_runs(runner.clone(), 3, format!("{ADDRESS}/limit/slow"), 2).await;
    assert_endpoint_concurrent_runs(runner.clone(), 3, format!("{ADDRESS}/api/slow"), 1).await;
    assert_endpoint_concurrent_runs(runner.clone(), 5, format!("{ADDRESS}/api/fast"), 5).await;
}

async fn assert_endpoint_concurrent_runs(
    runner: Arc<utils::ExampleRunner<()>>,
    n: usize,
    endpoint: String,
    expected_success: usize,
) {
    let local_set = tokio::task::LocalSet::new();
    let mut handles = Vec::with_capacity(n);

    for _ in 0..n {
        let runner = runner.clone();
        let endpoint = endpoint.clone();
        handles.push(local_set.spawn_local(async move {
            runner
                .get(endpoint)
                .send(Context::default())
                .await
                .unwrap()
                .status()
        }));
    }

    local_set.await;

    let mut success_count: usize = 0;
    let mut too_many_request_count: usize = 0;

    for handle in handles {
        match handle.await.unwrap() {
            StatusCode::OK => {
                success_count += 1;
            }
            StatusCode::TOO_MANY_REQUESTS => {
                too_many_request_count += 1;
            }
            _ => unreachable!(),
        }
    }

    assert_eq!(success_count, expected_success, "endpoint: {}", endpoint);
    assert_eq!(
        too_many_request_count,
        n - expected_success,
        "endpoint: {}",
        endpoint
    );
}
