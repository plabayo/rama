use super::utils;
use rama::http::StatusCode;
use std::sync::Arc;

#[tokio::test]
#[ignore]
async fn test_http_rate_limit() {
    utils::init_tracing();

    let runner: Arc<utils::ExampleRunner> =
        Arc::new(utils::ExampleRunner::interactive("http_rate_limit", None));

    const ADDRESS: &str = "http://127.0.0.1:62008";

    assert_endpoint_concurrent_runs(runner.clone(), 3, format!("{ADDRESS}/limit"), 3).await;
    assert_endpoint_concurrent_runs(runner.clone(), 3, format!("{ADDRESS}/limit/slow"), 2).await;
    assert_endpoint_concurrent_runs(runner.clone(), 3, format!("{ADDRESS}/api/slow"), 1).await;
    assert_endpoint_concurrent_runs(runner.clone(), 5, format!("{ADDRESS}/api/fast"), 5).await;

    assert_rate_limited(runner.clone(), format!("{ADDRESS}/rate")).await;
    assert_rate_limited(runner.clone(), format!("{ADDRESS}/rate/ip")).await;
    assert_paced(runner.clone(), format!("{ADDRESS}/paced")).await;
}

/// a rapid burst against a 2 req/s abort-mode rate limit: the burst
/// passes, the rest is 429 with a Retry-After header
async fn assert_rate_limited(runner: Arc<utils::ExampleRunner>, endpoint: String) {
    let mut success_count: usize = 0;
    let mut too_many_request_count: usize = 0;

    for _ in 0..6 {
        let response = runner.get(endpoint.clone()).send().await.unwrap();
        match response.status() {
            StatusCode::OK => success_count += 1,
            StatusCode::TOO_MANY_REQUESTS => {
                too_many_request_count += 1;
                assert!(
                    response.headers().contains_key("retry-after"),
                    "429 must carry a Retry-After header; endpoint: {endpoint}"
                );
            }
            other => panic!("unexpected status {other}; endpoint: {endpoint}"),
        }
    }

    // exact counts depend on wall-clock refills between requests:
    // at least the burst passes, and most of the rapid rest is rejected
    assert!(success_count >= 2, "endpoint: {endpoint}");
    assert!(too_many_request_count >= 2, "endpoint: {endpoint}");
}

/// the same burst against a 2 req/s wait-mode rate limit: nothing
/// fails, requests beyond the burst are simply served spread out
async fn assert_paced(runner: Arc<utils::ExampleRunner>, endpoint: String) {
    let start = std::time::Instant::now();
    for _ in 0..6 {
        let response = runner.get(endpoint.clone()).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "endpoint: {endpoint}");
    }
    // 6 requests at 2/s with a burst of 2: at least ~2s of pacing
    assert!(
        start.elapsed() >= std::time::Duration::from_millis(1_500),
        "paced requests should be spread out, took {:?}; endpoint: {endpoint}",
        start.elapsed()
    );
}

async fn assert_endpoint_concurrent_runs(
    runner: Arc<utils::ExampleRunner>,
    n: usize,
    endpoint: String,
    expected_success: usize,
) {
    let local_set = tokio::task::LocalSet::new();
    let mut handles = Vec::with_capacity(n);

    for _ in 0..n {
        let runner = runner.clone();
        let endpoint = endpoint.clone();
        handles.push(
            local_set
                .spawn_local(async move { runner.get(endpoint).send().await.unwrap().status() }),
        );
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

    assert_eq!(success_count, expected_success, "endpoint: {endpoint}");
    assert_eq!(
        too_many_request_count,
        n - expected_success,
        "endpoint: {endpoint}",
    );
}
