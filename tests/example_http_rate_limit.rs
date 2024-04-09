mod test_server;

use crate::test_server::recive_as_string;
use futures::future::join_all;
use http::StatusCode;
use rama::{error::BoxError, http::Request};
use std::sync::atomic::{AtomicUsize, Ordering};

const URL: &str = "http://127.0.0.1:40007/";
static COUNT_OK: AtomicUsize = AtomicUsize::new(0);
static COUNT_TOO_MANY_REQUEST: AtomicUsize = AtomicUsize::new(0);

#[tokio::test]
async fn test_http_rate_limit() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("http_rate_limit");
    let _ = test_limit_slow().await;

    Ok(())
}

async fn test_limit_slow() -> Result<(), BoxError> {
    let mut handle = Vec::new();
    for _ in 0..3 {
        handle.push(tokio::spawn(connect_limit_slow()));
    }
    join_all(handle).await;
    assert_eq!(COUNT_OK.load(Ordering::Relaxed), 2);
    assert_eq!(COUNT_TOO_MANY_REQUEST.load(Ordering::Relaxed), 1);
    Ok(())
}

async fn connect_limit_slow() {
    let request = Request::builder()
        .method("GET")
        .uri(format!("{}{}", URL, "limit/slow"))
        .body(String::new())
        .unwrap();

    let (part, _) = recive_as_string(request).await.unwrap();

    match part.status {
        StatusCode::OK => {
            COUNT_OK.fetch_add(1, Ordering::SeqCst);
        }
        StatusCode::TOO_MANY_REQUESTS => {
            COUNT_TOO_MANY_REQUEST.fetch_add(1, Ordering::SeqCst);
        }
        _ => unreachable!(),
    };
}
