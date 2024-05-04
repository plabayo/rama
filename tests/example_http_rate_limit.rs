pub mod test_server;

use http::StatusCode;
use rama::error::BoxError;
use rama::http::client::{HttpClient, HttpClientExt};
use rama::http::layer::decompression::DecompressionLayer;
use rama::http::layer::retry::{ManagedPolicy, RetryLayer};
use rama::http::layer::trace::TraceLayer;
use rama::service::util::backoff::ExponentialBackoff;
use rama::service::{Context, ServiceBuilder};
use std::sync::atomic::{AtomicUsize, Ordering};

const ADDRESS: &str = "127.0.0.1:40007";
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
    for handle in handle {
        handle.await?;
    }
    assert_eq!(COUNT_OK.load(Ordering::Relaxed), 2);
    assert_eq!(COUNT_TOO_MANY_REQUEST.load(Ordering::Relaxed), 1);
    Ok(())
}

async fn connect_limit_slow() {
    let client = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(DecompressionLayer::new())
        .layer(RetryLayer::new(
            ManagedPolicy::default().with_backoff(ExponentialBackoff::default()),
        ))
        .service(HttpClient::new());

    let request = client
        .get(format!("http://{ADDRESS}/{}", "limit/slow"))
        .send(Context::default())
        .await
        .unwrap();

    let (parts, _) = request.into_parts();

    match parts.status {
        StatusCode::OK => {
            COUNT_OK.fetch_add(1, Ordering::Relaxed);
        }
        StatusCode::TOO_MANY_REQUESTS => {
            COUNT_TOO_MANY_REQUEST.fetch_add(1, Ordering::Relaxed);
        }
        _ => unreachable!(),
    };
}
