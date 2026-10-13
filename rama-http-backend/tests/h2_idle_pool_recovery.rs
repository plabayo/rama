//! An idle GOAWAY retires pooled HTTP/2 transports, including a reserved request race.

#![expect(
    clippy::unwrap_used,
    reason = "Integration fixtures fail immediately at the failing setup or assertion"
)]

use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rama_core::{
    Layer, Service,
    error::{BoxError, error_chain},
    rt::Executor,
    service::service_fn,
};
use rama_http::layer::retry::{ManagedPolicy, Retry, RetryBody};
use rama_http_backend::{
    client::{HttpConnectRequestAdapter, HttpConnectorLayer, HttpPooledConnectorConfig},
    server::HttpServer,
};
use rama_http_core::{Error as HttpError, server::conn::IdleTimeout};
use rama_http_types::{
    Body, HeaderValue, Method, Request, Response, Version, body::util::BodyExt as _,
};
use rama_net::test_utils::client::MockConnectorService;
use tokio::sync::Mutex;

#[tokio::test(start_paused = true)]
async fn pooled_client_reconnects_after_server_idle_goaway() {
    idle_recovery(false).await;
}

#[tokio::test(start_paused = true)]
async fn reserved_post_retries_once_after_idle_goaway_without_reaching_application_twice() {
    idle_recovery(true).await;
}

async fn idle_recovery(reserve_before_timeout: bool) {
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let inner = HttpConnectorLayer::default().into_layer(MockConnectorService::new({
        let connections = connections.clone();
        let requests = requests.clone();
        move || {
            let id = connections.fetch_add(1, Ordering::Relaxed);
            let mut server = HttpServer::new_h2(Executor::new());
            server.h2_mut().set_idle_timeout(IdleTimeout {
                first_request: Duration::from_secs(1),
                idle: Duration::from_secs(2),
            });
            server.service(service_fn({
                let requests = requests.clone();
                move |request: Request| {
                    requests.fetch_add(1, Ordering::Relaxed);
                    async move {
                        if request.method() == Method::POST {
                            assert_eq!(
                                request.into_body().collect().await.unwrap().to_bytes(),
                                "replay once"
                            );
                        }
                        let mut response = Response::new(Body::from("ok"));
                        response
                            .headers_mut()
                            .insert("x-connection", HeaderValue::from(id as u64));
                        Ok::<_, Infallible>(response)
                    }
                }
            }))
        }
    }));
    let connector = Arc::new(HttpConnectRequestAdapter::new(
        HttpPooledConnectorConfig {
            idle_timeout: None,
            ..Default::default()
        }
        .build_connector(inner),
    ));
    for expected in [0, 0, 1] {
        if expected == 1 {
            let reserved = if reserve_before_timeout {
                Some(
                    connector
                        .serve(
                            Request::builder()
                                .uri("http://example.test/reserved")
                                .version(Version::HTTP_2)
                                .method(Method::POST)
                                .body(Body::from("replay once"))
                                .unwrap(),
                        )
                        .await
                        .unwrap(),
                )
            } else {
                None
            };
            for _ in 0..20 {
                tokio::task::yield_now().await;
            }
            tokio::time::advance(Duration::from_secs(3)).await;
            for _ in 0..20 {
                tokio::task::yield_now().await;
            }
            if let Some(reserved) = reserved {
                let rejected_attempts = Arc::new(AtomicUsize::new(0));
                let policy = ManagedPolicy::new({
                    let rejected_attempts = rejected_attempts.clone();
                    move |request: Request<RetryBody>, result: Result<Response, BoxError>| {
                        let rejected = result.as_ref().err().is_some_and(|error| {
                            error_chain(error.as_ref()).any(|error| {
                                error.downcast_ref::<HttpError>().is_some_and(|error| {
                                    error.is_canceled() || error.is_closed() || error.is_refused()
                                })
                            })
                        });
                        if rejected {
                            assert_eq!(rejected_attempts.fetch_add(1, Ordering::Relaxed), 0);
                        }
                        async move { (request, result, rejected) }
                    }
                });
                let retry = Retry::new(
                    policy,
                    service_fn({
                        let connector = connector.clone();
                        let reserved_conn = Arc::new(Mutex::new(Some(reserved.conn)));
                        move |request: Request<RetryBody>| {
                            let connector = connector.clone();
                            let reserved_conn = reserved_conn.clone();
                            async move {
                                let request = request.map(Body::new);
                                let conn = reserved_conn.lock().await.take();
                                if let Some(conn) = conn {
                                    conn.serve(request).await
                                } else {
                                    let established = connector.serve(request).await?;
                                    established.conn.serve(established.input).await
                                }
                            }
                        }
                    }),
                );
                let response = retry.serve(reserved.input).await.unwrap();
                assert_eq!(response.headers()["x-connection"], "1");
                assert_eq!(
                    response.into_body().collect().await.unwrap().to_bytes(),
                    "ok"
                );
                assert_eq!(rejected_attempts.load(Ordering::Relaxed), 1);
                assert_eq!(requests.load(Ordering::Relaxed), 3);
                assert_eq!(connections.load(Ordering::Relaxed), 2);
            }
        }
        let request = Request::builder()
            .uri("http://example.test/")
            .version(Version::HTTP_2)
            .body(Body::empty())
            .unwrap();
        let established = connector.serve(request).await.unwrap();
        let response = established.conn.serve(established.input).await.unwrap();
        assert_eq!(
            response.headers()["x-connection"].to_str().unwrap(),
            expected.to_string()
        );
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "ok"
        );
    }
    assert_eq!(connections.load(Ordering::Relaxed), 2);
    assert_eq!(
        requests.load(Ordering::Relaxed),
        3 + usize::from(reserve_before_timeout)
    );
}
