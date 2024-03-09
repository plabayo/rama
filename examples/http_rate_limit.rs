//! This example expands the `http_listener_hello` example to specifically showcase
//! how you can rate limit your HTTP server.
//!
//! Note you can also rate limit directly on the transport layer directly.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_rate_limit
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:8080`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v http://127.0.0.1:8080
//! curl -v http://127.0.0.1:8080/limit/slow
//! ```
//!
//! You should see a response with `HTTP/1.1 200 OK` and a JSON body with the method and path of the request.
//!
//! You can trigger a Rate Limit by opening 3 concurrent requests to `/limit/slow`:
//!
//! ```sh
//! curl -v http://127.0.0.1:8080/limit/slow
//! ```
//!
//! Consult your ip address to reach your server from another machine connected to the same network.

use std::{convert::Infallible, time::Duration};

use http::StatusCode;
use rama::{
    error::BoxError,
    http::{matcher::HttpMatcher, response::Json, server::HttpServer, Request},
    rt::Executor,
    service::{
        layer::{
            limit::policy::{ConcurrentPolicy, MatcherPolicyMap},
            LimitLayer,
        },
        util::backoff::ExponentialBackoff,
        ServiceBuilder,
    },
    stream::matcher::SocketMatcher,
};
use serde_json::json;

#[tokio::main]
async fn main() {
    let exec = Executor::default();

    HttpServer::auto(exec)
        .listen(
            "0.0.0.0:8080",
            ServiceBuilder::new()
                .map_result(|result: Result<Json<_>, BoxError>| match result {
                    Ok(response) => Ok((StatusCode::OK, response)),
                    Err(err) => Ok((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({
                            "error": err.to_string(),
                        })),
                    )),
                })
                .trace_err()
                .layer(LimitLayer::new(
                    MatcherPolicyMap::builder()
                        // external addresses are limited to 1 connection at a time,
                        // when choosing to use backoff, they have to be of same type (generic B),
                        // but you can make them also optional to not use backoff for some, while using it for others
                        .add(
                            HttpMatcher::socket(SocketMatcher::loopback()).negate(),
                            Some(ConcurrentPolicy::with_backoff(1, None)),
                        )
                        // you can also use options for the policy itself, in case you want to disable
                        // the limit for some
                        .add(HttpMatcher::path("/admin/*"), None)
                        // test path so you can test also rate limiting on an http level
                        // > NOTE: as you can also make your own Matchers you can limit on w/e
                        // > property you want.
                        .add(
                            HttpMatcher::path("/limit/*"),
                            Some(ConcurrentPolicy::with_backoff(
                                2,
                                Some(ExponentialBackoff::default()),
                            )),
                        )
                        .build(),
                ))
                .service_fn(|req: Request| async move {
                    if req.uri().path().ends_with("/slow") {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    }
                    Ok::<_, Infallible>(Json(json!({
                        "method": req.method().as_str(),
                        "path": req.uri().path(),
                    })))
                }),
        )
        .await
        .unwrap();
}
