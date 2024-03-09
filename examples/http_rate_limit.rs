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
//! Consult your ip address to reach your server from another machine connected to the same network.

use std::{convert::Infallible, time::Duration};

use http::StatusCode;
use rama::{
    http::{matcher::HttpMatcher, response::Json, server::HttpServer, Request},
    rt::Executor,
    service::{
        layer::{
            limit::policy::{ConcurrentPolicy, MatcherPolicyMap},
            LimitLayer,
        },
        util::{
            backoff::{ExponentialBackoffMaker, MakeBackoff},
            rng::HasherRng,
        },
        ServiceBuilder,
    },
    stream::matcher::SocketMatcher,
};
use serde_json::json;

#[tokio::main]
async fn main() {
    let exec = Executor::default();

    // you could of course also use different back offs for different mapped limits,
    // in this example we keep it simple and have just one limit for all
    let backoff_maker = ExponentialBackoffMaker::new(
        Duration::from_millis(50),
        Duration::from_secs(3),
        0.99,
        HasherRng::default(),
    )
    .expect("Unable to create ExponentialBackoff");

    // TODO:
    // - in this example:
    //   - expose error when one occurred
    //   - check why rate limit does not seem to be applied
    // - add test directly to the limit code where we clone and it should still work!
    //   - bug fix if needed

    HttpServer::auto(exec)
        .listen(
            "0.0.0.0:8080",
            ServiceBuilder::new()
                .map_result(|result| match result {
                    Ok(response) => Ok((StatusCode::OK, response)),
                    Err(_) => Ok((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({
                            "error": "something went wrong",
                        })),
                    )),
                })
                .trace_err()
                .layer(LimitLayer::new(
                    MatcherPolicyMap::builder()
                        // external addresses are limited to 1 connection at a time
                        .add(
                            HttpMatcher::socket(SocketMatcher::loopback()).negate(),
                            ConcurrentPolicy::with_backoff(1, backoff_maker.make_backoff()),
                        )
                        // test path so you can test also rate limiting on an http level
                        // > NOTE: as you can also make your own Matchers you can limit on w/e
                        // > property you want.
                        .add(
                            HttpMatcher::path("/limit/*"),
                            ConcurrentPolicy::with_backoff(2, backoff_maker.make_backoff()),
                        )
                        .build(),
                ))
                .service_fn(|req: Request| async move {
                    if req.uri().path().starts_with("/limit/slow") {
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
