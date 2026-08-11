//! This example expands the `http_listener_hello` example to specifically showcase
//! how you can rate limit your HTTP server.
//!
//! Note you can also rate limit directly on the transport layer directly.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin http_rate_limit --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62008`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v http://127.0.0.1:62008/limit
//! curl -v http://127.0.0.1:62008/limit/slow
//! ```
//!
//! You should see a response with `HTTP/1.1 200 OK` and a JSON body with the method and path of the request.
//!
//! You can trigger a Rate Limit by opening 3 concurrent requests to `/limit/slow`:
//!
//! ```sh
//! curl -v http://127.0.0.1:62008/limit/slow
//! ```
//!
//! Or easier by running:
//!
//! ```sh
//! curl -v http://127.0.0.1:62008/api/slow
//! ```
//!
//! Next to those concurrency limits this example also rate limits
//! (requests per second, backed by a token bucket):
//!
//! ```sh
//! # more than 2 requests per second get a 429 with a Retry-After header
//! for i in $(seq 1 6); do curl -so /dev/null -w "%{http_code}\n" http://127.0.0.1:62008/rate; done
//!
//! # more than 2 requests per second just wait their turn, they never fail
//! for i in $(seq 1 6); do curl -so /dev/null -w "%{http_code} %{time_total}\n" http://127.0.0.1:62008/paced; done
//!
//! # the same, but with a bucket per client IP (fair between clients)
//! for i in $(seq 1 6); do curl -so /dev/null -w "%{http_code}\n" http://127.0.0.1:62008/rate/ip; done
//! ```
//!
//! And the whole service is capped at 100 requests per second by a second
//! (stacked) limit layer, sitting outside the per-route policies.
//!
//! Consult your ip address to reach your server from another machine connected to the same network.

#![expect(
    clippy::unwrap_used,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use std::{convert::Infallible, sync::Arc, time::Duration};

use rama::{
    combinators::Either4,
    error::BoxError,
    http::headers::{HeaderMapExt, RetryAfter, util::Seconds},
    http::service::web::response::{IntoResponse, Json},
    http::{
        HeaderName, HeaderValue, Request, Response, StatusCode, matcher::HttpMatcher,
        server::HttpServer,
    },
    layer::{
        Layer, LimitLayer, MapResultLayer, TraceErrLayer,
        limit::policy::{ConcurrentPolicy, LimitReached, RateLimitReached, RatePolicy},
    },
    net::{
        rate::{ClientIpRateKey, KeyedRatePolicy},
        stream::matcher::SocketMatcher,
        uri::PathMatchOptions,
    },
    service::service_fn,
    utils::{backoff::ExponentialBackoff, rate::Rate},
};

use serde_json::json;

#[tokio::main]
async fn main() {
    HttpServer::default()
        .listen(
            "0.0.0.0:62008",
            (
                MapResultLayer::new(|result: Result<Response, BoxError>| match result {
                    Ok(response) => Ok(response),
                    Err(box_error) => {
                        if let Some(err) = box_error.downcast_ref::<RateLimitReached>() {
                            // rate limit exhausted: tell the client when to come back
                            let mut response = (
                                [(
                                    HeaderName::from_static("x-proxy-error"),
                                    HeaderValue::from_static("rate-limit-reached"),
                                )],
                                StatusCode::TOO_MANY_REQUESTS,
                            )
                                .into_response();
                            let secs = err.retry_after.as_secs()
                                + u64::from(err.retry_after.subsec_nanos() > 0);
                            response
                                .headers_mut()
                                .typed_insert(RetryAfter::delay(Seconds::new(secs)));
                            Ok(response)
                        } else if box_error.downcast_ref::<LimitReached>().is_some() {
                            Ok((
                                [(
                                    HeaderName::from_static("x-proxy-error"),
                                    HeaderValue::from_static("rate-limit-reached"),
                                )],
                                StatusCode::TOO_MANY_REQUESTS,
                            )
                                .into_response())
                        } else {
                            Ok((
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(json!({
                                    "error": box_error.to_string(),
                                })),
                            )
                                .into_response())
                        }
                    }
                }),
                TraceErrLayer::new(),
                // limit layers stack: this request-rate cap guards the whole
                // service and sits outside (= is checked before) the per-route
                // policies below, so a rate-rejected request never consumes
                // a concurrency slot
                LimitLayer::new(RatePolicy::abort(Rate::per_sec(100))),
                // using the [`Either4`] combinator you can make tree-like structures,
                // to make as complex rate limiting logic as you wish.
                //
                // For more variants you can use [`Either5`], and so on.
                // Keep it as simple as possible for your own sanity however...
                LimitLayer::new(Arc::new(vec![
                    // external addresses are limited to 1 connection at a time,
                    // when choosing to use backoff, they have to be of same type (generic B),
                    // but you can make them also optional to not use backoff for some, while using it for others
                    (
                        HttpMatcher::socket(SocketMatcher::loopback()).negate(),
                        Some(Either4::A(ConcurrentPolicy::max_with_backoff(1, None))),
                    ),
                    // you can also use options for the policy itself, in case you want to disable
                    // the limit for some
                    (HttpMatcher::path("/admin/{*}"), None),
                    // an actual rate limit: beyond 2 requests per second this
                    // aborts with a 429 response carrying a Retry-After header
                    (
                        HttpMatcher::path("/rate"),
                        Some(Either4::C(RatePolicy::abort(Rate::per_sec(2)))),
                    ),
                    // pacing instead of rejecting: beyond 2 requests per second
                    // requests wait for their turn, they never fail
                    (
                        HttpMatcher::path("/paced"),
                        Some(Either4::C(RatePolicy::wait(Rate::per_sec(2)))),
                    ),
                    // the same hard rate limit, but per client IP: one client
                    // exhausting its budget does not affect the others
                    (
                        HttpMatcher::path("/rate/ip"),
                        Some(Either4::D(KeyedRatePolicy::abort(
                            // Size the IPv6 aggregation prefix and the policy's
                            // max_keys together for the served population.
                            ClientIpRateKey::new(),
                            Rate::per_sec(2),
                        ))),
                    ),
                    // test path so you can test also rate limiting on an http level
                    // > NOTE: as you can also make your own Matchers you can limit on w/e
                    // > property you want.
                    (
                        HttpMatcher::path("/limit/{*}"),
                        Some(Either4::A(ConcurrentPolicy::max_with_backoff(
                            2,
                            Some(ExponentialBackoff::default()),
                        ))),
                    ),
                    // this one is the reason why we are using the (Vec<M, P>, P) approach from above,
                    // as we want to have a default policy for all other requests
                    (
                        HttpMatcher::path("/api/{*}"),
                        Some(Either4::B((
                            vec![
                                (
                                    HttpMatcher::path("/api/slow"),
                                    Some(ConcurrentPolicy::max_with_backoff(
                                        1,
                                        Some(ExponentialBackoff::default()),
                                    )),
                                ),
                                (HttpMatcher::path("/api/fast"), None),
                            ],
                            Some(ConcurrentPolicy::max_with_backoff(
                                5,
                                Some(ExponentialBackoff::default()),
                            )),
                        ))),
                    ),
                ])),
            )
                .into_layer(service_fn(async |req: Request| {
                    if req.uri().has_path_suffix_with_opts(
                        "slow",
                        PathMatchOptions {
                            ignore_ascii_case: true,
                            ..Default::default()
                        },
                    ) {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    }
                    Ok::<_, Infallible>(
                        Json(json!({
                            "method": req.method().as_str(),
                            "path": req.uri().path_or_root(),
                        }))
                        .into_response(),
                    )
                })),
        )
        .await
        .unwrap();
}
