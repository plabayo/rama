//! Interim responses are relayed up to a per-request limit and refused past it.

use super::{LIMIT, Pair};
use crate::h3::{Error, client, connection::Config, qpack::ErrorScope, server};
use rama_core::{extensions::ExtensionsRef as _, graceful::WeakScope, rt::spawn};
use rama_http_types::{
    Body, Method, Request, Response, StatusCode,
    proto::{h1::ext::informational::OnInformational, h3::Code},
};
use rama_net::uri::Uri;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

const ALLOWED: usize = 3;

/// Answer one request with `interim` 103 responses and a final one; report how many were seen.
async fn exchange(method: Method, interim: usize) -> (Result<StatusCode, Error>, usize) {
    // A refused CONNECT is an ordinary response, so no tunnel has to be held open.
    let last = if method == Method::CONNECT {
        StatusCode::FORBIDDEN
    } else {
        StatusCode::OK
    };
    let pair = Pair::in_memory(None, None).await;
    let config = Config {
        max_informational_responses: ALLOWED,
        ..Config::default()
    };
    let (mut client, client_driver) =
        client::handshake::<Body, _>(pair.client.clone(), config, WeakScope::detached()).unwrap();
    let (mut server, server_driver) =
        server::handshake(pair.server.clone(), Config::default()).unwrap();
    spawn(client_driver.run());
    spawn(server_driver.run());
    let serve = spawn(async move {
        let (_request, mut response) = server.accept().await.unwrap().resolve().await.unwrap();
        for _ in 0..interim {
            // The client refuses the stream once the limit is passed.
            if response
                .send_informational(Response::builder().status(103).body(()).unwrap())
                .await
                .is_err()
            {
                return;
            }
        }
        let last = Response::builder()
            .status(last)
            .body(Body::empty())
            .unwrap();
        _ = response.send_response(last).await;
    });
    let uri = if method == Method::CONNECT {
        Uri::parse_http_request_target("localhost:443", true).unwrap()
    } else {
        Uri::from_static("https://localhost/")
    };
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = seen.clone();
    request
        .extensions()
        .insert(OnInformational::new_fn(move |_response| {
            counter.fetch_add(1, Ordering::Relaxed);
        }));
    let result = client
        .send_request(request)
        .await
        .map(|response| response.status());
    serve.await.unwrap();
    pair.close().await;
    (result, seen.load(Ordering::Relaxed))
}

#[tokio::test(start_paused = true)]
async fn informational_responses_up_to_the_limit_precede_a_final_response() {
    tokio::time::timeout(LIMIT, async {
        for method in [Method::GET, Method::CONNECT] {
            let (result, seen) = exchange(method, ALLOWED).await;
            assert!(!result.unwrap().is_informational());
            assert_eq!(seen, ALLOWED);
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn informational_responses_past_the_limit_fail_the_request() {
    tokio::time::timeout(LIMIT, async {
        for method in [Method::GET, Method::CONNECT] {
            let (result, seen) = exchange(method, ALLOWED + 1).await;
            let error = result.unwrap_err();
            assert_eq!(error.code(), Code::H3_EXCESSIVE_LOAD);
            assert_eq!(error.scope(), ErrorScope::Stream);
            assert_eq!(seen, ALLOWED);
        }
    })
    .await
    .unwrap();
}
