//! `--next` requests run in order on the real client, each with its own options.

use super::{output_dir, send_cfg, spawn_origin};
use crate::cmd::send::{http::run_inner, next::following_requests};
use parking_lot::Mutex;
use rama::{
    http::{
        Body, Method, Request, Response, StatusCode,
        body::util::BodyExt as _,
        header::{AUTHORIZATION, COOKIE},
    },
    service::service_fn,
};
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

#[tokio::test]
async fn next_requests_run_in_order_with_their_own_options_and_only_the_last_output() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let origin = spawn_origin(service_fn({
        let seen = seen.clone();
        move |incoming: Request| {
            let seen = seen.clone();
            async move {
                let path = incoming.uri().path_or_root().into_owned();
                let method = incoming.method().clone();
                let authorization = incoming.headers().get(AUTHORIZATION).cloned();
                let cookie = incoming.headers().get(COOKIE).cloned();
                let order: Vec<_> = incoming
                    .headers()
                    .get_all("x-order")
                    .iter()
                    .cloned()
                    .collect();
                let body = incoming.into_body().collect().await.unwrap().to_bytes();
                seen.lock()
                    .push((path.clone(), method, authorization, cookie, order, body));
                Ok::<_, Infallible>(Response::new(Body::from(if path == "/main" {
                    "main-only".to_owned()
                } else {
                    "not-written".repeat(4096)
                })))
            }
        }
    }))
    .await;
    let (_directory, output) = output_dir();
    let (first, second, main) = (
        format!("http://{origin}/first"),
        format!("http://{origin}/second"),
        format!("http://{origin}/main"),
    );
    let proxy = format!("http://{origin}");
    let cfg = send_cfg(&[
        "--http1.1",
        "--proxy",
        &proxy,
        "--output",
        &output,
        "--last-response-only",
        "-X",
        "POST",
        "-H",
        "x-order: first",
        "-H",
        "x-order: second",
        "-H",
        "authorization: explicit-row",
        "-d",
        "preliminary",
        &first,
        "--next",
        &second,
        "--next",
        "--user",
        "test:synthetic",
        "-H",
        "Cookie: main-private",
        "-d",
        "MAIN",
        &main,
    ]);
    run_inner(&cfg, &following_requests(&cfg).unwrap(), false)
        .await
        .unwrap();
    assert_eq!(tokio::fs::read(&output).await.unwrap(), b"main-only");
    let seen = seen.lock();
    assert_eq!(
        seen.iter().map(|row| row.0.as_str()).collect::<Vec<_>>(),
        ["/first", "/second", "/main"]
    );
    assert_eq!(seen[0].1, Method::POST);
    assert_eq!(seen[0].2.as_ref().unwrap(), "explicit-row");
    assert_eq!(
        seen[0]
            .4
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    assert_eq!(seen[0].5, b"preliminary".as_slice());
    // Nothing of the first request is inherited.
    assert_eq!(seen[1].1, Method::GET);
    assert!(seen[1].2.is_none() && seen[1].3.is_none() && seen[1].4.is_empty());
    assert!(seen[1].5.is_empty());
    assert_eq!(seen[2].1, Method::POST);
    assert_eq!(seen[2].2.as_ref().unwrap(), "Basic dGVzdDpzeW50aGV0aWM=");
    assert_eq!(seen[2].3.as_ref().unwrap(), "main-private");
    assert_eq!(seen[2].5, b"MAIN".as_slice());
}

#[tokio::test]
async fn every_response_is_written_in_order_by_default() {
    let origin = spawn_origin(service_fn(|incoming: Request| async move {
        let body = format!("[{}]", incoming.uri().path_or_root());
        Ok::<_, Infallible>(Response::new(Body::from(body)))
    }))
    .await;
    let (_directory, output) = output_dir();
    let proxy = format!("http://{origin}");
    let (first, second) = (
        format!("http://{origin}/first"),
        format!("http://{origin}/second"),
    );
    let cfg = send_cfg(&[
        "--http1.1",
        "--proxy",
        &proxy,
        "--output",
        &output,
        &first,
        "--next",
        &second,
    ]);
    run_inner(&cfg, &following_requests(&cfg).unwrap(), false)
        .await
        .unwrap();
    assert_eq!(
        tokio::fs::read(&output).await.unwrap(),
        b"[/first][/second]"
    );
}

#[tokio::test]
async fn fail_stops_at_an_earlier_error_status_only_when_requested() {
    for fail in [false, true] {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let origin = spawn_origin(service_fn({
            let seen = seen.clone();
            move |incoming: Request| {
                let path = incoming.uri().path_or_root().into_owned();
                seen.lock().push(path.clone());
                async move {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(if path == "/reject" {
                                StatusCode::CONFLICT
                            } else {
                                StatusCode::OK
                            })
                            .body(Body::from("body"))
                            .unwrap(),
                    )
                }
            }
        }))
        .await;
        let (_directory, output) = output_dir();
        let proxy = format!("http://{origin}");
        let (reject, tail) = (
            format!("http://{origin}/reject"),
            format!("http://{origin}/tail"),
        );
        let mut arguments = vec!["--http1.1", "--proxy", &proxy, "--output", &output];
        if fail {
            arguments.push("--fail");
        }
        arguments.extend([reject.as_str(), "--next", tail.as_str()]);
        let cfg = send_cfg(&arguments);
        let result = run_inner(&cfg, &following_requests(&cfg).unwrap(), false).await;
        assert_eq!(result.is_err(), fail);
        assert_eq!(
            *seen.lock(),
            if fail {
                vec!["/reject"]
            } else {
                vec!["/reject", "/tail"]
            }
        );
    }
}

#[tokio::test]
async fn an_invalid_next_request_prevents_all_transport_io() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(service_fn({
        let hits = hits.clone();
        move |_: Request| {
            hits.fetch_add(1, Ordering::Relaxed);
            async { Ok::<_, Infallible>(Response::new(Body::empty())) }
        }
    }))
    .await;
    let (_directory, output) = output_dir();
    let proxy = format!("http://{origin}");
    let first = format!("http://{origin}/must-not-run");
    for invalid in [
        &["--next", "-X"][..],
        &[
            "--next",
            "--proxy",
            "http://other.test",
            "http://other.test/",
        ],
        &[
            "--next",
            "--emulate-request-variant",
            &"00".repeat(32),
            "http://other.test/",
        ],
    ] {
        let mut arguments = vec!["--http1.1", "--proxy", &proxy, "--output", &output, &first];
        arguments.extend_from_slice(invalid);
        let cfg = send_cfg(&arguments);
        let result = match following_requests(&cfg) {
            Ok(following) => run_inner(&cfg, &following, false).await,
            Err(error) => Err(error),
        };
        result.expect_err("invalid --next request");
    }
    assert_eq!(hits.load(Ordering::Relaxed), 0);
}
