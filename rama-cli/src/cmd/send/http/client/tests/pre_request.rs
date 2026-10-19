//! Explicit preliminary plans exercise the real HTTP client and output middleware.

use super::{new_hermetic, output_dir, send_cfg, spawn_origin};
use crate::cmd::send::http::{pre_request, request, run_inner};
use parking_lot::Mutex;
use rama::{
    Service,
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
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[tokio::test]
async fn explicit_plan_sends_own_body_order_and_auth_without_command_output() {
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
                    "discard-preliminary".repeat(4096)
                })))
            }
        }
    }))
    .await;
    let (directory, output) = output_dir();
    let first = directory.path().join("first.json");
    let second = directory.path().join("second.json");
    tokio::fs::write(
        &first,
        serde_json::to_vec(&serde_json::json!({
            "method":"POST", "uri":format!("http://{origin}/first"),
            "headers":[["x-order","first"],["x-order","second"],["authorization","explicit-row"]],
            "body_base64":"cHJlbGltaW5hcnk="
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    tokio::fs::write(
        &second,
        serde_json::to_vec(&serde_json::json!({
            "method":"GET", "uri":format!("http://{origin}/second")
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    let uri = format!("http://{origin}/main");
    let mut cfg = send_cfg(&[
        "--http1.1",
        "--user",
        "test:synthetic",
        "--header",
        "Cookie: main-private",
        "--data",
        "MAIN",
        "--output",
        &output,
        &uri,
    ]);
    cfg.pre_requests = vec![first, second];
    let requests = pre_request::load(&cfg).await.unwrap();
    let main = request::build(&cfg, false).await.unwrap();
    let client = new_hermetic(&cfg).await.unwrap();
    pre_request::run(&cfg, &client, requests).await.unwrap();
    assert!(tokio::fs::read(&output).await.unwrap().is_empty());
    client.serve(main).await.unwrap();
    assert_eq!(tokio::fs::read(&output).await.unwrap(), b"main-only");
    let seen = seen.lock();
    assert_eq!(seen.len(), 3);
    assert_eq!(
        seen.iter().map(|row| row.0.as_str()).collect::<Vec<_>>(),
        ["/first", "/second", "/main"]
    );
    assert_eq!(seen[0].1, Method::POST);
    assert_eq!(seen[0].2.as_ref().unwrap(), "explicit-row");
    assert!(seen[0].3.is_none());
    assert_eq!(
        seen[0]
            .4
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    assert_eq!(seen[0].5, b"preliminary".as_slice());
    assert_eq!(seen[1].1, Method::GET);
    assert!(seen[1].2.is_none());
    assert!(seen[1].3.is_none());
    assert!(seen[1].5.is_empty());
    assert_eq!(seen[2].2.as_ref().unwrap(), "Basic dGVzdDpzeW50aGV0aWM=");
    assert_eq!(seen[2].3.as_ref().unwrap(), "main-private");
    assert_eq!(seen[2].5, b"MAIN".as_slice());
}

#[tokio::test]
async fn preliminary_status_failure_stops_following_operations_only_with_fail() {
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
                            .body(Body::from("drain-response"))
                            .unwrap(),
                    )
                }
            }
        }))
        .await;
        let (directory, output) = output_dir();
        let mut files = Vec::new();
        for path in ["reject", "tail"] {
            let file = directory.path().join(format!("{path}.json"));
            tokio::fs::write(
                &file,
                serde_json::to_vec(&serde_json::json!({
                    "method":"GET", "uri":format!("http://{origin}/{path}")
                }))
                .unwrap(),
            )
            .await
            .unwrap();
            files.push(file);
        }
        let uri = format!("http://{origin}/main");
        let mut cfg = send_cfg(&["--http1.1", "--output", &output, &uri]);
        cfg.fail = fail;
        cfg.pre_requests = files;
        let requests = pre_request::load(&cfg).await.unwrap();
        let client = new_hermetic(&cfg).await.unwrap();
        let result = pre_request::run(&cfg, &client, requests).await;
        assert_eq!(result.is_err(), fail);
        if let Err(error) = result {
            assert!(error.to_string().contains("preliminary HTTP failure"));
            assert!(tokio::fs::read(&output).await.unwrap().is_empty());
        } else {
            client
                .serve(request::build(&cfg, false).await.unwrap())
                .await
                .unwrap();
        }
        assert_eq!(
            *seen.lock(),
            if fail {
                vec!["/reject"]
            } else {
                vec!["/reject", "/tail", "/main"]
            }
        );
    }
}

#[tokio::test]
async fn invalid_last_plan_prevents_all_actual_transport_io() {
    let hits = Arc::new(AtomicUsize::new(0));
    let origin = spawn_origin(service_fn({
        let hits = hits.clone();
        move |_: Request| {
            hits.fetch_add(1, Ordering::Relaxed);
            async { Ok::<_, Infallible>(Response::new(Body::empty())) }
        }
    }))
    .await;
    let (directory, output) = output_dir();
    let first = directory.path().join("first.json");
    let last = directory.path().join("invalid.json");
    tokio::fs::write(
        &first,
        serde_json::to_vec(&serde_json::json!({
            "method":"POST", "uri":format!("http://{origin}/must-not-run"), "body_base64":"eA=="
        }))
        .unwrap(),
    )
    .await
    .unwrap();
    tokio::fs::write(&last, b"{invalid}").await.unwrap();
    let uri = format!("http://{origin}/main");
    let proxy = format!("http://{origin}");
    let mut cfg = send_cfg(&[
        "--http1.1",
        "--max-time",
        "2",
        "--proxy",
        &proxy,
        "--output",
        &output,
        &uri,
    ]);
    cfg.pre_requests = vec![first, last];
    let error = run_inner(&cfg, false).await.unwrap_err();
    assert!(error.to_string().contains("parse preliminary request"));
    assert_eq!(hits.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn explicit_content_length_and_chunked_framing_reach_the_actual_wire() {
    for chunked in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                assert!(head.len() < 65536);
                let mut byte = [0];
                socket.read_exact(&mut byte).await.unwrap();
                head.push(byte[0]);
            }
            let head = String::from_utf8(head).unwrap();
            let lower = head.to_ascii_lowercase();
            assert!(head.starts_with("POST /pre HTTP/1.1\r\n"));
            let expected: &[u8] = if chunked {
                assert!(lower.contains("transfer-encoding: chunked\r\n"));
                assert!(!lower.contains("content-length:"));
                b"5\r\nhello\r\n0\r\n\r\n"
            } else {
                assert!(head.contains("CoNtEnT-LeNgTh: 5\r\n"));
                assert!(!lower.contains("transfer-encoding:"));
                b"hello"
            };
            let before = lower.find("x-before: one\r\n").unwrap();
            let framing = lower
                .find(if chunked {
                    "transfer-encoding:"
                } else {
                    "content-length:"
                })
                .unwrap();
            let after = lower.find("x-after: two\r\n").unwrap();
            assert!(before < framing && framing < after);
            let mut actual = vec![0; expected.len()];
            socket.read_exact(&mut actual).await.unwrap();
            assert_eq!(actual, expected);
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let (directory, output) = output_dir();
        let file = directory.path().join("explicit-framing.json");
        let framing = if chunked {
            ("Transfer-Encoding", "chunked")
        } else {
            ("CoNtEnT-LeNgTh", "5")
        };
        tokio::fs::write(
            &file,
            serde_json::to_vec(&serde_json::json!({
                "method":"POST", "uri":format!("http://{address}/pre"),
                "headers":[["x-before","one"],[framing.0,framing.1],["x-after","two"]],
                "body_base64":"aGVsbG8="
            }))
            .unwrap(),
        )
        .await
        .unwrap();
        let uri = format!("http://{address}/main");
        let mut cfg = send_cfg(&["--http1.1", "--output", &output, &uri]);
        cfg.pre_requests.push(file);
        let client = new_hermetic(&cfg).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            pre_request::run(&cfg, &client, pre_request::load(&cfg).await.unwrap())
                .await
                .unwrap();
            peer.await.unwrap();
        })
        .await
        .unwrap();
    }
}
