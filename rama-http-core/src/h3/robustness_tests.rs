//! Exercise admission recovery and independent streams across a real QUIC connection.

use super::{LIMIT, Pair};
use crate::h3::{
    Error, client,
    connection::{Config, Shared, initial_control},
    control::Role,
    qpack::{Encoder, EncoderConfig, ErrorScope},
    quic::Writer,
    server,
};
use rama_core::{
    bytes::{Bytes, BytesMut},
    futures::{FutureExt as _, stream},
    rt::{Executor, spawn},
};
use rama_http_types::{
    Body, HeaderMap, Method, Request, Response, StatusCode,
    body::{Frame, util::BodyExt},
    proto::h3::{Code, FrameHeader, FrameType, StreamType},
};
use rama_net::uri::Uri;
use rama_quic::TransportConfig;
use rama_quic_proto::{Dir, MAX_STREAM_COUNT, Side, StreamId, VarInt, coding::Codec};
use std::{
    convert::Infallible,
    error::Error as _,
    future::poll_fn,
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Poll,
};
use tokio::sync::{Barrier, oneshot};

#[tokio::test(start_paused = true)]
async fn memory_goaway_prevents_new_headers_when_stream_credit_arrives_concurrently() {
    // RFC 9114 section 5.2 permits a first GOAWAY at the maximum request ID.
    // That still prohibits new requests whose IDs would fall below this limit.
    const WAITERS: u32 = 32;
    tokio::time::timeout(LIMIT, async {
        let mut transport = TransportConfig::default();
        Config::default()
            .configure_transport(&mut transport)
            .unwrap();
        transport.set_max_concurrent_bidi_streams(0u32);
        let pair = Pair::in_memory(None, Some(transport)).await;
        let (mut client, driver) =
            client::handshake::<Body>(pair.client.clone(), Config::default(), Executor::new())
                .unwrap();
        let driver = spawn(driver.run());
        client.ready().await.unwrap();
        let mut requests = Vec::with_capacity(WAITERS as usize);
        for _ in 0..WAITERS {
            let mut sender = client.clone();
            let mut request = Box::pin(async move {
                sender
                    .send_request(
                        Request::builder()
                            .method(Method::POST)
                            .uri("https://localhost/stop-before-headers")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
            });
            assert!(poll_fn(|cx| Poll::Ready(request.as_mut().poll(cx).is_pending())).await);
            requests.push(request);
        }
        let mut control = pair.server.open_uni().await.unwrap();
        control
            .write_all(&initial_control(&Config::default()).unwrap())
            .await
            .unwrap();
        let limit = VarInt::from_u64(u64::from(StreamId::new(
            Side::Client,
            Dir::Bi,
            MAX_STREAM_COUNT - 1,
        )))
        .unwrap();
        let mut bytes = BytesMut::new();
        FrameHeader::new(FrameType::GOAWAY, limit.size() as u64)
            .encode(&mut bytes)
            .unwrap();
        limit.encode(&mut bytes);
        control.write_all(&bytes).await.unwrap();
        _ = client.closed_or_draining().await;

        // Make both cancellation and opening ready before repolling the pending
        // requests. The unused probe confirms receipt of the new MAX_STREAMS.
        pair.server.set_max_concurrent_bi_streams(WAITERS + 1);
        let _probe = pair.client.open_bi().await.unwrap();
        for mut request in requests {
            let result = poll_fn(|cx| Poll::Ready(request.as_mut().poll(cx))).await;
            let Poll::Ready(Err(error)) = result else {
                panic!(
                    "GOAWAY must reject before sending HEADERS, even with available stream credit"
                );
            };
            assert_eq!(error.code(), Code::H3_REQUEST_REJECTED);
        }
        pair.client.close(0u32, b"test complete");
        _ = driver.await.unwrap();
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn memory_goaway_releases_saturated_admission_and_preserves_active_response() {
    check_goaway_preserves_active_response(1).await;
}

#[tokio::test(start_paused = true)]
async fn memory_goaway_releases_stream_credit_waiter_and_preserves_active_response() {
    check_goaway_preserves_active_response(2).await;
}

async fn check_goaway_preserves_active_response(max_requests: usize) {
    // RFC 9114 section 5.2: stop opening requests after GOAWAY, while an
    // accepted request below its limit can still complete. Exercise the two
    // distinct waits before stream creation with the same one-stream peer.
    tokio::time::timeout(LIMIT, async {
        let mut transport = TransportConfig::default();
        Config::default()
            .configure_transport(&mut transport)
            .unwrap();
        transport.set_max_concurrent_bidi_streams(1u32);
        let pair = Pair::in_memory(None, Some(transport)).await;
        let (mut client, client_driver) = client::handshake::<Body>(
            pair.client.clone(),
            Config {
                max_requests,
                ..Config::default()
            },
            Executor::new(),
        )
        .unwrap();
        let (mut server, server_driver) =
            server::handshake(pair.server.clone(), Config::default()).unwrap();
        let client_driver = spawn(client_driver.run());
        let server_driver = spawn(server_driver.run());
        let accepted = spawn({
            let mut sender = client.clone();
            async move {
                sender
                    .send_request(
                        Request::builder()
                            .method(Method::POST)
                            .uri("https://localhost/accepted")
                            .body(Body::from("process once"))
                            .unwrap(),
                    )
                    .await
                    .unwrap()
            }
        });
        let (request, response) = server.accept().await.unwrap().resolve().await.unwrap();
        assert_eq!(request.method(), Method::POST);
        assert_eq!(
            request.into_body().collect().await.unwrap().to_bytes(),
            "process once"
        );
        let (release, wait) = oneshot::channel();
        let respond = spawn(async move {
            let body = Body::from_stream(stream::once(async move {
                wait.await.unwrap();
                Ok::<_, Infallible>(Bytes::from_static(b"completed after GOAWAY"))
            }));
            response.send_response(Response::new(body)).await.unwrap();
        });
        let active_response = accepted.await.unwrap();
        let body_polls = Arc::new(AtomicUsize::new(0));
        let request = || {
            let polls = body_polls.clone();
            Request::builder()
                .method(Method::POST)
                .uri("https://localhost/not-replayed")
                .body(Body::from_stream(stream::once(async move {
                    polls.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, Infallible>(Bytes::from_static(b"side effect"))
                })))
                .unwrap()
        };
        {
            let mut blocked = pin!(client.send_request(request()));
            assert!(poll_fn(|cx| Poll::Ready(blocked.as_mut().poll(cx).is_pending())).await);
            server.shutdown().unwrap();
            let error = blocked.await.unwrap_err();
            assert_eq!(error.code(), Code::H3_REQUEST_REJECTED);
            assert_eq!(error.scope(), ErrorScope::Stream);
        }
        assert!(client.is_draining());
        assert!(!client.is_closed());
        assert_eq!(
            client.send_request(request()).await.unwrap_err().code(),
            Code::H3_REQUEST_REJECTED
        );
        assert_eq!(body_polls.load(Ordering::SeqCst), 0);

        // Keep the active stream's credit held until both rejections arrive.
        release.send(()).unwrap();
        assert_eq!(
            active_response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes(),
            "completed after GOAWAY"
        );
        respond.await.unwrap();
        server.drained().await.unwrap();
        assert!(pair.server.accept_bi().now_or_never().is_none());
        assert_eq!(body_polls.load(Ordering::SeqCst), 0);
        assert!(pair.client.close_reason().is_none());
        pair.client.close(0u32, b"test complete");
        _ = client_driver.await.unwrap();
        _ = server_driver.await.unwrap();
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn malformed_control_streams_close_connection_and_wake_accept() {
    check_malformed_control_streams_close_connection_and_wake_accept(false).await;
}

#[tokio::test(start_paused = true)]
async fn memory_malformed_control_streams_close_connection_and_wake_accept() {
    check_malformed_control_streams_close_connection_and_wake_accept(true).await;
}

async fn check_malformed_control_streams_close_connection_and_wake_accept(in_memory: bool) {
    // RFC 9114 sections 6.2.1 and 7.2.4. Keep every sending stream open so
    // an unintended critical-stream FIN cannot mask the actual protocol error.
    let cases: &[(&str, &[&[u8]], Code)] = &[
        (
            "GOAWAY before SETTINGS",
            &[&[0, 7, 1, 0]],
            Code::H3_MISSING_SETTINGS,
        ),
        (
            "truncated setting integer",
            &[&[0, 4, 1, 0x40]],
            Code::H3_FRAME_ERROR,
        ),
        (
            "duplicate SETTINGS",
            &[&[0, 4, 0, 4, 0]],
            Code::H3_FRAME_UNEXPECTED,
        ),
        (
            "HTTP/2 reserved setting",
            &[&[0, 4, 2, 2, 0]],
            Code::H3_SETTINGS_ERROR,
        ),
        (
            "duplicate control stream",
            &[&[0, 4, 0], &[0, 4, 0]],
            Code::H3_STREAM_CREATION_ERROR,
        ),
    ];
    for &(scenario, streams, expected) in cases {
        tokio::time::timeout(LIMIT, async {
            let pair = pair(None, None, in_memory).await;
            let (mut server, driver) =
                server::handshake(pair.server.clone(), Config::default()).unwrap();
            let driver = spawn(driver.run());
            let accept = spawn(async move { server.accept().await.err().unwrap() });
            let mut retained = Vec::new();
            for &bytes in streams {
                let mut send = pair.client.open_uni().await.unwrap();
                send.write_all(bytes).await.unwrap();
                retained.push(send);
            }
            assert_eq!(
                driver.await.unwrap().unwrap_err().code(),
                expected,
                "{scenario}"
            );
            assert!(pair.server.close_reason().is_some(), "{scenario}");
            // The public accept API must not remain asleep after the driver fails.
            _ = accept.await.unwrap();
            pair.close().await;
        })
        .await
        .unwrap_or_else(|error| panic!("{scenario}: {error}"));
    }
}

#[tokio::test]
async fn malformed_request_streams_leave_connection_and_admission_usable() {
    check_malformed_request_streams_leave_connection_and_admission_usable(false).await;
}

#[tokio::test(start_paused = true)]
async fn memory_malformed_request_streams_leave_connection_and_admission_usable() {
    check_malformed_request_streams_leave_connection_and_admission_usable(true).await;
}

async fn check_malformed_request_streams_leave_connection_and_admission_usable(in_memory: bool) {
    tokio::time::timeout(LIMIT, async {
        let pair = pair(None, None, in_memory).await;
        let config = Config {
            max_requests: 1,
            ..Config::default()
        };
        let (mut client, client_driver) =
            client::handshake::<Body>(pair.client.clone(), config.clone(), Executor::new())
                .unwrap();
        let (mut server, server_driver) = server::handshake(pair.server.clone(), config).unwrap();
        let client_driver = spawn(client_driver.run());
        let server_driver = spawn(server_driver.run());
        let mut encoder = Encoder::before_peer_settings(EncoderConfig::default());
        // RFC 9114 sections 4.1.2, 4.2 and 4.3: malformed HTTP messages
        // invalidate their own stream, not unrelated requests on the connection.
        let malformed: &[(&[u8], &[u8])] = &[
            (b"Uppercase", b"value"),
            (b"connection", b"close"),
            (b":method", b"GET"),
            (b"content-length", b"not-a-number"),
            (b"x-whitespace", b" leading-space"),
        ];
        for &(name, value) in malformed {
            let (send, mut recv) = pair.client.open_bi().await.unwrap();
            let id = u64::from(send.id());
            let fields = [
                (b":method".as_slice(), b"GET".as_slice()),
                (b":scheme".as_slice(), b"https".as_slice()),
                (b":authority".as_slice(), b"localhost".as_slice()),
                (b":path".as_slice(), b"/".as_slice()),
                (name, value),
            ];
            let mut writer = Writer::new(send);
            writer
                .queue(FrameType::HEADERS, encoder.encode(id, fields).unwrap())
                .unwrap();
            std::future::poll_fn(|cx| writer.poll_finish(cx))
                .await
                .unwrap();
            let error = server
                .accept()
                .await
                .unwrap()
                .resolve()
                .await
                .err()
                .unwrap();
            assert_eq!(error.code(), Code::H3_MESSAGE_ERROR, "field {name:?}");
            assert_eq!(error.scope(), ErrorScope::Stream);
            assert!(pair.server.close_reason().is_none());
            let error = recv.read_chunk(1024, true).await.unwrap_err();
            assert!(matches!(error, rama_quic::ReadError::Reset(code)
                if code.into_inner() == Code::H3_MESSAGE_ERROR.value()));
        }
        let serve = spawn(async move {
            let (request, response) = server.accept().await.unwrap().resolve().await.unwrap();
            request.into_body().collect().await.unwrap();
            response
                .send_response(Response::new(Body::from("still usable")))
                .await
                .unwrap();
        });
        let response = client
            .send_request(
                Request::builder()
                    .uri("https://localhost/valid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "still usable"
        );
        serve.await.unwrap();
        pair.client.close(0u32, b"test complete");
        _ = client_driver.await.unwrap();
        _ = server_driver.await.unwrap();
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_idle_response_releases_single_admission_slot() {
    check_cancelled_idle_response_releases_single_admission_slot(false).await;
}

#[tokio::test(start_paused = true)]
async fn memory_cancelled_idle_response_releases_single_admission_slot() {
    check_cancelled_idle_response_releases_single_admission_slot(true).await;
}

async fn check_cancelled_idle_response_releases_single_admission_slot(in_memory: bool) {
    tokio::time::timeout(LIMIT, async {
        let pair = pair(None, None, in_memory).await;
        let config = Config {
            max_requests: 1,
            ..Config::default()
        };
        let (mut client, client_driver) =
            client::handshake::<Body>(pair.client.clone(), config.clone(), Executor::new())
                .unwrap();
        let (mut server, server_driver) = server::handshake(pair.server.clone(), config).unwrap();
        let client_driver = spawn(client_driver.run());
        let server_driver = spawn(server_driver.run());
        let serve = spawn(async move {
            // Repeated cancellation must release both sides' sole admission permit.
            for _ in 0..16 {
                let (request, response) = server.accept().await.unwrap().resolve().await.unwrap();
                request.into_body().collect().await.unwrap();
                let body = Body::from_stream(rama_core::futures::stream::pending::<
                    Result<Bytes, Infallible>,
                >());
                let error = response
                    .send_response(Response::new(body))
                    .await
                    .unwrap_err();
                assert_eq!(error.code(), Code::H3_REQUEST_CANCELLED);
            }
            let (request, response) = server.accept().await.unwrap().resolve().await.unwrap();
            request.into_body().collect().await.unwrap();
            response
                .send_response(Response::new(Body::from("recovered")))
                .await
                .unwrap();
        });
        for _ in 0..16 {
            let response = client
                .send_request(
                    Request::builder()
                        .uri("https://localhost/cancel")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            drop(response);
        }
        let response = client
            .send_request(
                Request::builder()
                    .uri("https://localhost/recovered")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "recovered"
        );
        serve.await.unwrap();
        assert!(pair.client.close_reason().is_none());
        pair.client.close(0u32, b"test complete");
        _ = client_driver.await.unwrap();
        _ = server_driver.await.unwrap();
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn concurrent_stream_waves_recover_admission_and_flow_control_credit() {
    check_concurrent_stream_waves_recover_admission_and_flow_control_credit(false).await;
}

#[tokio::test(start_paused = true)]
async fn memory_concurrent_stream_waves_recover_admission_and_flow_control_credit() {
    check_concurrent_stream_waves_recover_admission_and_flow_control_credit(true).await;
}

async fn check_concurrent_stream_waves_recover_admission_and_flow_control_credit(in_memory: bool) {
    const CONCURRENT: usize = 8;
    const WAVES: usize = 16;
    tokio::time::timeout(LIMIT, async {
        let config = Config {
            max_requests: CONCURRENT,
            ..Config::default()
        };
        let transport = || {
            let mut transport = rama_quic::TransportConfig::default();
            config.configure_transport(&mut transport).unwrap();
            // Every body exceeds both stream and connection receive windows.
            transport.set_stream_receive_window(rama_utils::octets::kib(1) as u32);
            transport.set_receive_window(rama_utils::octets::kib(4) as u32);
            transport
        };
        let pair = pair(Some(transport()), Some(transport()), in_memory).await;
        let (client, client_driver) =
            client::handshake::<Body>(pair.client.clone(), config.clone(), Executor::new())
                .unwrap();
        let (mut server, server_driver) = server::handshake(pair.server.clone(), config).unwrap();
        let client_driver = spawn(client_driver.run());
        let server_driver = spawn(server_driver.run());
        let serve = spawn(async move {
            for _ in 0..WAVES {
                let mut responses = tokio::task::JoinSet::new();
                for _ in 0..CONCURRENT {
                    let stream = server.accept().await.unwrap();
                    responses.spawn(async move {
                        let (request, response) = stream.resolve().await.unwrap();
                        let body = request.into_body().collect().await.unwrap().to_bytes();
                        response
                            .send_response(Response::new(Body::from(body)))
                            .await
                            .unwrap();
                    });
                }
                while let Some(result) = responses.join_next().await {
                    result.unwrap();
                }
            }
        });
        for wave in 0..WAVES {
            let barrier = Arc::new(Barrier::new(CONCURRENT));
            let mut requests = tokio::task::JoinSet::new();
            for stream in 0..CONCURRENT {
                let mut client = client.clone();
                let barrier = barrier.clone();
                requests.spawn(async move {
                    barrier.wait().await;
                    let payload = Bytes::from(vec![
                        (wave * CONCURRENT + stream) as u8;
                        rama_utils::octets::kib(8)
                    ]);
                    let response = client
                        .send_request(
                            Request::builder()
                                .method(Method::POST)
                                .uri("https://localhost/echo")
                                .body(Body::from(payload.clone()))
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        response.into_body().collect().await.unwrap().to_bytes(),
                        payload
                    );
                });
            }
            while let Some(result) = requests.join_next().await {
                result.unwrap();
            }
        }
        serve.await.unwrap();
        assert!(pair.client.close_reason().is_none());
        pair.client.close(0u32, b"test complete");
        _ = client_driver.await.unwrap();
        _ = server_driver.await.unwrap();
        pair.close().await;
    })
    .await
    .unwrap();
}

async fn pair(
    client: Option<rama_quic::TransportConfig>,
    server: Option<rama_quic::TransportConfig>,
    in_memory: bool,
) -> Pair {
    if in_memory {
        Pair::in_memory(client, server).await
    } else {
        Pair::new(client, server).await
    }
}

#[tokio::test(start_paused = true)]
async fn memory_reset_before_headers_does_not_fragment_priority_history() {
    const REQUESTS: usize = 300;
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (mut client, client_driver) =
            client::handshake::<Body>(pair.client.clone(), Config::default(), Executor::new())
                .unwrap();
        let (mut server, server_driver) =
            server::handshake(pair.server.clone(), Config::default()).unwrap();
        let client_driver = spawn(client_driver.run());
        let server_driver = spawn(server_driver.run());
        let serve = spawn(async move {
            for _ in 0..REQUESTS {
                let error = server
                    .accept()
                    .await
                    .unwrap()
                    .resolve()
                    .await
                    .err()
                    .unwrap();
                assert_eq!(error.scope(), ErrorScope::Stream);
                let (request, response) = server.accept().await.unwrap().resolve().await.unwrap();
                request.into_body().collect().await.unwrap();
                response
                    .send_response(Response::new(Body::from("ok")))
                    .await
                    .unwrap();
            }
        });
        for _ in 0..REQUESTS {
            let (mut send, mut recv) = pair.client.open_bi().await.unwrap();
            // A partial HEADERS frame followed by reset must release admission,
            // scheduling and compression bookkeeping just like a valid request.
            send.write_all(&[1]).await.unwrap();
            send.reset(Code::H3_REQUEST_CANCELLED.value() as u32)
                .unwrap();
            recv.stop(Code::H3_REQUEST_CANCELLED.value() as u32)
                .unwrap();
            let response = client
                .send_request(
                    Request::builder()
                        .uri("https://localhost/survivor")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                "ok"
            );
            assert!(pair.client.close_reason().is_none());
        }
        serve.await.unwrap();
        pair.client
            .close(Code::H3_NO_ERROR.value() as u32, b"complete");
        client_driver.await.unwrap().unwrap();
        server_driver.await.unwrap().unwrap();
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn memory_clean_close_preserves_buffered_response_and_trailers() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (mut client, driver) =
            client::handshake::<Body>(pair.client.clone(), Config::default(), Executor::new())
                .unwrap();
        let driver = spawn(driver.run());
        client.ready().await.unwrap();
        let mut response = pin!(
            client.send_request(
                Request::builder()
                    .uri("https://localhost/buffered")
                    .body(Body::empty())
                    .unwrap(),
            )
        );
        assert!(poll_fn(|cx| Poll::Ready(response.as_mut().poll(cx).is_pending())).await);
        let (mut send, mut recv) = pair.server.accept_bi().await.unwrap();
        recv.read_to_end(4096).await.unwrap();
        let mut encoder = Encoder::new(EncoderConfig {
            max_table_capacity: 0,
            ..EncoderConfig::default()
        });
        let mut bytes = BytesMut::new();
        for (ty, payload) in [
            (
                FrameType::HEADERS,
                encoder
                    .encode(0, [(":status", "200"), ("content-length", "4")])
                    .unwrap(),
            ),
            (FrameType::DATA, Bytes::from_static(b"done")),
            (
                FrameType::HEADERS,
                encoder.encode(0, [("x-end", "yes")]).unwrap(),
            ),
        ] {
            FrameHeader::new(ty, payload.len() as u64)
                .encode(&mut bytes)
                .unwrap();
            bytes.extend_from_slice(&payload);
        }
        send.write_all(&bytes).await.unwrap();
        send.finish().unwrap();
        // ACK confirms the complete response and FIN reached the peer before close.
        assert_eq!(send.stopped().await.unwrap(), None);
        pair.server
            .close(Code::H3_NO_ERROR.value() as u32, b"complete");
        driver.await.unwrap().unwrap();
        let response = response.await.unwrap();
        let body = response.into_body().collect().await.unwrap();
        assert_eq!(body.trailers().unwrap()["x-end"], "yes");
        assert_eq!(body.to_bytes(), "done");
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn memory_closed_connection_preserves_only_complete_successful_responses() {
    tokio::time::timeout(LIMIT, async {
        // All cases expose the headers before close, leaving the body buffered.
        for (finish, declared_length, close_code, abort_driver) in [
            (true, "4", Code::H3_NO_ERROR, false),
            (false, "4", Code::H3_NO_ERROR, false),
            (true, "5", Code::H3_NO_ERROR, false),
            (true, "4", Code::H3_GENERAL_PROTOCOL_ERROR, false),
            (true, "4", Code::H3_NO_ERROR, true),
        ] {
            let pair = Pair::in_memory(None, None).await;
            let (mut client, driver) =
                client::handshake::<Body>(pair.client.clone(), Config::default(), Executor::new())
                    .unwrap();
            let driver = spawn(driver.run());
            client.ready().await.unwrap();
            let response = spawn(async move {
                client
                    .send_request(
                        Request::builder()
                            .uri("https://localhost/incomplete")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap()
            });
            let (mut send, mut recv) = pair.server.accept_bi().await.unwrap();
            recv.read_to_end(4096).await.unwrap();
            let mut encoder = Encoder::new(EncoderConfig {
                max_table_capacity: 0,
                ..EncoderConfig::default()
            });
            let headers = encoder
                .encode(0, [(":status", "200"), ("content-length", declared_length)])
                .unwrap();
            let mut bytes = BytesMut::new();
            FrameHeader::new(FrameType::HEADERS, headers.len() as u64)
                .encode(&mut bytes)
                .unwrap();
            bytes.extend_from_slice(&headers);
            FrameHeader::new(FrameType::DATA, 4)
                .encode(&mut bytes)
                .unwrap();
            bytes.extend_from_slice(b"done");
            send.write_all(&bytes).await.unwrap();
            if finish {
                send.finish().unwrap();
                assert_eq!(send.stopped().await.unwrap(), None);
            }
            let response = response.await.unwrap();
            if abort_driver {
                driver.abort();
                assert!(driver.await.unwrap_err().is_cancelled());
            } else {
                pair.server.close(close_code.value() as u32, b"test close");
                let result = driver.await.unwrap();
                assert_eq!(result.is_ok(), close_code == Code::H3_NO_ERROR);
            }
            assert_eq!(
                response.into_body().collect().await.is_ok(),
                finish
                    && declared_length == "4"
                    && close_code == Code::H3_NO_ERROR
                    && !abort_driver
            );
            pair.close().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn clean_close_decodes_available_qpack_without_waiting_for_missing_inserts() {
    tokio::time::timeout(LIMIT, async {
        let mut config = Config::default();
        config.decoder.max_decoder_stream_bytes = 10;
        let shared = Shared::new(config, Role::Client, Default::default()).unwrap();
        let mut encoder = Encoder::new(EncoderConfig::default());
        let bytes = encoder.encode(0, [("x-dynamic", "present")]).unwrap();
        assert!(
            !shared
                .feed_instructions(StreamType::QPACK_ENCODER, &encoder.take_encoder_stream())
                .unwrap()
        );
        shared.fail(Error::connection(Code::H3_NO_ERROR, "complete"));
        // Feedback is impossible after close, but known entries remain usable.
        for id in (0..400).step_by(4) {
            let fields = shared.decode(id, bytes.clone()).await.unwrap();
            assert_eq!(fields[0].value, "present");
        }
        let missing = encoder
            .encode(400, [("x-dynamic", "not received")])
            .unwrap();
        assert_eq!(
            shared.decode(400, missing).await.unwrap_err().code(),
            Code::H3_NO_ERROR
        );
        // A protocol error discovered during draining must still poison other readers.
        shared.fail(Error::connection(
            Code::H3_FRAME_UNEXPECTED,
            "malformed buffered frame",
        ));
        assert_eq!(
            shared.receive_error().unwrap().code(),
            Code::H3_FRAME_UNEXPECTED
        );
        assert_eq!(
            shared.decode(404, bytes).await.unwrap_err().code(),
            Code::H3_FRAME_UNEXPECTED
        );
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn memory_clean_peer_close_has_one_driver_result() {
    tokio::time::timeout(LIMIT, async {
        for _ in 0..32 {
            let pair = Pair::in_memory(None, None).await;
            let (mut client, driver) =
                client::handshake::<Body>(pair.client.clone(), Config::default(), Executor::new())
                    .unwrap();
            let (server, server_driver) =
                server::handshake(pair.server.clone(), Config::default()).unwrap();
            let driver = spawn(driver.run());
            let server_driver = spawn(server_driver.run());
            client.ready().await.unwrap();
            pair.server
                .close(Code::H3_NO_ERROR.value() as u32, b"graceful peer close");
            driver.await.unwrap().unwrap();
            server_driver.await.unwrap().unwrap();
            drop(server);
            pair.close().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn memory_drained_server_driver_drop_sends_no_error() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (mut client, driver) =
            client::handshake::<Body>(pair.client.clone(), Config::default(), Executor::new())
                .unwrap();
        let (mut server, server_driver) =
            server::handshake(pair.server.clone(), Config::default()).unwrap();
        let driver = spawn(driver.run());
        let server_driver = spawn(server_driver.run());
        client.ready().await.unwrap();
        server.shutdown().unwrap();
        server.drained().await.unwrap();
        server_driver.abort();
        assert!(server_driver.await.unwrap_err().is_cancelled());
        let reason = pair.client.closed().await;
        let rama_quic::ConnectionError::ApplicationClosed(close) = reason else {
            panic!("expected HTTP/3 application close: {reason:?}");
        };
        assert_eq!(close.error_code.into_inner(), Code::H3_NO_ERROR.value());
        driver.await.unwrap().unwrap();
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn memory_oversized_outgoing_trailers_preserve_connection() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let mut config = Config::default();
        config.decoder.max_field_section_size = 256;
        config.max_pushes = 1;
        let (mut client, client_driver) =
            client::handshake::<Body>(pair.client.clone(), config, Executor::new()).unwrap();
        let (mut server, server_driver) = server::handshake(
            pair.server.clone(),
            Config {
                max_pushes: 1,
                ..Config::default()
            },
        )
        .unwrap();
        let client_driver = spawn(client_driver.run());
        let server_driver = spawn(server_driver.run());
        let serve = spawn(async move {
            let (request, response) = server.accept().await.unwrap().resolve().await.unwrap();
            request.into_body().collect().await.unwrap();
            // MAX_PUSH_ID follows SETTINGS on the control stream, providing a
            // wire-level barrier before we exercise the advertised field limit.
            response.ready_for_push().await.unwrap();
            let mut trailers = HeaderMap::new();
            trailers.insert("x-too-large", "a".repeat(256).parse().unwrap());
            let body = Body::from_frame_stream(stream::iter([
                Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"prefix"))),
                Ok(Frame::trailers(trailers)),
            ]));
            let error = response
                .send_response(Response::new(body))
                .await
                .unwrap_err();
            assert_eq!(error.scope(), ErrorScope::Stream);
            assert_eq!(error.code(), Code::H3_MESSAGE_ERROR);
            let (request, response) = server.accept().await.unwrap().resolve().await.unwrap();
            request.into_body().collect().await.unwrap();
            response
                .send_response(Response::new(Body::from("survived")))
                .await
                .unwrap();
        });
        let request = || {
            Request::builder()
                .uri("https://localhost/")
                .body(Body::empty())
                .unwrap()
        };
        match client.send_request(request()).await {
            Ok(response) => {
                let error = response.into_body().collect().await.unwrap_err();
                let error = error.source().unwrap().downcast_ref::<Error>().unwrap();
                assert_eq!(error.code(), Code::H3_MESSAGE_ERROR);
            }
            Err(error) => {
                assert_eq!(error.scope(), ErrorScope::Stream);
                assert_eq!(error.code(), Code::H3_MESSAGE_ERROR);
            }
        }
        assert!(pair.client.close_reason().is_none());
        let response = client.send_request(request()).await.unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "survived"
        );
        serve.await.unwrap();
        pair.client
            .close(Code::H3_NO_ERROR.value() as u32, b"complete");
        client_driver.await.unwrap().unwrap();
        server_driver.await.unwrap().unwrap();
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn memory_unread_request_body_is_stopped_without_error() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (_client, client_driver) =
            client::handshake::<Body>(pair.client.clone(), Config::default(), Executor::new())
                .unwrap();
        let (mut server, server_driver) =
            server::handshake(pair.server.clone(), Config::default()).unwrap();
        let client_driver = spawn(client_driver.run());
        let server_driver = spawn(server_driver.run());
        let (send, mut recv) = pair.client.open_bi().await.unwrap();
        let stopped = send.stopped();
        let mut writer = Writer::new(send);
        let mut encoder = Encoder::before_peer_settings(EncoderConfig::default());
        let fields = encoder
            .encode(
                0,
                [
                    (":method", "POST"),
                    (":scheme", "https"),
                    (":authority", "localhost"),
                    (":path", "/"),
                    ("content-length", "100"),
                ],
            )
            .unwrap();
        writer.queue(FrameType::HEADERS, fields).unwrap();
        poll_fn(|cx| writer.poll_flush(cx)).await.unwrap();
        let (request, response) = server.accept().await.unwrap().resolve().await.unwrap();
        response
            .send_response(Response::new(Body::from("done")))
            .await
            .unwrap();
        drop(request);
        assert_eq!(
            stopped.await.unwrap().unwrap().into_inner(),
            Code::H3_NO_ERROR.value()
        );
        recv.read_to_end(1024).await.unwrap();
        assert!(pair.client.close_reason().is_none());
        pair.client
            .close(Code::H3_NO_ERROR.value() as u32, b"complete");
        client_driver.await.unwrap().unwrap();
        server_driver.await.unwrap().unwrap();
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn memory_malformed_request_body_and_trailers_abort_both_directions() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (_client, client_driver) = client::handshake::<Body>(
            pair.client.clone(), Config::default(), Executor::new()).unwrap();
        let (mut server, server_driver) = server::handshake(
            pair.server.clone(), Config::default()).unwrap();
        let client_driver = spawn(client_driver.run());
        let server_driver = spawn(server_driver.run());
        let mut encoder = Encoder::before_peer_settings(EncoderConfig::default());
        for malformed_trailers in [false, true] {
            let (send, mut recv) = pair.client.open_bi().await.unwrap();
            let id = u64::from(send.id());
            let stopped = send.stopped();
            let mut writer = Writer::new(send);
            let fields = encoder.encode(id, [
                (":method", "POST"), (":scheme", "https"), (":authority", "localhost"),
                (":path", "/"), ("content-length", "1"),
            ]).unwrap();
            writer.queue(FrameType::HEADERS, fields).unwrap();
            poll_fn(|cx| writer.poll_flush(cx)).await.unwrap();
            if malformed_trailers {
                let trailers = encoder.encode(id, [(":status", "200")]).unwrap();
                writer.queue(FrameType::HEADERS, trailers).unwrap();
            } else {
                writer.queue(FrameType::DATA, Bytes::from_static(b"too long")).unwrap();
            }
            poll_fn(|cx| writer.poll_flush(cx)).await.unwrap();
            let (request, response) = server.accept().await.unwrap().resolve().await.unwrap();
            request.into_body().collect().await.unwrap_err();
            assert_eq!(stopped.await.unwrap().unwrap().into_inner(), Code::H3_MESSAGE_ERROR.value());
            assert!(matches!(recv.read_chunk(1024, true).await.unwrap_err(),
                rama_quic::ReadError::Reset(code) if code.into_inner() == Code::H3_MESSAGE_ERROR.value()));
            // The send direction is reset immediately, even while its application
            // response handle remains alive in another task.
            drop(response);
            assert!(pair.client.close_reason().is_none());
        }
        pair.client.close(Code::H3_NO_ERROR.value() as u32, b"complete");
        client_driver.await.unwrap().unwrap();
        server_driver.await.unwrap().unwrap();
        pair.close().await;
    }).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn memory_rejected_connect_retains_response_and_stops_without_error() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (mut client, client_driver) =
            client::handshake::<Body>(pair.client.clone(), Config::default(), Executor::new())
                .unwrap();
        let (mut server, server_driver) =
            server::handshake(pair.server.clone(), Config::default()).unwrap();
        let client_driver = spawn(client_driver.run());
        let server_driver = spawn(server_driver.run());
        let (send, mut recv) = pair.client.open_bi().await.unwrap();
        let stopped = send.stopped();
        let mut writer = Writer::new(send);
        let mut encoder = Encoder::before_peer_settings(EncoderConfig::default());
        writer
            .queue(
                FrameType::HEADERS,
                encoder
                    .encode(0, [(":method", "CONNECT"), (":authority", "localhost:443")])
                    .unwrap(),
            )
            .unwrap();
        poll_fn(|cx| writer.poll_flush(cx)).await.unwrap();
        let (_request, response) = server.accept().await.unwrap().resolve().await.unwrap();
        response
            .send_response(
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::from("denied"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            stopped.await.unwrap().unwrap().into_inner(),
            Code::H3_NO_ERROR.value()
        );
        recv.read_to_end(1024).await.unwrap();
        let serve = spawn(async move {
            let (_request, response) = server.accept().await.unwrap().resolve().await.unwrap();
            response
                .send_response(
                    Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Body::from("denied"))
                        .unwrap(),
                )
                .await
                .unwrap();
        });
        let response = client
            .send_request(
                Request::builder()
                    .method(Method::CONNECT)
                    .uri(Uri::parse_http_request_target("localhost:443", true).unwrap())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "denied"
        );
        serve.await.unwrap();
        assert!(pair.client.close_reason().is_none());
        pair.client
            .close(Code::H3_NO_ERROR.value() as u32, b"complete");
        client_driver.await.unwrap().unwrap();
        server_driver.await.unwrap().unwrap();
        pair.close().await;
    })
    .await
    .unwrap();
}
