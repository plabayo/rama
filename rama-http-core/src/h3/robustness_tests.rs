//! Exercise admission recovery and independent streams across a real QUIC connection.

use super::{LIMIT, Pair};
use crate::h3::{
    client,
    connection::Config,
    qpack::{Encoder, EncoderConfig, ErrorScope},
    quic::Writer,
    server,
};
use rama_core::{
    bytes::Bytes,
    rt::{Executor, spawn},
};
use rama_http_types::{
    Body, Method, Request, Response,
    body::util::BodyExt,
    proto::h3::{Code, FrameType},
};
use std::{convert::Infallible, sync::Arc};
use tokio::sync::Barrier;

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
            let (send, recv) = pair.client.open_bi().await.unwrap();
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
            drop(recv);
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
