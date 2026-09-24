//! Closing QUIC must not discard already received HTTP/3 control and QPACK state.

use super::{LIMIT, Pair};
use crate::h3::{
    Error, client,
    connection::{Config, Driver, Shared, initial_control},
    control::Role,
    qpack::{Encoder, EncoderConfig, ErrorScope},
};
use rama_core::{
    bytes::{Bytes, BytesMut},
    error::{BoxError, BoxErrorExt as _, error_chain},
    futures::stream,
    rt::{Executor, spawn},
};
use rama_http_types::{
    Body, Method, Request,
    body::util::BodyExt as _,
    proto::h3::{Code, FrameHeader, FrameType, StreamType},
};
use rama_net::uri::Uri;
use rama_quic_proto::{MAX_STREAM_COUNT, VarInt, coding::Codec};
use std::{convert::Infallible, future::poll_fn, pin::pin, task::Poll};
use tokio::sync::oneshot;

#[tokio::test(start_paused = true)]
async fn memory_clean_close_drains_accepted_control_frames_before_terminal_notification() {
    for malformed in [false, true] {
        tokio::time::timeout(LIMIT, async {
            let pair = Pair::in_memory(None, None).await;
            let shared =
                Shared::from_connection(Config::default(), Role::Client, &pair.client).unwrap();
            let mut driver =
                pin!(Driver::new(pair.client.clone(), shared.clone(), Role::Client).run());
            assert!(poll_fn(|cx| Poll::Ready(driver.as_mut().poll(cx).is_pending())).await);

            let mut control = pair.server.open_uni().await.unwrap();
            let mut bytes = BytesMut::from(initial_control(&Config::default()).unwrap().as_ref());
            let first = VarInt::from_u64((MAX_STREAM_COUNT - 1) * 4).unwrap();
            FrameHeader::new(FrameType::GOAWAY, first.size() as u64)
                .encode(&mut bytes)
                .unwrap();
            first.encode(&mut bytes);
            control.write_all(&bytes).await.unwrap();
            // This barrier proves the driver accepted this control stream and owns
            // its parser before it is paused. A new accept cannot recreate it.
            poll_fn(|cx| {
                assert!(driver.as_mut().poll(cx).is_pending());
                if shared.goaway() == Some(first.into_inner()) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;

            bytes.clear();
            for _ in 0..128 {
                FrameHeader::new(FrameType::new(0x21), 0)
                    .encode(&mut bytes)
                    .unwrap();
            }
            if malformed {
                FrameHeader::new(FrameType::DATA, 0)
                    .encode(&mut bytes)
                    .unwrap();
            } else {
                FrameHeader::new(FrameType::GOAWAY, 1)
                    .encode(&mut bytes)
                    .unwrap();
                VarInt::from_u32(0).encode(&mut bytes);
            }
            control.write_all(&bytes).await.unwrap();
            control.finish().unwrap();
            assert_eq!(control.stopped().await.unwrap(), None);
            // Leave a partially consumed chunk behind a cooperative yield.
            assert!(poll_fn(|cx| Poll::Ready(driver.as_mut().poll(cx).is_pending())).await);
            pair.server
                .close(Code::H3_NO_ERROR.value() as u32, b"complete");
            pair.client.closed().await;
            let result = driver.await;
            if malformed {
                let error = result.unwrap_err();
                assert_eq!(error.code(), Code::H3_FRAME_UNEXPECTED);
                assert!(error.is_remote_failure());
            } else {
                result.unwrap();
                assert_eq!(shared.goaway(), Some(0));
                assert!(shared.rejected(Some(0)).await.is_rejected());
            }
            pair.close().await;
        })
        .await
        .unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn memory_clean_close_drains_qpack_before_failing_missing_insert_waiters() {
    tokio::time::timeout(LIMIT, async {
        const READY: usize = 80;
        let pair = Pair::in_memory(None, None).await;
        let mut config = Config::default();
        config.decoder.max_decoder_stream_bytes = 10;
        config.decoder.max_blocked_streams = READY as u64 + 1;
        let shared = Shared::from_connection(config, Role::Client, &pair.client).unwrap();
        let mut driver = pin!(Driver::new(pair.client.clone(), shared.clone(), Role::Client).run());
        assert!(poll_fn(|cx| Poll::Ready(driver.as_mut().poll(cx).is_pending())).await);
        let mut encoder = Encoder::new(EncoderConfig::default());
        let fields = encoder.encode(0, [("x-buffered", "ready")]).unwrap();
        let instructions = encoder.take_encoder_stream();
        let missing = encoder
            .encode((READY * 4) as u64, [("x-buffered", "missing")])
            .unwrap();
        assert!(!encoder.take_encoder_stream().is_empty());
        let mut waiting = Vec::with_capacity(READY);
        for index in 0..READY {
            let mut decode = Box::pin(shared.decode((index * 4) as u64, fields.clone()));
            assert!(poll_fn(|cx| Poll::Ready(decode.as_mut().poll(cx).is_pending())).await);
            waiting.push(decode);
        }
        let missing_after_close = missing.clone();
        let mut missing = pin!(shared.decode((READY * 4) as u64, missing));
        assert!(poll_fn(|cx| Poll::Ready(missing.as_mut().poll(cx).is_pending())).await);

        let mut stream = pair.server.open_uni().await.unwrap();
        let mut bytes = BytesMut::new();
        VarInt::from_u64(StreamType::QPACK_ENCODER.value())
            .unwrap()
            .encode(&mut bytes);
        // End inside the first encoder instruction. The accepted future must
        // retain its decoder state while the remaining bytes arrive with close.
        bytes.extend_from_slice(&instructions[..1]);
        stream.write_all(&bytes).await.unwrap();
        assert!(poll_fn(|cx| Poll::Ready(driver.as_mut().poll(cx).is_pending())).await);
        stream.write_all(&instructions[1..]).await.unwrap();
        stream.finish().unwrap();
        assert_eq!(stream.stopped().await.unwrap(), None);
        pair.server
            .close(Code::H3_NO_ERROR.value() as u32, b"complete");
        pair.client.closed().await;
        driver.await.unwrap();
        for decode in waiting {
            let fields = decode.await.unwrap();
            assert_eq!(fields[0].value, "ready");
        }
        let error = missing.await.unwrap_err();
        assert_eq!(error.code(), Code::H3_REQUEST_INCOMPLETE);
        assert_eq!(error.scope(), ErrorScope::Stream);
        assert!(error.is_remote_failure());
        let error = shared
            .decode(((READY + 1) * 4) as u64, missing_after_close)
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::H3_REQUEST_INCOMPLETE);
        assert!(error.is_remote_failure());
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn memory_unknown_connection_codes_are_clean_and_keep_raw_diagnostics() {
    tokio::time::timeout(LIMIT, async {
        for code in [0, 0x21, 0x40, 0xdead] {
            let pair = Pair::in_memory(None, None).await;
            let shared =
                Shared::from_connection(Config::default(), Role::Client, &pair.client).unwrap();
            let mut driver =
                pin!(Driver::new(pair.client.clone(), shared.clone(), Role::Client).run());
            assert!(poll_fn(|cx| Poll::Ready(driver.as_mut().poll(cx).is_pending())).await);
            pair.server
                .close(VarInt::from_u32(code), b"extension close code");
            pair.client.closed().await;
            driver.await.unwrap();
            let error = shared.error().unwrap();
            assert_eq!(error.code(), Code::H3_NO_ERROR);
            assert_eq!(error.raw_code().value(), u64::from(code));
            assert!(!error.is_remote_failure());
            assert!(!error.is_rejected());
            pair.close().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn memory_response_close_waits_for_buffered_goaway_before_classifying_rejection() {
    for method in [Method::GET, Method::POST, Method::CONNECT] {
        tokio::time::timeout(LIMIT, async {
            let pair = Pair::in_memory(None, None).await;
            let (mut client, driver) =
                client::handshake::<Body>(pair.client.clone(), Config::default(), Executor::new())
                    .unwrap();
            let mut driver = pin!(driver.run());
            assert!(poll_fn(|cx| Poll::Ready(driver.as_mut().poll(cx).is_pending())).await);
            let uri = if method == Method::CONNECT {
                Uri::parse_http_request_target("localhost:443", true).unwrap()
            } else {
                Uri::try_from("https://localhost/rejected").unwrap()
            };
            let (body, upload_dropped) = if method == Method::POST {
                let (guard, dropped) = oneshot::channel::<()>();
                let body = Body::from_stream(stream::once(async move {
                    let _guard = guard;
                    std::future::pending::<Result<Bytes, Infallible>>().await
                }));
                (body, Some(dropped))
            } else {
                (Body::empty(), None)
            };
            let mut response = pin!(
                client.send_request(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .body(body)
                        .unwrap()
                )
            );
            assert!(poll_fn(|cx| Poll::Ready(response.as_mut().poll(cx).is_pending())).await);
            let (_send, mut recv) = pair.server.accept_bi().await.unwrap();
            recv.read_chunk(4096, true).await.unwrap();
            let mut control = pair.server.open_uni().await.unwrap();
            let mut bytes = BytesMut::from(initial_control(&Config::default()).unwrap().as_ref());
            for _ in 0..128 {
                FrameHeader::new(FrameType::new(0x21), 0)
                    .encode(&mut bytes)
                    .unwrap();
            }
            FrameHeader::new(FrameType::GOAWAY, 1)
                .encode(&mut bytes)
                .unwrap();
            VarInt::from_u32(0).encode(&mut bytes);
            control.write_all(&bytes).await.unwrap();
            control.finish().unwrap();
            assert_eq!(control.stopped().await.unwrap(), None);
            pair.server
                .close(Code::H3_NO_ERROR.value() as u32, b"rejected all requests");
            pair.client.closed().await;
            if let Some(dropped) = upload_dropped {
                assert!(dropped.await.is_err());
            }
            // Let the request observe transport closure before its driver can
            // drain the control stream. It must wait rather than lose GOAWAY.
            assert!(poll_fn(|cx| Poll::Ready(response.as_mut().poll(cx).is_pending())).await);
            driver.await.unwrap();
            let error = response.await.unwrap_err();
            assert!(error.is_rejected());
            assert_eq!(error.scope(), ErrorScope::Stream);
            pair.close().await;
        })
        .await
        .unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn memory_response_failure_provenance_separates_peer_reset_from_application_body() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (mut client, driver) =
            client::handshake::<Body>(pair.client.clone(), Config::default(), Executor::new())
                .unwrap();
        let driver = spawn(driver.run());
        let remote_failure = spawn({
            let mut client = client.clone();
            async move {
                client
                    .send_request(
                        Request::builder()
                            .uri("https://localhost/reset")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap_err()
            }
        });
        let (mut send, mut recv) = pair.server.accept_bi().await.unwrap();
        recv.read_to_end(4096).await.unwrap();
        send.reset(VarInt::from_u32(Code::H3_REQUEST_CANCELLED.value() as u32))
            .unwrap();
        let error = remote_failure.await.unwrap();
        assert_eq!(error.scope(), ErrorScope::Stream);
        assert!(error.is_remote_failure());

        let late_reset = spawn({
            let mut client = client.clone();
            async move {
                client
                    .send_request(
                        Request::builder()
                            .uri("https://localhost/late-reset")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap()
            }
        });
        let (mut send, mut recv) = pair.server.accept_bi().await.unwrap();
        recv.read_to_end(4096).await.unwrap();
        let id = u64::from(send.id());
        let mut encoder = Encoder::new(EncoderConfig {
            max_table_capacity: 0,
            ..EncoderConfig::default()
        });
        let fields = encoder.encode(id, [(":status", "200")]).unwrap();
        let mut bytes = BytesMut::new();
        FrameHeader::new(FrameType::HEADERS, fields.len() as u64)
            .encode(&mut bytes)
            .unwrap();
        bytes.extend_from_slice(&fields);
        send.write_all(&bytes).await.unwrap();
        let mut body = late_reset.await.unwrap().into_body();
        send.reset(VarInt::from_u32(Code::H3_REQUEST_CANCELLED.value() as u32))
            .unwrap();
        let error = body.frame().await.unwrap().unwrap_err();
        let cause = error_chain(&error)
            .find_map(|cause| cause.downcast_ref::<Error>())
            .unwrap();
        assert_eq!(cause.scope(), ErrorScope::Stream);
        assert!(cause.is_remote_failure());

        let body = Body::from_stream(stream::once(async {
            Err::<Bytes, _>(BoxError::from_static_str("application body failed"))
        }));
        let error = client
            .send_request(
                Request::builder()
                    .method(Method::POST)
                    .uri("https://localhost/local-error")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::H3_INTERNAL_ERROR);
        assert!(!error.is_remote_failure());
        assert!(pair.client.close_reason().is_none());
        pair.client
            .close(Code::H3_NO_ERROR.value() as u32, b"complete");
        driver.await.unwrap().unwrap();
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn memory_received_body_length_and_trailer_errors_are_remote() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (client, driver) =
            client::handshake::<Body>(pair.client.clone(), Config::default(), Executor::new())
                .unwrap();
        let driver = spawn(driver.run());
        for (declared, bad_trailer) in [("0", false), ("2", false), ("1", true)] {
            let response = spawn({
                let mut client = client.clone();
                async move {
                    client
                        .send_request(
                            Request::builder()
                                .uri("https://localhost/malformed-body")
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap()
                }
            });
            let (mut send, mut recv) = pair.server.accept_bi().await.unwrap();
            recv.read_to_end(4096).await.unwrap();
            let id = u64::from(send.id());
            let mut encoder = Encoder::new(EncoderConfig {
                max_table_capacity: 0,
                ..EncoderConfig::default()
            });
            let fields = encoder
                .encode(id, [(":status", "200"), ("content-length", declared)])
                .unwrap();
            let mut bytes = BytesMut::new();
            FrameHeader::new(FrameType::HEADERS, fields.len() as u64)
                .encode(&mut bytes)
                .unwrap();
            bytes.extend_from_slice(&fields);
            FrameHeader::new(FrameType::DATA, 1)
                .encode(&mut bytes)
                .unwrap();
            bytes.extend_from_slice(b"x");
            if bad_trailer {
                let fields = encoder.encode(id, [("content-length", "0")]).unwrap();
                FrameHeader::new(FrameType::HEADERS, fields.len() as u64)
                    .encode(&mut bytes)
                    .unwrap();
                bytes.extend_from_slice(&fields);
            }
            send.write_all(&bytes).await.unwrap();
            send.finish().unwrap();
            assert_eq!(send.stopped().await.unwrap(), None);
            let error = response
                .await
                .unwrap()
                .into_body()
                .collect()
                .await
                .unwrap_err();
            let cause = error_chain(&error)
                .find_map(|cause| cause.downcast_ref::<Error>())
                .unwrap();
            assert_eq!(cause.code(), Code::H3_MESSAGE_ERROR);
            assert!(cause.is_remote_failure());
            assert!(pair.client.close_reason().is_none());
        }
        pair.client
            .close(Code::H3_NO_ERROR.value() as u32, b"complete");
        driver.await.unwrap().unwrap();
        pair.close().await;
    })
    .await
    .unwrap();
}
