//! Cancellation across independent HTTP message directions and QPACK state.

use super::{LIMIT, Pair};
use crate::h3::{
    body, client,
    connection::{Config, Shared},
    control::Role,
    qpack::{Encoder, EncoderConfig},
    server,
    stream::{Phase, Reader},
};
use rama_core::{
    bytes::{Bytes, BytesMut},
    extensions::ExtensionsRef,
    futures::{FutureExt as _, stream},
    rt::{Executor, spawn},
};
use rama_http_types::{
    Body, Method, Request, Response,
    body::{Frame, util::BodyExt},
    proto::{
        h2::ext::Protocol,
        h3::{Code, FrameHeader, FrameType},
    },
};
use std::{convert::Infallible, sync::Arc};
use tokio::sync::{Semaphore, oneshot};

fn headers_frame(fields: &[u8]) -> Bytes {
    let mut wire = BytesMut::new();
    FrameHeader::new(FrameType::HEADERS, fields.len() as u64)
        .encode(&mut wire)
        .unwrap();
    wire.extend_from_slice(fields);
    wire.freeze()
}

#[tokio::test]
async fn extended_connect_is_rejected_before_opening_a_stream() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (mut client, driver) =
            client::handshake::<Body>(pair.client.clone(), Config::default(), Executor::new())
                .unwrap();
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri("https://localhost:443/chat")
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(Protocol::WEBSOCKET);
        let error = client
            .send_request(request)
            .now_or_never()
            .expect("unsupported requests fail locally without waiting for peer traffic")
            .unwrap_err();
        assert_eq!(error.code(), Code::H3_MESSAGE_ERROR);
        // The rejected request must not consume even one stream ID.
        let (send, recv) = pair.client.open_bi().await.unwrap();
        assert_eq!(u64::from(send.id()), 0);
        drop((send, recv, client, driver));
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn abandoned_push_stream_releases_peer_qpack_sections_in_both_arrival_orders() {
    for cancel_before_stream in [false, true] {
        tokio::time::timeout(LIMIT, async {
            let pair = Pair::in_memory(None, None).await;
            let shared = Shared::new(Config::default(), Role::Client, Default::default()).unwrap();
            shared.pushes.lock().grant(0);
            let mut send = pair.server.open_uni().await.unwrap();
            let id = u64::from(send.id());
            let mut encoder = Encoder::new(EncoderConfig::default());
            let fields = encoder.encode(id, [("x-pushed", "retained")]).unwrap();
            assert_eq!(encoder.tracked_section_count(), 1);
            send.write_chunk(headers_frame(&fields)).await.unwrap();
            let recv = pair.client.accept_uni().await.unwrap();
            if cancel_before_stream {
                shared.cancel_push(0, true).unwrap();
            }
            shared.accept_push_stream(0, recv, Bytes::new()).unwrap();
            if !cancel_before_stream {
                shared.cancel_push(0, true).unwrap();
            }
            let feedback = shared.take_output(false).unwrap();
            assert!(!feedback.is_empty());
            encoder.feed_decoder_stream(&feedback).unwrap();
            assert_eq!(encoder.tracked_section_count(), 0);
            assert_eq!(
                send.stopped().await.unwrap().map(u64::from),
                Some(Code::H3_REQUEST_CANCELLED.value())
            );
            shared.cancel_push(0, true).unwrap();
            assert!(shared.take_output(false).unwrap().is_empty());
            pair.close().await;
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn dropping_unread_request_body_cancels_peer_qpack_sections() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let shared = Shared::new(Config::default(), Role::Server, Default::default()).unwrap();
        let (mut send, response) = pair.client.open_bi().await.unwrap();
        let id = u64::from(send.id());
        let mut encoder = Encoder::new(EncoderConfig::default());
        let trailers = encoder.encode(id, [("x-trailer", "unread")]).unwrap();
        assert_eq!(encoder.tracked_section_count(), 1);
        send.write_chunk(headers_frame(&trailers)).await.unwrap();
        let (response_send, recv) = pair.server.accept_bi().await.unwrap();
        let mut reader = Reader::new(recv, shared.clone(), id);
        reader.phase = Phase::Body;
        let permit = Arc::new(Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap());
        drop(body::Body::new(reader, None, permit));
        let feedback = shared.take_output(false).unwrap();
        assert!(!feedback.is_empty());
        encoder.feed_decoder_stream(&feedback).unwrap();
        assert_eq!(encoder.tracked_section_count(), 0);
        assert_eq!(
            send.stopped().await.unwrap().map(u64::from),
            Some(Code::H3_REQUEST_CANCELLED.value())
        );
        drop((response, response_send));
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn consuming_early_response_keeps_request_upload_alive() {
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
            let (request, response) = server.accept().await.unwrap().resolve().await.unwrap();
            response
                .send_response(Response::new(Body::empty()))
                .await
                .unwrap();
            assert_eq!(
                request.into_body().collect().await.unwrap().to_bytes(),
                "late upload"
            );
        });
        let (release_upload, upload_ready) = oneshot::channel();
        let frames = stream::once(async move {
            upload_ready.await.unwrap();
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"late upload")))
        });
        let response = client
            .send_request(
                Request::builder()
                    .method(Method::POST)
                    .uri("https://localhost/upload")
                    .body(Body::from_frame_stream(frames))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
        release_upload.send(()).unwrap();
        serve.await.unwrap();
        pair.client.close(Code::H3_NO_ERROR.value() as u32, b"done");
        _ = client_driver.await;
        _ = server_driver.await;
        pair.close().await;
    })
    .await
    .unwrap();
}
