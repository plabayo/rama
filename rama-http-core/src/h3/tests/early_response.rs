//! An unwanted H3 upload must be stopped independently of response completion.
//! Waiting for response ACK before stopping creates a circular flow-control wait
//! for clients that write their upload before reading a multi-window response.

use super::{LIMIT, Pair};
use crate::h3::{
    connection::Config,
    qpack::{Encoder, EncoderConfig},
    server,
};
use rama_core::{
    bytes::{Bytes, BytesMut},
    rt::spawn,
};
use rama_http_types::{
    Body, Response,
    proto::h3::{Code, FrameHeader, FrameType},
};
use rama_quic::TransportConfig;
use rama_utils::octets::kib;
use std::time::Duration;

const WINDOW: usize = kib(16);

fn transport() -> TransportConfig {
    let mut transport = TransportConfig::default();
    Config::default()
        .configure_transport(&mut transport)
        .unwrap();
    transport.set_stream_receive_window(WINDOW as u32);
    transport
}

#[tokio::test(start_paused = true)]
async fn abandoned_upload_does_not_stall_client_that_uploads_before_reading() {
    tokio::time::timeout(LIMIT * 10, async {
        let pair = Pair::in_memory(Some(transport()), Some(transport())).await;
        let (mut server, driver) =
            server::handshake(pair.server.clone(), Config::default()).unwrap();
        let driver = spawn(driver.run());
        let (mut send, mut recv) = pair.client.open_bi().await.unwrap();
        let fields = Encoder::before_peer_settings(EncoderConfig::default())
            .encode(
                u64::from(send.id()),
                [
                    (":method", "POST"),
                    (":scheme", "https"),
                    (":authority", "localhost"),
                    (":path", "/early-response"),
                    ("content-length", "1048576"),
                ],
            )
            .unwrap();
        let mut wire = BytesMut::new();
        FrameHeader::new(FrameType::HEADERS, fields.len() as u64)
            .encode(&mut wire)
            .unwrap();
        wire.extend_from_slice(&fields);
        FrameHeader::new(FrameType::DATA, 1_048_576)
            .encode(&mut wire)
            .unwrap();
        send.write_chunk(wire.freeze()).await.unwrap();

        // Sequential client: write the whole upload, only then read the response.
        let client = spawn(async move {
            let started = tokio::time::Instant::now();
            let mut upload = Ok(());
            for _ in 0..(1_048_576 / WINDOW) {
                if let Err(error) = send.write_chunk(Bytes::from(vec![0x61; WINDOW])).await {
                    upload = Err(error);
                    break;
                }
            }
            let upload_ended_after = started.elapsed();
            let response = recv.read_to_end(kib(1024)).await;
            (upload, upload_ended_after, response)
        });

        let (request, response) = server.accept().await.unwrap().resolve().await.unwrap();
        // The handler does not want the upload and answers with more than one
        // client stream window of response body.
        drop(request);
        let sending =
            spawn(response.send_response(Response::new(Body::from(vec![0x5a; 4 * WINDOW]))));

        let (upload, upload_ended_after, wire) =
            tokio::time::timeout(Duration::from_secs(5), client)
                .await
                .expect("upload and response deadlocked")
                .unwrap();
        sending.await.unwrap().unwrap();
        assert!(upload_ended_after < Duration::from_secs(5));
        let error = upload.expect_err("upload must be stopped, not drained");
        assert!(
            matches!(error, rama_quic::WriteError::Stopped(code) if code.into_inner() == Code::H3_NO_ERROR.value())
        );
        let wire = wire.unwrap();
        let mut decoder = crate::h3::frame::FrameDecoder::new(kib(1024));
        decoder.feed(&wire).unwrap();
        let mut received = 0;
        let mut headers = 0;
        while let Some(event) = decoder.poll().unwrap() {
            match event {
                crate::h3::frame::FrameEvent::Headers(_) => headers += 1,
                crate::h3::frame::FrameEvent::DataChunk(bytes) => {
                    assert!(bytes.iter().all(|byte| *byte == 0x5a));
                    received += bytes.len();
                }
                _ => {}
            }
        }
        assert!(decoder.is_at_frame_boundary());
        assert_eq!(headers, 1);
        assert_eq!(received, 4 * WINDOW);
        pair.client.close(0u32, b"done");
        _ = driver.await;
        pair.close().await;
    })
    .await
    .unwrap();
}
