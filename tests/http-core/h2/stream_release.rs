//! A stream is released once its last handle drops, also when it outlives its connection.

use h2_support::prelude::*;
use rama_core::futures::StreamExt;
use tokio::sync::oneshot;

/// What the handles do once the connection is gone, before they drop.
#[derive(Clone, Copy, Debug)]
enum Late {
    ReleaseCapacity,
    SendReset,
}

#[tokio::test]
async fn client_streams_outliving_their_connection_are_released() {
    h2_support::trace_init!();
    for late in [Late::ReleaseCapacity, Late::SendReset] {
        for io_error in [false, true] {
            let (io, mut srv) = mock::new();
            let payload = vec![0_u8; 16_384];
            let (responded_tx, responded_rx) = oneshot::channel::<()>();

            let mock = async move {
                let settings = srv.assert_client_handshake().await;
                assert_default_settings!(settings);
                srv.recv_frame(frames::headers(1).request("POST", "https://http2.akamai.com/"))
                    .await;
                srv.send_frame(frames::headers(1).response(200)).await;
                for _ in 0..3 {
                    srv.send_frame(frames::data(1, &payload[..])).await;
                }
                responded_rx.await.unwrap();
                if io_error {
                    srv.close_without_notify();
                }
            };

            let h2 = async move {
                let (mut client, mut conn) = client::handshake(io).await.unwrap();
                let request = Request::builder()
                    .method(Method::POST)
                    .uri("https://http2.akamai.com/")
                    .body(())
                    .unwrap();
                let (response, mut stream) = client.send_request(request, false).unwrap();
                let mut body = conn.drive(response).await.unwrap().into_body();
                responded_tx.send(()).unwrap();
                // The connection ends and is dropped while every handle remains.
                drop(conn.await);

                match late {
                    Late::ReleaseCapacity => {
                        while let Some(Ok(chunk)) = body.data().await {
                            body.flow_control().release_capacity(chunk.len()).unwrap();
                        }
                    }
                    Late::SendReset => stream.send_reset(Reason::CANCEL),
                }
                drop((body, stream));
                assert_eq!(
                    client.num_wired_streams(),
                    0,
                    "{late:?}, io error: {io_error}"
                );
            };

            join(mock, h2).await;
        }
    }
}

/// A stream dropped while it waits for connection capacity is reset; the capacity it
/// reclaims for the connection must not release it while that drop is still at work.
#[tokio::test]
async fn dropping_a_stream_waiting_for_connection_capacity_resets_it() {
    h2_support::trace_init!();
    let (io, mut srv) = mock::new();
    let mut settings = frame::Settings::default();
    settings.config.initial_window_size = Some(1_000_000);
    let (reset_tx, reset_rx) = oneshot::channel::<()>();

    let mock = async move {
        let settings = srv.assert_client_handshake_with_settings(settings).await;
        assert_default_settings!(settings);
        srv.recv_frame(frames::headers(1).request("POST", "https://http2.akamai.com/"))
            .await;
        srv.recv_frame(frames::reset(1).cancel()).await;
        reset_tx.send(()).unwrap();
    };

    let h2 = async move {
        let (mut client, mut conn) = client::handshake(io).await.unwrap();
        conn.drive(client.await_peer_initial_settings())
            .await
            .expect("peer SETTINGS");
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://http2.akamai.com/")
            .body(())
            .unwrap();
        let (response, mut stream) = client.send_request(request, false).unwrap();
        // More than the connection window: the stream gets that and waits for the rest.
        stream.reserve_capacity(100_000);
        conn.drive(util::yield_once()).await;
        assert_eq!(stream.capacity(), 65_535);

        drop((response, stream));
        conn.drive(reset_rx).await.unwrap();
        // The store checks on drop that every stream was released.
        drop(client);
        conn.await.unwrap();
    };

    join(mock, h2).await;
}

/// The server end of a peer that dies while its request body is still buffered unread:
/// the body is read and released only after the connection is gone.
#[tokio::test]
async fn server_streams_outliving_their_connection_are_released() {
    h2_support::trace_init!();
    for io_error in [false, true] {
        let (io, mut client) = mock::new();
        let payload = vec![0_u8; 16_384];

        let client = async move {
            let settings = client.assert_server_handshake().await;
            assert_default_settings!(settings);
            client
                .send_frame(frames::headers(1).request("POST", "https://example.com/"))
                .await;
            for _ in 0..3 {
                client.send_frame(frames::data(1, &payload[..])).await;
            }
            client.recv_frame(frames::headers(1).response(200)).await;
            if io_error {
                client.close_without_notify();
            }
        };

        let srv = async move {
            let mut srv = server::handshake(io).await.expect("handshake");
            let (request, mut respond) = srv.next().await.unwrap().unwrap();
            let mut body = request.into_body();
            let response = Response::builder().status(200).body(()).unwrap();
            let send = respond.send_response(response, false).unwrap();
            while srv.next().await.is_some() {}
            drop(srv);

            while let Some(Ok(chunk)) = body.data().await {
                body.flow_control().release_capacity(chunk.len()).unwrap();
            }
            // The store checks on drop that every stream was released.
            drop((body, send, respond));
        };

        join(client, srv).await;
    }
}
