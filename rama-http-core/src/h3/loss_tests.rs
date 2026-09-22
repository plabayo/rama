//! Exercise HTTP/3 recovery through the real QUIC driver under datagram faults.

use super::{LIMIT, Pair};
use crate::h3::{client, connection::Config, server};
use rama_core::{
    bytes::Bytes,
    futures::stream,
    rt::{Executor, spawn},
};
use rama_http_types::{
    Body, HeaderMap, Method, Request, Response, Version,
    body::{Frame, util::BodyExt as _},
    proto::h3::Code,
};
use rama_utils::octets::kib;
use std::convert::Infallible;

const REQUESTS: usize = 4;
const PAYLOAD_SIZE: usize = kib(64);

fn body(payload: Bytes, trailer: &'static str) -> Body {
    let mut trailers = HeaderMap::new();
    trailers.insert("x-trailer", trailer.parse().unwrap());
    Body::from_frame_stream(stream::iter([
        Ok::<_, Infallible>(Frame::data(payload)),
        Ok(Frame::trailers(trailers)),
    ]))
}

#[tokio::test(start_paused = true)]
async fn memory_loss_and_reordering_recover_headers_bodies_trailers_and_qpack() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::impaired().await;
        let faults = pair.datagram_faults.as_ref().unwrap();
        // Arm only after QUIC handshakes. These first faults affect H3 control
        // and request streams, rather than merely exercising TLS retransmits.
        for direction in faults {
            direction.drop_next(1);
            direction.reorder_next_pair().unwrap();
        }
        let (mut client, client_driver) =
            client::handshake::<Body>(pair.client.clone(), Config::default(), Executor::new())
                .unwrap();
        let (mut server, server_driver) =
            server::handshake(pair.server.clone(), Config::default()).unwrap();
        let client_driver = spawn(client_driver.run());
        let server_driver = spawn(server_driver.run());
        let serving = spawn(async move {
            for sequence in 0..REQUESTS {
                let (request, response) = server.accept().await.unwrap().resolve().await.unwrap();
                assert_eq!(request.version(), Version::HTTP_3);
                assert_eq!(
                    request.headers()["x-repeated"],
                    "request dynamic table value"
                );
                let collected = request.into_body().collect().await.unwrap();
                assert_eq!(
                    collected.trailers().unwrap()["x-trailer"],
                    "request trailer"
                );
                let payload = collected.to_bytes();
                assert_eq!(payload.len(), PAYLOAD_SIZE);
                assert!(payload.iter().all(|byte| *byte == sequence as u8));
                response
                    .send_response(
                        Response::builder()
                            .header("x-repeated", "response dynamic table value")
                            .body(body(payload, "response trailer"))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
            }
        });

        for sequence in 0..REQUESTS {
            if sequence > 0 {
                // Repeat faults on an established H3 connection, with a warm
                // QPACK table and previous response bytes fully consumed.
                for direction in faults {
                    assert_eq!(direction.stats().dropped, sequence);
                    assert_eq!(direction.stats().reordered_pairs, sequence);
                    direction.drop_next(1);
                    direction.reorder_next_pair().unwrap();
                }
            }
            let response = client
                .send_request(
                    Request::builder()
                        .method(Method::POST)
                        .uri("https://localhost/loss-and-reordering")
                        .header("x-repeated", "request dynamic table value")
                        .body(body(
                            Bytes::from(vec![sequence as u8; PAYLOAD_SIZE]),
                            "request trailer",
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.version(), Version::HTTP_3);
            assert_eq!(
                response.headers()["x-repeated"],
                "response dynamic table value"
            );
            let collected = response.into_body().collect().await.unwrap();
            assert_eq!(
                collected.trailers().unwrap()["x-trailer"],
                "response trailer"
            );
            let payload = collected.to_bytes();
            assert_eq!(payload.len(), PAYLOAD_SIZE);
            assert!(payload.iter().all(|byte| *byte == sequence as u8));
        }
        for direction in faults {
            assert_eq!(direction.stats().dropped, REQUESTS);
            assert_eq!(direction.stats().reordered_pairs, REQUESTS);
        }
        assert!(client.dynamic_insert_count() > 0);
        serving.await.unwrap();
        pair.client
            .close(Code::H3_NO_ERROR.value() as u32, b"test complete");
        let _client_result = client_driver.await.unwrap();
        let _server_result = server_driver.await.unwrap();
        pair.close().await;
    })
    .await
    .unwrap();
}
