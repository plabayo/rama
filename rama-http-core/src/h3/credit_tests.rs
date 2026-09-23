//! Exercise advertised stream-credit boundaries on the actual control stream.

use super::{LIMIT, Pair};
use crate::h3::{
    connection::{Config, initial_control},
    server,
};
use rama_core::{bytes::BytesMut, rt::spawn};
use rama_http_types::proto::h3::{Code, FrameHeader, FrameType};
use rama_quic_proto::{Dir, Side, StreamId, coding::Codec as _};

#[tokio::test(start_paused = true)]
async fn priority_update_checks_exact_advertised_stream_limit() {
    tokio::time::timeout(LIMIT, async {
        for at_limit in [false, true] {
            let pair = Pair::in_memory(None, None).await;
            let (_server, driver) =
                server::handshake(pair.server.clone(), Config::default()).unwrap();
            let driver = spawn(driver.run());
            let limit = pair.server.remote_stream_limit(Dir::Bi);
            let index = if at_limit { limit } else { limit - 1 };
            let mut payload = BytesMut::new();
            StreamId::new(Side::Client, Dir::Bi, index).encode(&mut payload);
            payload.extend_from_slice(b"u=1");
            let mut bytes = BytesMut::from(initial_control(&Config::default()).unwrap().as_ref());
            FrameHeader::new(FrameType::PRIORITY_UPDATE_REQUEST, payload.len() as u64)
                .encode(&mut bytes)
                .unwrap();
            bytes.extend_from_slice(&payload);
            // An invalid control-stream DATA frame is a processing barrier. The
            // valid update below the limit must reach it; the exact-limit ID
            // must fail first, independently of priority-field parsing.
            FrameHeader::new(FrameType::DATA, 0)
                .encode(&mut bytes)
                .unwrap();
            let mut control = pair.client.open_uni().await.unwrap();
            control.write_all(&bytes).await.unwrap();
            assert_eq!(
                driver.await.unwrap().unwrap_err().code(),
                if at_limit {
                    Code::H3_ID_ERROR
                } else {
                    Code::H3_FRAME_UNEXPECTED
                }
            );
            pair.close().await;
        }
    })
    .await
    .unwrap();
}
