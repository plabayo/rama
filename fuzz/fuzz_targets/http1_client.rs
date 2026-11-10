//! HTTP/1 client connection fuzz target: response heads, bodies and keep-alive.
//!
//! Goals: arbitrary response bytes, read in arbitrary chunk sizes, never panic
//! or hang the client connection, its parser or body decoders.
//!
//! Run with:
//!     cargo +nightly fuzz run http1_client -- -max_len=65536 -timeout=10
#![expect(
    clippy::unwrap_used,
    reason = "fuzz target: panic-on-error is the standard pattern for harnesses"
)]
#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::ServiceInput;
use rama::bytes::{Buf as _, Bytes};
use rama::http::body::util::BodyExt as _;
use rama::http::core::client::conn::http1;
use rama::http::{Body, Method, Request};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Hands out the input in chunks of `step` bytes and accepts every write.
struct MockIo {
    input: Bytes,
    step: usize,
}

impl AsyncRead for MockIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let len = self.step.min(self.input.len()).min(buf.remaining());
        buf.put_slice(&self.input[..len]);
        self.input.advance(len);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MockIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn run(io: MockIo, head: bool) {
    let Ok((mut send, connection)) = http1::handshake::<_, Body>(ServiceInput::new(io)).await
    else {
        return;
    };
    let connection = tokio::spawn(connection);
    // pipelined responses: keep asking while the connection stays usable
    for _ in 0..4 {
        if send.ready().await.is_err() {
            break;
        }
        let method = if head { Method::HEAD } else { Method::GET };
        let request = Request::builder()
            .method(method)
            .uri("/")
            .header("host", "example.com")
            .body(Body::empty())
            .unwrap();
        let Ok(response) = send.send_request(request).await else {
            break;
        };
        _ = response.into_body().collect().await;
    }
    drop(send);
    _ = connection.await;
}

fuzz_target!(|data: &[u8]| {
    let Some((&control, input)) = data.split_first() else {
        return;
    };
    let io = MockIo {
        input: Bytes::copy_from_slice(input),
        step: usize::from(control >> 1).max(1),
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        _ = tokio::time::timeout(Duration::from_secs(5), run(io, control & 1 == 1)).await;
    });
});
