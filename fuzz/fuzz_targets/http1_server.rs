//! HTTP/1 server connection fuzz target: request heads, bodies and keep-alive.
//!
//! Goals: arbitrary request bytes, read in arbitrary chunk sizes, never panic
//! or hang the connection, its parser, body decoders or response writer.
//!
//! Run with:
//!     cargo +nightly fuzz run http1_server -- -max_len=65536 -timeout=10
#![expect(
    clippy::unwrap_used,
    reason = "fuzz target: panic-on-error is the standard pattern for harnesses"
)]
#![no_main]

use libfuzzer_sys::fuzz_target;
use rama::ServiceInput;
use rama::bytes::{Buf as _, Bytes};
use rama::http::body::util::BodyExt as _;
use rama::http::core::server::conn::http1;
use rama::http::core::service::RamaHttpService;
use rama::http::{Body, Request, Response};
use rama::service::service_fn;
use std::convert::Infallible;
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

async fn echo_length(req: Request) -> Result<Response, Infallible> {
    let len = match req.into_body().collect().await {
        Ok(body) => body.to_bytes().len(),
        Err(_) => 0,
    };
    Ok(Response::new(Body::from(len.to_string())))
}

fuzz_target!(|data: &[u8]| {
    let Some((&step, input)) = data.split_first() else {
        return;
    };
    let io = MockIo {
        input: Bytes::copy_from_slice(input),
        step: usize::from(step).max(1),
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let connection = http1::Builder::new()
            .serve_connection(
                ServiceInput::new(io),
                RamaHttpService::new(service_fn(echo_length)),
            )
            .with_upgrades();
        _ = tokio::time::timeout(Duration::from_secs(5), connection).await;
    });
});
