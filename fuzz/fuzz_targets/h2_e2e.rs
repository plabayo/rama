#![no_main]
use rama::http::{Method, Request};

use libfuzzer_sys::fuzz_target;
use rama::futures::stream::FuturesUnordered;
use rama::futures::{Stream, future};

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct MockIo<'a> {
    input: &'a [u8],
}

impl MockIo<'_> {
    fn next_byte(&mut self) -> Option<u8> {
        if let Some(&c) = self.input.first() {
            self.input = &self.input[1..];
            Some(c)
        } else {
            None
        }
    }

    fn next_u32(&mut self) -> u32 {
        ((self.next_byte().unwrap_or(0) as u32) << 8) | self.next_byte().unwrap_or(0) as u32
    }
}

impl AsyncRead for MockIo<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let mut len = self.next_u32() as usize;
        if self.input.is_empty() {
            Poll::Ready(Ok(()))
        } else if len == 0 {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            if len > self.input.len() {
                len = self.input.len();
            }

            if len > buf.remaining() {
                len = buf.remaining();
            }
            buf.put_slice(&self.input[..len]);
            self.input = &self.input[len..];
            Poll::Ready(Ok(()))
        }
    }
}

impl AsyncWrite for MockIo<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let len = std::cmp::min(self.next_u32() as usize, buf.len());
        if len == 0 {
            if self.input.is_empty() {
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        } else {
            Poll::Ready(Ok(len))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn run(script: &[u8]) -> Result<(), rama_http_core::h2::Error> {
    let io = MockIo { input: script };
    let (mut h2, mut connection) = rama_http_core::h2::client::handshake(io).await?;
    let mut futs = FuturesUnordered::new();
    let future = future::poll_fn(|cx| {
        if Pin::new(&mut connection).poll(cx)? == Poll::Ready(()) {
            return Poll::Ready(Ok::<_, rama_http_core::h2::Error>(()));
        }
        while futs.len() < 128 {
            if !h2.poll_ready(cx)?.is_ready() {
                break;
            }
            let request = Request::builder()
                .method(Method::POST)
                .uri("https://example.com/")
                .body(())
                .unwrap();
            let (resp, mut send) = h2.send_request(request, false)?;
            send.send_data(vec![0u8; 32769].into(), true).unwrap();
            drop(send);
            futs.push(resp);
        }
        loop {
            match Pin::new(&mut futs).poll_next(cx) {
                Poll::Pending | Poll::Ready(None) => break,
                r @ Poll::Ready(Some(Ok(_) | Err(_))) => {
                    eprintln!("{r:?}");
                }
            }
        }
        Poll::Pending
    });
    future.await?;
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _res = rt.block_on(run(data));
});
