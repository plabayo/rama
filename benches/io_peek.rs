#![expect(
    clippy::expect_used,
    reason = "bench: panic-on-error checks the in-memory fixture"
)]

//! Prefix peeking and PROXY header ingestion under fragmented input.

use divan::{black_box, counter::BytesCount};
use rama::bytes::{Buf as _, Bytes};
use rama::error::BoxError;
use rama::io::peek::{PeekVerdict, PeekWaiter, peek_input_until_verdict_growing};
use rama::proxy::haproxy::{protocol::v2, server::HaProxyService};
use rama::service::service_fn;
use rama::utils::octets::kib;
use rama::{Service, ServiceInput};
use std::{
    io,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

mod bench_alloc;

struct Fragmented {
    input: Bytes,
    width: usize,
}

impl AsyncRead for Fragmented {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let n = self.input.len().min(self.width).min(buf.remaining());
        buf.put_slice(&self.input[..n]);
        self.input.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Fragmented {
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

fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return out;
        }
        std::hint::spin_loop();
    }
}

fn prefix(input: &Bytes, width: usize) -> Vec<u8> {
    let mut buffer = Vec::new();
    let len = input.len();
    let matched = block_on(peek_input_until_verdict_growing(
        &mut Fragmented {
            input: input.clone(),
            width,
        },
        &mut buffer,
        len,
        NonZeroUsize::new(kib(8)).expect("nonzero read size"),
        &mut PeekWaiter::new(None),
        |data| {
            if data.len() == len {
                PeekVerdict::Match(())
            } else {
                PeekVerdict::NeedMore
            }
        },
    ));
    assert!(matched.is_some());
    buffer
}

fn proxy_header() -> Bytes {
    v2::Builder::with_addresses(
        v2::Version::Two | v2::Command::Local,
        v2::Protocol::Unspecified,
        v2::Addresses::Unspecified,
    )
    .write_tlv(v2::Type::NoOp, &vec![b'x'; kib(16)])
    .expect("valid TLV")
    .build()
    .expect("valid header")
    .into()
}

fn main() {
    let input = Bytes::from(vec![b'x'; kib(16)]);
    for width in [1, 64, kib(8)] {
        assert_eq!(prefix(&input, width), input);
    }
    divan::main();
}

#[divan::bench(args = [1, 64, 8192])]
fn growing_prefix(bencher: divan::Bencher, width: usize) {
    let input = Bytes::from(vec![b'x'; kib(16)]);
    bencher
        .counter(BytesCount::new(input.len()))
        .bench_local(|| prefix(black_box(&input), width));
}

#[divan::bench(args = [1, 64, 8192])]
fn required_proxy_header(bencher: divan::Bencher, width: usize) {
    let input = proxy_header();
    let service = HaProxyService::new(service_fn(|_stream| async { Ok::<_, BoxError>(()) }));
    bencher
        .counter(BytesCount::new(input.len()))
        .bench_local(|| {
            block_on(service.serve(ServiceInput::new(Fragmented {
                input: black_box(&input).clone(),
                width,
            })))
            .expect("valid PROXY header")
        });
}
