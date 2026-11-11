//! An idle HTTP/1 keep-alive connection releases large message buffers after its
//! brief reuse window, with or without vectored writes on the transport.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail immediately on unexpected setup, transport, or body errors"
)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    convert::Infallible,
    io,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll, ready},
    time::Duration,
};

use rama_core::{
    ServiceInput,
    bytes::{Buf, Bytes},
    service::service_fn,
};
use rama_http::{Body, Method, Request, Response, body::util::BodyExt};
use rama_http_core::{server::conn::http1, service::RamaHttpService};
use rama_utils::octets::{kib, mib};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, DuplexStream, ReadBuf},
    sync::mpsc,
};

struct CountingAlloc;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards to `System` unchanged; the counter is only bookkeeping.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        // SAFETY: same layout contract as our caller.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: `ptr` came from `alloc` above with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE_BYTES.fetch_add(new_size, Ordering::Relaxed);
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: same contract as our caller.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

// Well above per-connection steady state, far below the message sizes used here.
const IDLE_GROWTH_LIMIT: usize = kib(64);
const RESPONSE_SIZE: usize = mib(4);
const UPLOAD_SIZE: usize = mib(8);
const SMALL_REQUEST: &[u8] = b"POST /small HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhi";

/// Server side transport: requests arrive as whole chunks, like a fast socket hands over
/// full reads; responses go out over a duplex; vectored-write support is configurable.
struct Transport {
    requests: mpsc::UnboundedReceiver<Bytes>,
    pending: Bytes,
    inner: DuplexStream,
    vectored: bool,
}

impl AsyncRead for Transport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pending.is_empty() {
            match ready!(self.requests.poll_recv(cx)) {
                Some(chunk) => self.pending = chunk,
                None => return Poll::Ready(Ok(())),
            }
        }
        let n = self.pending.len().min(buf.remaining());
        buf.put_slice(&self.pending[..n]);
        self.pending.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Transport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.vectored
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn read_response(client: &mut DuplexStream, scratch: &mut [u8]) {
    let mut head = Vec::new();
    let body_start = loop {
        let n = client.read(scratch).await.unwrap();
        assert_ne!(n, 0, "connection closed before the response head");
        head.extend_from_slice(&scratch[..n]);
        if let Some(pos) = head.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let content_length: usize = std::str::from_utf8(&head[..body_start])
        .unwrap()
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().unwrap())
        })
        .expect("content-length");
    let mut remaining = content_length - (head.len() - body_start);
    drop(head);
    while remaining > 0 {
        let n = client.read(scratch).await.unwrap();
        assert_ne!(n, 0, "connection closed mid body");
        remaining -= n;
    }
}

async fn settle() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

async fn idle_growth_after(vectored: bool, request: &[Bytes]) -> (usize, usize) {
    let big = Bytes::from(vec![b'x'; RESPONSE_SIZE]);
    let (requests, rx) = mpsc::unbounded_channel();
    let (mut client, server) = tokio::io::duplex(kib(16));
    let service = service_fn(move |req: Request| {
        let big = big.clone();
        async move {
            let body = if req.method() == Method::GET {
                Body::from(big)
            } else {
                drop(req.into_body().collect().await.unwrap());
                Body::from("ok")
            };
            Ok::<_, Infallible>(Response::new(body))
        }
    });
    let connection = tokio::spawn(http1::Builder::new().serve_connection(
        ServiceInput::new(Transport {
            requests: rx,
            pending: Bytes::new(),
            inner: server,
            vectored,
        }),
        RamaHttpService::new(service),
    ));

    let mut scratch = vec![0u8; kib(16)];
    requests.send(Bytes::from_static(SMALL_REQUEST)).unwrap();
    read_response(&mut client, &mut scratch).await;
    settle().await;
    let baseline = LIVE_BYTES.load(Ordering::Relaxed);

    for chunk in request {
        requests.send(chunk.clone()).unwrap();
    }
    read_response(&mut client, &mut scratch).await;
    settle().await;
    let warm_growth = LIVE_BYTES.load(Ordering::Relaxed).saturating_sub(baseline);

    // No new traffic: the connection must wake itself to release its warm
    // allocation. Keep the original long-idle memory bound unchanged.
    tokio::time::advance(Duration::from_millis(150)).await;
    settle().await;
    let expired_growth = LIVE_BYTES.load(Ordering::Relaxed).saturating_sub(baseline);

    requests.send(Bytes::from_static(SMALL_REQUEST)).unwrap();
    read_response(&mut client, &mut scratch).await;

    connection.abort();
    assert!(connection.await.unwrap_err().is_cancelled());
    (warm_growth, expired_growth)
}

// One test so no other test allocates while the counter is read.
#[tokio::test(start_paused = true)]
async fn idle_connection_releases_large_message_buffers() {
    let download = [Bytes::from_static(b"GET /big HTTP/1.1\r\nHost: a\r\n\r\n")];
    let upload_body = Bytes::from(vec![b'u'; UPLOAD_SIZE]);
    let mut upload = vec![Bytes::from(format!(
        "POST /upload HTTP/1.1\r\nHost: a\r\nContent-Length: {UPLOAD_SIZE}\r\n\r\n"
    ))];
    upload.extend(
        (0..UPLOAD_SIZE)
            .step_by(kib(512))
            .map(|at| upload_body.slice(at..at + kib(512))),
    );

    for vectored in [false, true] {
        let (warm_growth, growth) = idle_growth_after(vectored, &download).await;
        assert!(
            warm_growth < IDLE_GROWTH_LIMIT,
            "vectored={vectored}: write buffers retained {warm_growth} bytes after flush"
        );
        assert!(
            growth < IDLE_GROWTH_LIMIT,
            "vectored={vectored}: idle connection kept {growth} bytes after a large response"
        );

        let (warm_growth, growth) = idle_growth_after(vectored, &upload).await;
        assert!(
            (IDLE_GROWTH_LIMIT..kib(512) + IDLE_GROWTH_LIMIT).contains(&warm_growth),
            "vectored={vectored}: unexpected warm read-buffer growth of {warm_growth} bytes"
        );
        assert!(
            growth < IDLE_GROWTH_LIMIT,
            "vectored={vectored}: idle connection kept {growth} bytes after a large upload"
        );
    }
}
