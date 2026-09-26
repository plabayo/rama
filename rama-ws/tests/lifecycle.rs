//! Transport shutdown after the close handshake, across split halves and cancelled polls.

#![expect(clippy::unwrap_used, reason = "test fixtures")]

use parking_lot::Mutex;
use rama_core::{
    ServiceInput,
    futures::{Sink, Stream, StreamExt as _},
};
use rama_ws::{AsyncWebSocket, Message, protocol::Role};
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Releases a pending transport shutdown on demand.
#[derive(Default)]
struct Gate {
    open: AtomicBool,
    // A valid transport keeps only the latest shutdown waker.
    waker: Mutex<Option<Waker>>,
}

impl Gate {
    fn release(&self) {
        self.open.store(true, Ordering::Release);
        self.waker.lock().take().unwrap().wake();
    }
}

/// Delivers one masked client close frame, then stays idle; shutdown waits for the gate.
struct GatedIo {
    delivered: bool,
    gate: Arc<Gate>,
}

impl AsyncRead for GatedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.delivered {
            return Poll::Pending;
        }
        buf.put_slice(&[0x88, 0x80, 0, 0, 0, 0]);
        self.delivered = true;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for GatedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.gate.open.load(Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        }
        *self.gate.waker.lock() = Some(cx.waker().clone());
        Poll::Pending
    }
}

#[derive(Default)]
struct CountWakes(AtomicUsize);

impl Wake for CountWakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

impl CountWakes {
    fn count(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }
}

async fn closed_socket(gate: &Arc<Gate>) -> AsyncWebSocket<ServiceInput<GatedIo>> {
    let io = ServiceInput::new(GatedIo {
        delivered: false,
        gate: gate.clone(),
    });
    let mut socket = AsyncWebSocket::from_raw_socket(io, Role::Server, None).await;
    assert!(matches!(socket.next().await, Some(Ok(Message::Close(_)))));
    socket
}

#[tokio::test]
async fn split_halves_both_wake_when_the_shutdown_completes() {
    for sink_first in [true, false] {
        let gate = Arc::new(Gate::default());
        let (mut sink, mut stream) = closed_socket(&gate).await.split();
        let read_wakes = Arc::new(CountWakes::default());
        let write_wakes = Arc::new(CountWakes::default());
        let read_waker = Waker::from(read_wakes.clone());
        let write_waker = Waker::from(write_wakes.clone());
        let mut read_cx = Context::from_waker(&read_waker);
        let mut write_cx = Context::from_waker(&write_waker);
        if sink_first {
            assert!(Pin::new(&mut sink).poll_close(&mut write_cx).is_pending());
            assert!(Pin::new(&mut stream).poll_next(&mut read_cx).is_pending());
        } else {
            assert!(Pin::new(&mut stream).poll_next(&mut read_cx).is_pending());
            assert!(Pin::new(&mut sink).poll_close(&mut write_cx).is_pending());
        }
        read_wakes.0.store(0, Ordering::Release);
        write_wakes.0.store(0, Ordering::Release);
        gate.release();
        // Drive only the half the transport notified, as an executor would.
        if sink_first {
            assert!(read_wakes.count() > 0);
            assert!(matches!(
                Pin::new(&mut stream).poll_next(&mut read_cx),
                Poll::Ready(None)
            ));
            assert!(write_wakes.count() > 0, "the pending close was stranded");
        } else {
            assert!(write_wakes.count() > 0);
            assert!(matches!(
                Pin::new(&mut sink).poll_close(&mut write_cx),
                Poll::Ready(Ok(()))
            ));
            assert!(read_wakes.count() > 0, "the pending read was stranded");
        }
    }
}

#[tokio::test]
async fn cancelled_shutdowns_resume_through_any_operation() {
    // A pending poll abandoned while the socket is kept, as when a select branch loses.
    for first in ["read", "close"] {
        for resume in ["read", "close", "flush"] {
            let gate = Arc::new(Gate::default());
            let mut socket = closed_socket(&gate).await;
            let old_waker = Waker::from(Arc::new(CountWakes::default()));
            let mut old_cx = Context::from_waker(&old_waker);
            let initial = match first {
                "read" => Pin::new(&mut socket).poll_next(&mut old_cx).map(drop),
                _ => Pin::new(&mut socket).poll_close(&mut old_cx).map(drop),
            };
            assert!(initial.is_pending());
            let new_wakes = Arc::new(CountWakes::default());
            let new_waker = Waker::from(new_wakes.clone());
            let mut new_cx = Context::from_waker(&new_waker);
            let poll = |socket: &mut AsyncWebSocket<ServiceInput<GatedIo>>,
                        cx: &mut Context<'_>|
             -> Poll<()> {
                match resume {
                    "read" => Pin::new(socket)
                        .poll_next(cx)
                        .map(|next| assert!(next.is_none())),
                    "close" => Pin::new(socket).poll_close(cx).map(|r| r.unwrap()),
                    _ => Pin::new(socket).poll_flush(cx).map(|r| r.unwrap()),
                }
            };
            assert!(
                poll(&mut socket, &mut new_cx).is_pending(),
                "{resume} completed a cancelled {first} before the transport shut down"
            );
            gate.release();
            assert!(
                new_wakes.count() > 0,
                "the resumed {resume} was not notified"
            );
            assert!(poll(&mut socket, &mut new_cx).is_ready());
        }
    }
}
