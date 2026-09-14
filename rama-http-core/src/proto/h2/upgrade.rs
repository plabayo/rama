use std::io::Cursor;
use std::pin::Pin;
use std::task::{Context, Poll};

use rama_core::bytes::{Buf, Bytes};
use rama_core::extensions::{Extensions, ExtensionsRef};
use rama_core::futures::ready;
use rama_core::telemetry::tracing::trace;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::SendBuf;
use super::ping::Recorder;
use crate::h2::{Reason, RecvStream, SendStream};

pub(super) fn upgraded<B>(
    send_stream: SendStream<SendBuf<B>>,
    recv_stream: RecvStream,
    ping: Recorder,
) -> H2Upgraded
where
    B: Buf + Send + 'static,
{
    // The upgraded IO owns this HTTP/2 stream's transport metadata. Message
    // extensions may contain OnUpgrade itself, creating a cycle through the
    // queued Upgraded, and may describe the opposite side of a proxy.
    let extensions = recv_stream.extensions();
    H2Upgraded {
        send_stream: Box::new(send_stream),
        send_closed: false,
        recv_stream,
        ping,
        buf: Bytes::new(),
        extensions,
    }
}

/// The h2 send half of a tunnel with the body type erased, so the upgraded IO
/// writes into the stream directly instead of hopping through a channel and a
/// writer task per tunnel.
trait TunnelSink: Send {
    fn reserve_capacity(&mut self, capacity: usize);
    fn poll_capacity(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<usize, crate::h2::Error>>>;
    fn poll_reset(&mut self, cx: &mut Context<'_>) -> Poll<Result<Reason, crate::h2::Error>>;
    fn send_data(&mut self, data: Box<[u8]>) -> Result<(), crate::h2::Error>;
    fn send_end_of_stream(&mut self) -> Result<(), crate::h2::Error>;
}

impl<B> TunnelSink for SendStream<SendBuf<B>>
where
    B: Buf + Send + 'static,
{
    fn reserve_capacity(&mut self, capacity: usize) {
        Self::reserve_capacity(self, capacity);
    }

    fn poll_capacity(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<usize, crate::h2::Error>>> {
        Self::poll_capacity(self, cx)
    }

    fn poll_reset(&mut self, cx: &mut Context<'_>) -> Poll<Result<Reason, crate::h2::Error>> {
        Self::poll_reset(self, cx)
    }

    fn send_data(&mut self, data: Box<[u8]>) -> Result<(), crate::h2::Error> {
        Self::send_data(self, SendBuf::Cursor(Cursor::new(data)), false)
    }

    fn send_end_of_stream(&mut self) -> Result<(), crate::h2::Error> {
        Self::send_data(self, SendBuf::None, true)
    }
}

pub(super) struct H2Upgraded {
    ping: Recorder,
    send_stream: Box<dyn TunnelSink>,
    send_closed: bool,
    recv_stream: RecvStream,
    buf: Bytes,
    extensions: Extensions,
}

impl ExtensionsRef for H2Upgraded {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl Drop for H2Upgraded {
    fn drop(&mut self) {
        // Half-close the tunnel for a peer that is still reading, as a
        // shutdown would have. Nothing to do if the stream is already gone.
        if !self.send_closed {
            _ = self.send_stream.send_end_of_stream();
        }
    }
}

// ===== impl H2Upgraded =====

impl AsyncRead for H2Upgraded {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        read_buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if self.buf.is_empty() {
            self.buf = loop {
                match ready!(self.recv_stream.poll_data(cx)) {
                    None => return Poll::Ready(Ok(())),
                    Some(Ok(buf)) if buf.is_empty() && !self.recv_stream.is_end_stream() => {}
                    Some(Ok(buf)) => {
                        self.ping.record_data(buf.len());
                        break buf;
                    }
                    Some(Err(e)) => {
                        return Poll::Ready(match e.reason() {
                            Some(Reason::NO_ERROR | Reason::CANCEL) => Ok(()),
                            Some(Reason::STREAM_CLOSED) => {
                                Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
                            }
                            _ => Err(h2_to_io_error(e)),
                        });
                    }
                }
            };
        }
        let cnt = std::cmp::min(self.buf.len(), read_buf.remaining());
        read_buf.put_slice(&self.buf[..cnt]);
        self.buf.advance(cnt);
        _ = self.recv_stream.flow_control().release_capacity(cnt);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for H2Upgraded {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.send_closed {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }

        // Flow control decides how much of this write fits; a partial write is
        // fine for `AsyncWrite`. Errors from the capacity and data paths are
        // read off `poll_reset`, which carries the peer's actual reason.
        self.send_stream.reserve_capacity(buf.len());
        let sent = loop {
            match ready!(self.send_stream.poll_capacity(cx)) {
                None => break Some(0),
                // a zero grant is not a grant yet; poll again
                Some(Ok(0)) => {}
                Some(Ok(cnt)) => {
                    let cnt = cnt.min(buf.len());
                    break self
                        .send_stream
                        .send_data(buf[..cnt].into())
                        .ok()
                        .map(|()| cnt);
                }
                Some(Err(_)) => break None,
            }
        };
        if let Some(sent) = sent {
            return Poll::Ready(Ok(sent));
        }

        Poll::Ready(Err(match ready!(self.send_stream.poll_reset(cx)) {
            Ok(reason) => {
                trace!("stream received RST_STREAM: {:?}", reason);
                match reason {
                    Reason::NO_ERROR | Reason::CANCEL | Reason::STREAM_CLOSED => {
                        std::io::ErrorKind::BrokenPipe.into()
                    }
                    reason => h2_to_io_error(reason.into()),
                }
            }
            Err(e) => h2_to_io_error(e),
        }))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        // data handed to h2 is flushed by the connection task
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if self.send_closed {
            return Poll::Ready(Ok(()));
        }
        self.send_closed = true;
        Poll::Ready(
            self.send_stream
                .send_end_of_stream()
                .map_err(h2_to_io_error),
        )
    }
}

#[inline(always)]
fn h2_to_io_error(e: crate::h2::Error) -> std::io::Error {
    e.force_into_io()
}
