//! Ordinary CONNECT uses Rama's existing upgrade API and bounded DATA framing.

use super::{
    frame::FrameEvent,
    quic::Writer,
    stream::{Phase, Reader},
};
use rama_core::{
    bytes::Bytes,
    extensions::{Extensions, ExtensionsRef},
};
use rama_http::io::upgrade::Upgraded;
use rama_http_types::proto::h3::{Code, FrameType};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::OwnedSemaphorePermit,
};

pub(crate) fn new(
    mut reader: Reader<rama_quic::RecvStream>,
    writer: Writer<rama_quic::SendStream>,
    permit: Arc<OwnedSemaphorePermit>,
    priority: Option<super::priority::Lease>,
) -> Upgraded {
    reader.phase = Phase::Tunnel;
    let extensions = reader.shared.transport_extensions.fork();
    let abort = writer.abort_handle();
    extensions.insert(rama_http::io::upgrade::OnUpstreamError::new(move || {
        abort.abort(rama_quic_proto::VarInt::from_u32(
            Code::H3_CONNECT_ERROR.value() as u32,
        ));
    }));
    Upgraded::new(
        Tunnel {
            reader,
            writer,
            buffer: Bytes::new(),
            extensions,
            _priority: priority,
            _permit: Some(permit),
            write_finished: false,
        },
        Bytes::new(),
    )
}

struct Tunnel {
    reader: Reader<rama_quic::RecvStream>,
    writer: Writer<rama_quic::SendStream>,
    buffer: Bytes,
    extensions: Extensions,
    _permit: Option<Arc<OwnedSemaphorePermit>>,
    write_finished: bool,
    _priority: Option<super::priority::Lease>,
}
impl Tunnel {
    fn release_finished(&mut self) {
        if self.write_finished && self.reader.phase == Phase::Finished {
            self._permit.take();
            self._priority.take();
        }
    }

    fn flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), super::Error>> {
        let shared = &self.reader.shared;
        let id = self.reader.id;
        let priority = ready!(shared.schedule.lock().poll_turn(id, cx));
        self.writer.priority(i32::from(7 - priority.urgency()))?;
        let result = self.writer.poll_flush(cx);
        shared.schedule.lock().release(id);
        result
    }
}
impl ExtensionsRef for Tunnel {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}
impl AsyncRead for Tunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if dst.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..32 {
            if !self.buffer.is_empty() {
                let count = dst.remaining().min(self.buffer.len());
                dst.put_slice(&self.buffer.split_to(count));
                return Poll::Ready(Ok(()));
            }
            match ready!(self.reader.poll_event(cx)).map_err(io::Error::other)? {
                Some(FrameEvent::DataChunk(bytes)) => self.buffer = bytes,
                Some(FrameEvent::DataHeader { .. }) => (),
                None => {
                    self.release_finished();
                    return Poll::Ready(Ok(()));
                }
                Some(_) => {
                    let error = super::Error::connection(
                        Code::H3_FRAME_UNEXPECTED,
                        "frame forbidden in CONNECT tunnel",
                    );
                    return Poll::Ready(Err(io::Error::other(self.reader.reject(error))));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl AsyncWrite for Tunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        src: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.flush(cx)).map_err(io::Error::other)?;
        let count = src.len().min(self.reader.shared.config.read_chunk_size);
        if count != 0 {
            self.writer
                .queue(FrameType::DATA, Bytes::copy_from_slice(&src[..count]))
                .map_err(io::Error::other)?;
        }
        // Ownership has transferred: report acceptance before any subsequent Pending.
        Poll::Ready(Ok(count))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flush(cx).map_err(io::Error::other)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.flush(cx)).map_err(io::Error::other)?;
        ready!(self.writer.poll_finish(cx)).map_err(io::Error::other)?;
        self.write_finished = true;
        self.release_finished();
        Poll::Ready(Ok(()))
    }
}
