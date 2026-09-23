//! Private chunk transport boundary. HTTP messages never use a QUIC connection as byte IO.

use super::Error;
use rama_core::bytes::{Bytes, BytesMut};
use rama_http_types::proto::h3::{Code, FrameHeader, FrameType, VarInt};
use rama_quic::{
    ReadError, RecvStream as QuicRecvStream, SendStream as QuicSendStream, StoppedError,
    StreamAbortHandle, WriteError,
};
use std::task::{Context, Poll, ready};

pub(crate) trait SendStream {
    /// Wait for FIN acknowledgement, or observe cancellation before it arrives.
    fn acknowledged(&self) -> impl Future<Output = Result<(), Error>> + Send + Sync + 'static;

    fn poll_chunks(
        &mut self,
        cx: &mut Context<'_>,
        chunks: &mut [Bytes],
    ) -> Poll<Result<(), Error>>;
    fn finish(&mut self) -> Result<(), Error>;
    fn reset(&mut self, code: Code);
    fn priority(&mut self, priority: i32) -> Result<(), Error>;
}

pub(crate) trait RecvStream {
    fn poll_chunk(
        &mut self,
        cx: &mut Context<'_>,
        limit: usize,
    ) -> Poll<Result<Option<Bytes>, Error>>;
    fn stop(&mut self, code: Code);
}

impl SendStream for QuicSendStream {
    fn acknowledged(&self) -> impl Future<Output = Result<(), Error>> + Send + Sync + 'static {
        let stopped = self.stopped();
        async move {
            match stopped.await {
                Ok(Some(code)) => Err(Error::peer_stopped(Code::new(code.into_inner()))),
                Err(StoppedError::ConnectionLost(error)) => Err(Error::from_transport(&error)),
                Ok(None) => Ok(()),
                Err(StoppedError::ZeroRttRejected) => Err(Error::stream(
                    Code::H3_REQUEST_CANCELLED,
                    "send stream closed",
                )),
            }
        }
    }

    fn priority(&mut self, priority: i32) -> Result<(), Error> {
        self.set_priority(priority)
            .map_err(|_error| Error::stream(Code::H3_REQUEST_CANCELLED, "send stream closed"))
    }

    fn poll_chunks(
        &mut self,
        cx: &mut Context<'_>,
        chunks: &mut [Bytes],
    ) -> Poll<Result<(), Error>> {
        self.poll_write_chunks_with_reserve(cx, chunks, super::connection::CRITICAL_SEND_RESERVE)
            .map(|result| result.map(|_| ()).map_err(|error| write_error(&error)))
    }

    fn finish(&mut self) -> Result<(), Error> {
        self.finish()
            .map_err(|_error| Error::stream(Code::H3_REQUEST_CANCELLED, "send stream closed"))
    }

    fn reset(&mut self, code: Code) {
        if let Ok(code) = VarInt::from_u64(code.value()) {
            _ = self.reset(code);
        }
    }
}

impl RecvStream for QuicRecvStream {
    fn poll_chunk(
        &mut self,
        cx: &mut Context<'_>,
        limit: usize,
    ) -> Poll<Result<Option<Bytes>, Error>> {
        self.poll_read_chunk(cx, limit, true).map(|result| {
            result
                .map(|chunk| chunk.map(|c| c.bytes))
                .map_err(|error| read_error(&error))
        })
    }

    fn stop(&mut self, code: Code) {
        if let Ok(code) = VarInt::from_u64(code.value()) {
            _ = self.stop(code);
        }
    }
}

fn write_error(error: &WriteError) -> Error {
    match error {
        WriteError::Stopped(code) => Error::peer_stopped(Code::new(code.into_inner())),
        WriteError::ConnectionLost(error) => Error::from_transport(error),
        _ => Error::stream(Code::H3_REQUEST_CANCELLED, "QUIC send failed"),
    }
}

fn read_error(error: &ReadError) -> Error {
    match error {
        ReadError::Reset(code) => {
            Error::stream(Code::new(code.into_inner()), "peer reset stream").remote()
        }
        ReadError::ConnectionLost(error) => Error::from_transport(error),
        _ => Error::stream(Code::H3_REQUEST_CANCELLED, "QUIC receive failed"),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SendState {
    Open,
    FinQueued,
    Complete,
}

/// At most one frame in flight. Dropping a poll future does not discard its remaining bytes.
pub(crate) struct Writer<S: SendStream> {
    stream: S,
    chunks: [Bytes; 2],
    data_header: Option<(usize, Bytes)>,
    priority: Option<i32>,
    state: SendState,
    pub(crate) cancel_code: Code,
}

impl Writer<QuicSendStream> {
    pub(crate) fn abort_handle(&self) -> StreamAbortHandle {
        self.stream.abort_handle()
    }
}

impl<S: SendStream> Writer<S> {
    /// Abort the send direction using the same cause as the receive direction.
    pub(crate) fn reset(&mut self, code: Code) {
        if self.state != SendState::Complete {
            self.stream.reset(code);
            self.state = SendState::Complete;
        }
    }

    /// Record successful FIN delivery so dropping this writer no longer cancels it.
    pub(crate) fn mark_acknowledged(&mut self) {
        self.state = SendState::Complete;
    }

    pub(crate) fn acknowledged(
        &self,
    ) -> impl Future<Output = Result<(), Error>> + Send + Sync + 'static {
        self.stream.acknowledged()
    }

    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream,
            chunks: [Bytes::new(), Bytes::new()],
            state: SendState::Open,
            cancel_code: Code::H3_REQUEST_CANCELLED,
            data_header: None,
            priority: None,
        }
    }

    pub(crate) fn with_prefix(stream: S, prefix: Bytes) -> Self {
        Self {
            stream,
            chunks: [prefix, Bytes::new()],
            state: SendState::Open,
            cancel_code: Code::H3_REQUEST_CANCELLED,
            data_header: None,
            priority: None,
        }
    }

    pub(crate) fn is_drained(&self) -> bool {
        self.chunks.iter().all(Bytes::is_empty)
    }

    pub(crate) fn priority(&mut self, priority: i32) -> Result<(), Error> {
        if self.priority != Some(priority) {
            self.stream.priority(priority)?;
            self.priority = Some(priority);
        }
        Ok(())
    }

    pub(crate) fn queue(&mut self, ty: FrameType, payload: Bytes) -> Result<(), Error> {
        if self.state != SendState::Open || self.chunks.iter().any(|chunk| !chunk.is_empty()) {
            return Err(Error::stream(
                Code::H3_INTERNAL_ERROR,
                "write must be drained before queuing a frame",
            ));
        }
        let header = if let Some((length, header)) = &self.data_header
            && ty == FrameType::DATA
            && *length == payload.len()
        {
            header.clone()
        } else {
            let mut header = BytesMut::with_capacity(16);
            FrameHeader::new(ty, payload.len() as u64)
                .encode(&mut header)
                .ok_or(Error::stream(
                    Code::H3_INTERNAL_ERROR,
                    "frame exceeds QUIC integer range",
                ))?;
            let header = header.freeze();
            if ty == FrameType::DATA {
                self.data_header = Some((payload.len(), header.clone()));
            }
            header
        };
        self.chunks = [header, payload];
        Ok(())
    }

    pub(crate) fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        // Bound work even if a fake/transport accepts only one byte per call.
        for _ in 0..super::cooperative::OPERATIONS_PER_QUANTUM {
            if self.chunks.iter().all(Bytes::is_empty) {
                return Poll::Ready(Ok(()));
            }
            ready!(self.stream.poll_chunks(cx, &mut self.chunks))?;
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    pub(crate) fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        ready!(self.poll_flush(cx))?;
        if self.state == SendState::Open {
            self.stream.finish()?;
            self.state = SendState::FinQueued;
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: SendStream> Drop for Writer<S> {
    fn drop(&mut self) {
        if self.state != SendState::Complete {
            self.stream.reset(self.cancel_code);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use std::sync::Arc;

    #[derive(Default)]
    struct State {
        wire: Vec<u8>,
        reset: Option<Code>,
        finished: bool,
        pending: bool,
        always_ready: bool,
        priority_updates: usize,
    }
    struct Fake(Arc<Mutex<State>>);
    impl SendStream for Fake {
        fn acknowledged(&self) -> impl Future<Output = Result<(), Error>> + Send + Sync + 'static {
            std::future::pending()
        }

        fn priority(&mut self, _priority: i32) -> Result<(), Error> {
            self.0.lock().priority_updates += 1;
            Ok(())
        }
        fn poll_chunks(
            &mut self,
            cx: &mut Context<'_>,
            chunks: &mut [Bytes],
        ) -> Poll<Result<(), Error>> {
            let mut state = self.0.lock();
            state.pending = !state.pending;
            if state.pending && !state.always_ready {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if let Some(chunk) = chunks.iter_mut().find(|c| !c.is_empty()) {
                state.wire.extend_from_slice(&chunk.split_to(1));
            }
            Poll::Ready(Ok(()))
        }
        fn finish(&mut self) -> Result<(), Error> {
            self.0.lock().finished = true;
            Ok(())
        }
        fn reset(&mut self, code: Code) {
            self.0.lock().reset = Some(code);
        }
    }

    #[test]
    fn unchanged_priority_does_not_touch_transport_per_frame() {
        let state = Arc::new(Mutex::new(State::default()));
        let mut writer = Writer::new(Fake(state.clone()));
        for _ in 0..100 {
            writer.priority(4).unwrap();
        }
        assert_eq!(state.lock().priority_updates, 1);
        writer.priority(5).unwrap();
        assert_eq!(state.lock().priority_updates, 2);
    }

    #[test]
    fn tiny_immediately_ready_writes_are_bounded_and_retain_payload() {
        let state = Arc::new(Mutex::new(State {
            always_ready: true,
            ..State::default()
        }));
        let mut writer = Writer::new(Fake(state.clone()));
        let payload = Bytes::from(vec![0xaa; 128]);
        let payload_start = payload.as_ptr();
        writer.queue(FrameType::DATA, payload).unwrap();
        let header_len = writer.chunks[0].len();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(writer.poll_flush(&mut cx).is_pending());
        let sent = state.lock().wire.len();
        assert_eq!(sent, crate::h3::cooperative::OPERATIONS_PER_QUANTUM);
        assert_eq!(
            writer.chunks[1].as_ptr(),
            payload_start.wrapping_add(sent - header_len)
        );
        while writer.poll_finish(&mut cx).is_pending() {}
        assert_eq!(state.lock().wire.len(), header_len + 128);
    }

    #[test]
    fn equal_data_frames_reuse_header_and_payload_storage() {
        let state = Arc::new(Mutex::new(State::default()));
        let mut writer = Writer::new(Fake(state));
        let data = Bytes::from_static(b"payload");
        writer.queue(FrameType::DATA, data.clone()).unwrap();
        let header = writer.chunks[0].clone();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        for _ in 0..64 {
            while writer.poll_flush(&mut cx).is_pending() {}
            writer.queue(FrameType::DATA, data.clone()).unwrap();
            assert_eq!(writer.chunks[0].as_ptr(), header.as_ptr());
            assert_eq!(writer.chunks[1].as_ptr(), data.as_ptr());
        }
    }

    #[test]
    fn fragmented_writes_resume_and_finish_after_payload() {
        let state = Arc::new(Mutex::new(State::default()));
        let mut writer = Writer::new(Fake(state.clone()));
        let data = Bytes::from_static(b"payload");
        writer.queue(FrameType::DATA, data.clone()).unwrap();
        assert_eq!(writer.chunks[1].as_ptr(), data.as_ptr());
        let mut cx = Context::from_waker(std::task::Waker::noop());
        while writer.poll_finish(&mut cx).is_pending() {}
        writer.mark_acknowledged();
        drop(writer);
        let state = state.lock();
        assert_eq!(state.wire, b"\x00\x07payload");
        assert!(state.finished);
        assert!(state.reset.is_none());
    }

    #[test]
    fn dropping_unacknowledged_fin_resets_the_stream() {
        let state = Arc::new(Mutex::new(State::default()));
        let mut writer = Writer::new(Fake(state.clone()));
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(writer.poll_finish(&mut cx), Poll::Ready(Ok(()))));
        assert!(state.lock().finished);
        drop(writer);
        assert_eq!(state.lock().reset, Some(Code::H3_REQUEST_CANCELLED));
    }

    #[test]
    fn cancellation_at_every_write_offset_resets_instead_of_fin() {
        for offset in 0..10 {
            let state = Arc::new(Mutex::new(State::default()));
            let mut writer = Writer::new(Fake(state.clone()));
            writer
                .queue(FrameType::DATA, Bytes::from_static(b"payload"))
                .unwrap();
            let mut cx = Context::from_waker(std::task::Waker::noop());
            while state.lock().wire.len() < offset {
                _ = writer.poll_flush(&mut cx);
            }
            drop(writer);
            let state = state.lock();
            assert_eq!(state.reset, Some(Code::H3_REQUEST_CANCELLED));
            assert!(!state.finished);
            assert_eq!(state.wire, b"\x00\x07payload"[..offset]);
        }
    }
}
