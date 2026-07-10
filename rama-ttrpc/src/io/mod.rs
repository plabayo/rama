use std::fmt;
use std::future::Future;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use prost::bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, split};
use tokio::pin;
use tokio::sync::mpsc::error::SendError as MpscSendError;
use tokio::sync::mpsc::{Receiver, Sender, UnboundedSender, channel, unbounded_channel};
use tokio::sync::oneshot;
use tokio::task::JoinSet;

/// Default number of inbound frames buffered per connection (and per stream) before the reader
/// applies backpressure. Each frame can be up to 4 MiB, so this bounds the memory a peer can pin
/// by sending faster than the application consumes; it is a smoothing buffer, not a hard cap on
/// concurrency.
pub(crate) const DEFAULT_MAX_BUFFERED_FRAMES: usize = 64;

use crate::id_pool::{IdPool, IdPoolGuard};
use crate::types::encoding::{Decodeable as _, Encodeable, InvalidInput};
use crate::types::flags::Flags;
use crate::types::frame::{Frame, StreamFrame, read_frame_bytes};
use crate::types::message::Message;
use crate::types::protos::{Data, Response, Status};

#[derive(Clone)]
pub(crate) struct MessageSender {
    tx: UnboundedSender<(Bytes, oneshot::Sender<()>)>,
}

pub(crate) struct MessageReceiver {
    // Bounded so the reader task applies backpressure (and in turn TCP backpressure to the peer)
    // instead of buffering frames without limit.
    rx: Receiver<Frame>,
    streams: IdPool<Sender<StreamFrame>>,
    capacity: usize,
}

pub(crate) struct MessageIo {
    pub tx: MessageSender,
    pub rx: MessageReceiver,
}

#[derive(Debug)]
pub enum SendError {
    Io(IoError),
    InvalidInput(InvalidInput),
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "Io error: {err}"),
            Self::InvalidInput(err) => write!(f, "Invalid input: {err}"),
        }
    }
}

impl std::error::Error for SendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::InvalidInput(err) => Some(err),
        }
    }
}

impl From<IoError> for SendError {
    fn from(err: IoError) -> Self {
        Self::Io(err)
    }
}

impl From<InvalidInput> for SendError {
    fn from(err: InvalidInput) -> Self {
        Self::InvalidInput(err)
    }
}

impl SendError {
    pub fn channel_closed() -> Self {
        Self::Io(IoError::new(IoErrorKind::BrokenPipe, "Channel closed"))
    }
}

pub struct SendResult(Result<oneshot::Receiver<()>, InvalidInput>);

impl Future for SendResult {
    type Output = Result<(), SendError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        match &mut self.0 {
            Err(err) => Poll::Ready(Err(err.clone().into())),
            Ok(receiver) => {
                pin!(receiver);
                match receiver.poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(result) => {
                        Poll::Ready(result.map_err(|_recv_err| SendError::channel_closed()))
                    }
                }
            }
        }
    }
}

impl MessageSender {
    pub(crate) fn new(
        tasks: &mut JoinSet<IoResult<()>>,
        mut writer: impl AsyncWrite + Unpin + Send + 'static,
    ) -> Self {
        let (tx, mut rx) = unbounded_channel();
        let sender = Self { tx };
        tasks.spawn(async move {
            while let Some((mut bytes, ch)) = rx.recv().await {
                // Errors writing bytes to the stream interrupt the loop
                writer.write_all_buf(&mut bytes).await?;
                _ = ch.send(());
            }
            Ok(())
        });
        sender
    }

    pub(crate) fn send<Msg: Message + Encodeable>(
        &self,
        id: u32,
        frame: impl Into<StreamFrame<Msg>>,
    ) -> SendResult {
        // Errors encoding the message do not interrupt the loop
        let rx = (move || {
            let frame = frame.into();
            let frame = frame.into_frame(id);
            let bytes = frame.encode_to_bytes()?;
            let (tx, rx) = oneshot::channel();
            _ = self.tx.send((bytes, tx));
            Ok::<_, InvalidInput>(rx)
        })();

        SendResult(rx)
    }

    fn stream(&self, id: u32) -> StreamSender {
        let tx = self.clone();
        StreamSender { id, tx }
    }
}

impl MessageReceiver {
    pub(crate) fn new(
        tasks: &mut JoinSet<IoResult<()>>,
        mut reader: impl AsyncRead + Send + Unpin + 'static,
        capacity: usize,
    ) -> Self {
        let (tx, rx) = channel(capacity);
        let streams = IdPool::default();
        let receiver = Self {
            rx,
            streams,
            capacity,
        };
        tasks.spawn(async move {
            loop {
                // Errors reading bytes from the stream interrupt the loop
                let bytes = read_frame_bytes(&mut reader).await?;

                // This is safe because RawFrame decode errors are delayed until the
                // message is accessed.
                // The only possible error is if `bytes` has less than `HEADER_LENGTH`
                // bytes, which is not possible here.
                #[expect(
                    clippy::unwrap_used,
                    reason = "read_frame_bytes always yields at least HEADER_LENGTH bytes; payload decode errors are deferred to message access"
                )]
                let frame = Frame::decode(bytes).unwrap();

                // A full channel parks the reader here, so we stop pulling from the socket and
                // let TCP backpressure the peer. An error means the receiver was dropped.
                if tx.send(frame).await.is_err() {
                    return Ok(());
                }
            }
        });
        receiver
    }

    pub(crate) async fn recv(&mut self) -> Option<(u32, StreamFrame)> {
        while let Some(frame) = self.rx.recv().await {
            let id = frame.id;
            let frame = frame.into_stream_frame();

            let Some(stream_tx) = self.streams.get(id).cloned() else {
                // there was no stream for this id, return the message
                return Some((id, frame));
            };

            // there was a stream for this id, so attempt to send it. A full per-stream buffer
            // parks here, which stops draining `rx` and backpressures the reader (and the peer).
            if let Err(MpscSendError(frame)) = stream_tx.send(frame).await {
                // the stream was already closed, return the message and let consumers handle it
                return Some((id, frame));
            }
        }
        None
    }

    fn stream(&mut self, id: u32) -> Option<StreamReceiver> {
        let (tx, rx) = channel(self.capacity);
        let guard = self.streams.claim(id, tx)?;
        let guard = Arc::new(guard);
        Some(StreamReceiver { rx, guard })
    }
}

impl MessageIo {
    pub(crate) fn new(
        tasks: &mut JoinSet<IoResult<()>>,
        connection: impl AsyncRead + AsyncWrite + Send + 'static,
        capacity: usize,
    ) -> Self {
        let (reader, writer) = split(connection);

        let rx = MessageReceiver::new(tasks, reader, capacity);
        let tx = MessageSender::new(tasks, writer);

        Self { tx, rx }
    }

    pub(crate) fn stream(&mut self, id: u32) -> Option<StreamIo> {
        let rx = self.rx.stream(id)?;
        let tx = self.tx.stream(rx.id());
        Some(StreamIo { tx, rx })
    }
}

#[derive(Clone)]
pub struct StreamSender {
    id: u32,
    tx: MessageSender,
}

pub struct StreamReceiver {
    rx: Receiver<StreamFrame>,
    guard: Arc<IdPoolGuard>,
}

pub struct StreamIo {
    pub tx: StreamSender,
    pub rx: StreamReceiver,
}

impl StreamSender {
    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn send<Msg: Message + Encodeable>(
        &self,
        frame: impl Into<StreamFrame<Msg>>,
    ) -> SendResult {
        self.tx.send(self.id, frame)
    }

    pub fn error(&self, status: Status) -> SendResult {
        self.send(Response::error(status))
    }

    pub fn respond<Payload: prost::Message + Default>(&self, payload: Payload) -> SendResult {
        self.send(Response::ok(payload))
    }

    pub fn data<Payload: prost::Message + Default>(&self, payload: Payload) -> SendResult {
        self.send(StreamFrame {
            flags: Flags::empty(),
            message: Data { payload },
        })
    }

    pub fn close_data(&self) -> SendResult {
        self.send(StreamFrame {
            flags: Flags::REMOTE_CLOSED | Flags::NO_DATA,
            message: Data { payload: () },
        })
    }
}

impl StreamReceiver {
    pub fn id(&self) -> u32 {
        self.guard.id()
    }

    pub fn guard(&self) -> Arc<IdPoolGuard> {
        self.guard.clone()
    }

    pub async fn recv(&mut self) -> Option<StreamFrame> {
        self.rx.recv().await
    }
}

impl StreamIo {
    pub fn id(&self) -> u32 {
        self.tx.id()
    }

    pub fn split(self) -> (StreamSender, StreamReceiver) {
        (self.tx, self.rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::frame::HEADER_LENGTH;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::ReadBuf;

    /// A reader that serves `remaining` fixed header-only frames (counting the bytes actually
    /// read from it) and then pends forever, an idle-after-burst peer.
    struct CountingReader {
        frame: Vec<u8>,
        pos: usize,
        remaining: usize,
        bytes_read: Arc<AtomicUsize>,
    }

    impl AsyncRead for CountingReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<IoResult<()>> {
            if self.remaining == 0 {
                return Poll::Pending;
            }
            let frame_len = self.frame.len();
            let n = {
                let avail = &self.frame[self.pos..];
                let n = avail.len().min(buf.remaining());
                buf.put_slice(&avail[..n]);
                n
            };
            self.bytes_read.fetch_add(n, Ordering::SeqCst);
            self.pos += n;
            if self.pos == frame_len {
                self.pos = 0;
                self.remaining -= 1;
            }
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn inbound_channel_applies_backpressure_without_a_consumer() {
        // A minimal header-only frame (data_length = 0), message-type byte set to Request.
        let mut frame = vec![0u8; HEADER_LENGTH];
        frame[8] = 1;
        let bytes_read = Arc::new(AtomicUsize::new(0));

        let reader = CountingReader {
            frame,
            pos: 0,
            remaining: 1000,
            bytes_read: Arc::clone(&bytes_read),
        };

        let mut tasks = JoinSet::new();
        let capacity = 4;
        // Hold the receiver so the channel stays open, but never call `recv`.
        let _receiver = MessageReceiver::new(&mut tasks, reader, capacity);

        // Give the reader task ample turns to fill the channel and park on the full send.
        for _ in 0..200 {
            tokio::task::yield_now().await;
        }

        let read = bytes_read.load(Ordering::SeqCst);
        assert!(read > 0, "reader never made progress");
        assert!(
            read <= (capacity + 1) * HEADER_LENGTH,
            "reader buffered {read} bytes without a consumer; backpressure not applied"
        );
    }
}
