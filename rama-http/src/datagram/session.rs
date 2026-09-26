//! One request-associated HTTP Datagram session over any HTTP version (RFC 9297).

use super::{
    capsule::{CapsuleConfig, CapsuleDecoder, CapsuleError, CapsuleEvent},
    native::{NativeDatagrams, NativeRecvError, NativeSendError, NativeSendPolicy},
};
use crate::io::upgrade::{OnMalformedMessage, Upgraded};
use parking_lot::Mutex;
use rama_core::{
    bytes::{Buf as _, Bytes, BytesMut},
    extensions::ExtensionsRef,
    stream::io::poll_read_buf,
};
use rama_http_types::proto::capsule::{CapsuleHeader, CapsuleType, InvalidCapsule};
use rama_utils::octets::kib;
use std::{
    fmt, io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker, ready},
};
use tokio::io::{AsyncRead, AsyncWrite};

/// Configuration of an [`HttpDatagramSession`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionConfig {
    /// Capsule limits and the control capsule types the application handles.
    pub capsules: CapsuleConfig,
    /// Native send behaviour when the transport's buffer is full.
    pub native_send: NativeSendPolicy,
    /// Largest read from the data stream at once.
    pub read_chunk_size: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            capsules: CapsuleConfig::default(),
            native_send: NativeSendPolicy::default(),
            read_chunk_size: kib(16),
        }
    }
}

/// How an HTTP Datagram travelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatagramTransport {
    /// A native unreliable datagram (HTTP/3 QUIC DATAGRAM). It may be lost or reordered.
    Native,
    /// A DATAGRAM capsule on the reliable, ordered data stream.
    Capsule,
}

/// An event received on a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    /// An HTTP Datagram payload.
    Datagram {
        /// The payload, possibly empty.
        payload: Bytes,
        /// How it arrived.
        transport: DatagramTransport,
    },
    /// A control capsule of a type listed in [`CapsuleConfig::capsule_types`].
    Capsule {
        /// The capsule type.
        ty: CapsuleType,
        /// The complete value.
        value: Bytes,
    },
    /// The header of an unknown capsule being forwarded
    /// ([`super::capsule::UnknownCapsules::Forward`]).
    UnknownCapsule(CapsuleHeader),
    /// A chunk of the current forwarded capsule value.
    UnknownCapsuleData(Bytes),
}

/// A session operation failed.
///
/// Rejections leave the session unchanged and usable: [`CapsuleInProgress`],
/// [`CapsuleNotStarted`], [`CapsuleLengthMismatch`], [`InvalidCapsule`] and
/// [`Native`] with [`NativeSendError::TooLarge`], [`NativeSendError::Full`] or
/// [`NativeSendError::Unavailable`]. Every other error is terminal for its direction and
/// returned again, without I/O, by later operations on it.
///
/// [`CapsuleInProgress`]: Self::CapsuleInProgress
/// [`CapsuleNotStarted`]: Self::CapsuleNotStarted
/// [`CapsuleLengthMismatch`]: Self::CapsuleLengthMismatch
/// [`InvalidCapsule`]: Self::InvalidCapsule
/// [`Native`]: Self::Native
#[derive(Debug)]
pub enum SessionError {
    /// The peer violated the Capsule Protocol; the stream was aborted as malformed.
    Malformed(CapsuleError),
    /// A native datagram was not sent. [`NativeSendError::Closed`] is terminal.
    Native(NativeSendError),
    /// The native carrier's receive side failed; terminal for receiving.
    NativeRecv(NativeRecvError),
    /// A capsule exceeds the variable-length integer range.
    InvalidCapsule,
    /// A streamed capsule still expects value bytes; nothing else may use the data stream.
    CapsuleInProgress,
    /// Capsule value data without a started capsule.
    CapsuleNotStarted,
    /// The chunk exceeds the declared length of the streamed capsule.
    CapsuleLengthMismatch,
    /// [`SessionSender::close`] already committed the end of the data stream.
    SendClosed,
    /// The data stream failed.
    Io(io::Error),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(error) => write!(f, "malformed capsule stream: {error}"),
            Self::Native(error) => write!(f, "native datagram: {error}"),
            Self::NativeRecv(error) => write!(f, "native datagram receive: {error}"),
            Self::InvalidCapsule => f.write_str("capsule exceeds the varint range"),
            Self::CapsuleInProgress => f.write_str("a streamed capsule is still in progress"),
            Self::CapsuleNotStarted => f.write_str("capsule data without a started capsule"),
            Self::CapsuleLengthMismatch => f.write_str("capsule data exceeds its declared length"),
            Self::SendClosed => f.write_str("session already closed for sending"),
            Self::Io(error) => write!(f, "data stream: {error}"),
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Malformed(error) => Some(error),
            Self::Native(error) => Some(error),
            Self::NativeRecv(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<InvalidCapsule> for SessionError {
    fn from(_: InvalidCapsule) -> Self {
        Self::InvalidCapsule
    }
}

/// An HTTP Datagram and Capsule Protocol session on an established request.
///
/// Built from the upgraded I/O of a successful HTTP/1.x upgrade (`101`) or HTTP/2 and
/// HTTP/3 Extended CONNECT (`2xx`); the protocol logic above it needs no version switch.
/// Datagrams use a [`NativeDatagrams`] carrier when the I/O publishes one (HTTP/3 with
/// negotiated QUIC DATAGRAM) and DATAGRAM capsules otherwise. Control capsules always use
/// the reliable data stream.
///
/// # Cancellation
///
/// A send accepts its value when a poll finds no earlier accepted bytes left to write; from
/// then on the session owns it, and dropping the future leaves it to be written by the next
/// send or [`close`](Self::close). A future dropped before that point sent nothing. Capsule
/// headers are never interleaved. [`recv`](Self::recv) is cancel safe.
///
/// Dropping the sender while a capsule is partially on the wire, or receiving a malformed
/// data stream, aborts the carrier: through its [`OnMalformedMessage`] hook when published,
/// and by closing the I/O in any case, even while the other half is retained. The peer never
/// sees a clean end mid-value.
pub struct HttpDatagramSession<T = Upgraded> {
    sender: SessionSender<T>,
    receiver: SessionReceiver<T>,
}

impl<T> fmt::Debug for HttpDatagramSession<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpDatagramSession")
            .field("native", &self.sender.native)
            .finish_non_exhaustive()
    }
}

impl<T> HttpDatagramSession<T>
where
    T: AsyncRead + AsyncWrite + ExtensionsRef,
{
    /// A session with the default configuration.
    pub fn new(io: T) -> Self {
        Self::with_config(io, SessionConfig::default())
    }

    /// A session with `config`.
    pub fn with_config(io: T, config: SessionConfig) -> Self {
        let native = io.extensions().get_ref::<NativeDatagrams>().cloned();
        let malformed = io.extensions().get_ref::<OnMalformedMessage>().cloned();
        let io = SharedIo::new(io, malformed);
        Self {
            sender: SessionSender {
                io: io.clone(),
                native: native.clone(),
                policy: config.native_send,
                pending: [Bytes::new(), Bytes::new()],
                scratch: BytesMut::new(),
                remainder: 0,
                on_wire: false,
                state: SendState::Open,
            },
            receiver: SessionReceiver {
                io,
                native,
                decoder: CapsuleDecoder::new(config.capsules),
                buf: BytesMut::new(),
                read_chunk_size: config.read_chunk_size.max(1),
                native_first: true,
                native_open: true,
                end: None,
            },
        }
    }

    /// The negotiated native carrier, if the transport offers one.
    #[must_use]
    pub fn native(&self) -> Option<&NativeDatagrams> {
        self.sender.native.as_ref()
    }

    /// Send an HTTP Datagram. See [`SessionSender::send_datagram`].
    pub async fn send_datagram(
        &mut self,
        payload: Bytes,
    ) -> Result<DatagramTransport, SessionError> {
        self.sender.send_datagram(payload).await
    }

    /// Send a capsule reliably. See [`SessionSender::send_capsule`].
    pub async fn send_capsule(
        &mut self,
        ty: CapsuleType,
        value: Bytes,
    ) -> Result<(), SessionError> {
        self.sender.send_capsule(ty, value).await
    }

    /// Begin a capsule whose value follows in chunks. See [`SessionSender::start_capsule`].
    pub async fn start_capsule(&mut self, header: CapsuleHeader) -> Result<(), SessionError> {
        self.sender.start_capsule(header).await
    }

    /// Append value bytes to the started capsule. See [`SessionSender::send_capsule_data`].
    pub async fn send_capsule_data(&mut self, chunk: Bytes) -> Result<(), SessionError> {
        self.sender.send_capsule_data(chunk).await
    }

    /// Receive the next event. See [`SessionReceiver::recv`].
    pub async fn recv(&mut self) -> Result<Option<SessionEvent>, SessionError> {
        self.receiver.recv().await
    }

    /// Finish sending. See [`SessionSender::close`].
    pub async fn close(&mut self) -> Result<(), SessionError> {
        self.sender.close().await
    }

    /// Split into independently usable halves, for example for a bidirectional relay.
    #[must_use]
    pub fn split(self) -> (SessionSender<T>, SessionReceiver<T>) {
        (self.sender, self.receiver)
    }
}

#[derive(Debug)]
enum SendState {
    Open,
    /// The end of the data stream is committed.
    Closing,
    /// The data stream failed; later operations report the same kind.
    Failed(io::ErrorKind),
    /// The native association's send side closed, and with it the request stream's.
    NativeClosed,
}

/// The carrier I/O shared by both halves. Either half can abort it for both: the carrier's
/// [`OnMalformedMessage`] hook runs (once per session) and dropping the I/O closes
/// (HTTP/1.1) or resets (HTTP/2, HTTP/3) the carrier. Both halves observe the abort before
/// returning buffered events, and a half already waiting on the I/O is woken.
struct SharedIo<T>(Arc<IoShared<T>>);

struct IoShared<T> {
    state: Mutex<IoState<T>>,
    aborted: AtomicBool,
}

struct IoState<T> {
    io: Option<Pin<Box<T>>>,
    // The last task waiting on each direction, registered under the poll's lock.
    wakers: [Option<Waker>; 2],
    malformed: Option<OnMalformedMessage>,
}

#[derive(Clone, Copy)]
enum Half {
    Read = 0,
    Write = 1,
}

impl<T> Clone for SharedIo<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> SharedIo<T> {
    fn new(io: T, malformed: Option<OnMalformedMessage>) -> Self {
        Self(Arc::new(IoShared {
            state: Mutex::new(IoState {
                io: Some(Box::pin(io)),
                wakers: [None, None],
                malformed,
            }),
            aborted: AtomicBool::new(false),
        }))
    }

    fn is_aborted(&self) -> bool {
        self.0.aborted.load(Ordering::Acquire)
    }

    /// Abort the carrier for both halves; later calls do nothing.
    fn abort(&self) {
        let (io, wakers, malformed) = {
            let mut state = self.0.state.lock();
            self.0.aborted.store(true, Ordering::Release);
            (
                state.io.take(),
                std::mem::take(&mut state.wakers),
                state.malformed.take(),
            )
        };
        // The hook picks the abort code before dropping the I/O would end the stream.
        if let Some(malformed) = malformed {
            malformed.call();
        }
        drop(io);
        wakers.into_iter().flatten().for_each(Waker::wake);
    }

    fn with<R>(
        &self,
        half: Half,
        cx: &mut Context<'_>,
        poll: impl FnOnce(Pin<&mut T>, &mut Context<'_>) -> Poll<io::Result<R>>,
    ) -> Poll<io::Result<R>> {
        let mut state = self.0.state.lock();
        let IoState { io, wakers, .. } = &mut *state;
        let Some(io) = io.as_mut() else {
            return Poll::Ready(Err(aborted()));
        };
        let result = poll(io.as_mut(), cx);
        if result.is_pending() {
            let slot = &mut wakers[half as usize];
            if !slot
                .as_ref()
                .is_some_and(|waker| waker.will_wake(cx.waker()))
            {
                *slot = Some(cx.waker().clone());
            }
        }
        result
    }
}

fn aborted() -> io::Error {
    io::ErrorKind::ConnectionAborted.into()
}

/// The sending half of an [`HttpDatagramSession`].
pub struct SessionSender<T> {
    io: SharedIo<T>,
    native: Option<NativeDatagrams>,
    policy: NativeSendPolicy,
    // Accepted bytes not yet written: they stay owned here, so a cancelled send never
    // truncates a capsule.
    pending: [Bytes; 2],
    scratch: BytesMut,
    // Declared value bytes of a streamed capsule the application has not supplied yet.
    remainder: u64,
    // Part of an unfinished capsule reached the carrier.
    on_wire: bool,
    state: SendState,
}

impl<T> fmt::Debug for SessionSender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionSender")
            .field("native", &self.native)
            .field("policy", &self.policy)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl<T> Drop for SessionSender<T> {
    fn drop(&mut self) {
        // The peer must not see a clean end of stream in the middle of a capsule value.
        if self.on_wire {
            self.io.abort();
        }
    }
}

impl<T: AsyncWrite> SessionSender<T> {
    /// Send an HTTP Datagram.
    ///
    /// With a negotiated native carrier the datagram is handed to it without waiting and may
    /// be lost; a payload above the current native maximum fails with
    /// [`NativeSendError::TooLarge`], and a closed association with
    /// [`NativeSendError::Closed`], rather than silently switching to reliable delivery
    /// (RFC 9297 §3.5). Otherwise it is written as a DATAGRAM capsule, waiting for
    /// data-stream flow control.
    pub async fn send_datagram(
        &mut self,
        payload: Bytes,
    ) -> Result<DatagramTransport, SessionError> {
        self.check_open()?;
        if let Some(native) = &self.native
            && let Some(max) = native.channel().max_payload_size()
        {
            if payload.len() > max {
                return Err(SessionError::Native(NativeSendError::TooLarge { max }));
            }
            match native.channel().send(payload.clone(), self.policy) {
                Ok(()) => return Ok(DatagramTransport::Native),
                // Negotiation raced away: reliable delivery is still correct.
                Err(NativeSendError::Unavailable) => (),
                Err(NativeSendError::Closed) => {
                    self.state = SendState::NativeClosed;
                    return Err(SessionError::Native(NativeSendError::Closed));
                }
                Err(error) => return Err(SessionError::Native(error)),
            }
        }
        self.send_capsule(CapsuleType::DATAGRAM, payload).await?;
        Ok(DatagramTransport::Capsule)
    }

    /// Send a complete capsule on the reliable data stream and flush it.
    pub async fn send_capsule(
        &mut self,
        ty: CapsuleType,
        value: Bytes,
    ) -> Result<(), SessionError> {
        self.check_idle()?;
        let header = CapsuleHeader::new(ty, value.len() as u64)?;
        let mut value = Some(value);
        std::future::poll_fn(|cx| {
            ready!(self.poll_write_pending(cx))?;
            if let Some(value) = value.take() {
                self.accept_header(header);
                self.pending[1] = value;
            }
            self.poll_write_and_flush(cx)
        })
        .await
    }

    /// Begin forwarding one capsule whose value arrives in chunks through
    /// [`send_capsule_data`](Self::send_capsule_data).
    ///
    /// Until the declared length is supplied, other capsules, capsule-carried datagrams and
    /// [`close`](Self::close) are rejected with [`SessionError::CapsuleInProgress`]; native
    /// datagrams are unaffected. Forwarding preserves type, length and value; integers are
    /// re-encoded minimally.
    pub async fn start_capsule(&mut self, header: CapsuleHeader) -> Result<(), SessionError> {
        self.check_idle()?;
        let mut header = Some(header);
        std::future::poll_fn(|cx| {
            ready!(self.poll_write_pending(cx))?;
            if let Some(header) = header.take() {
                self.accept_header(header);
                self.remainder = header.length.into_inner();
            }
            self.poll_write_and_flush(cx)
        })
        .await
    }

    /// Append value bytes to the capsule begun by [`start_capsule`](Self::start_capsule).
    ///
    /// A chunk beyond the declared length is rejected with
    /// [`SessionError::CapsuleLengthMismatch`] and the capsule stays open.
    pub async fn send_capsule_data(&mut self, chunk: Bytes) -> Result<(), SessionError> {
        self.check_open()?;
        if self.remainder == 0 {
            return Err(SessionError::CapsuleNotStarted);
        }
        if chunk.len() as u64 > self.remainder {
            return Err(SessionError::CapsuleLengthMismatch);
        }
        let mut chunk = Some(chunk);
        std::future::poll_fn(|cx| {
            ready!(self.poll_write_pending(cx))?;
            if let Some(chunk) = chunk.take() {
                self.remainder -= chunk.len() as u64;
                self.pending[1] = chunk;
            }
            self.poll_write_and_flush(cx)
        })
        .await
    }

    /// Write any accepted bytes, then finish the data stream cleanly.
    ///
    /// Only the local direction ends; receiving continues until the peer ends its own. Once
    /// the end is committed, sends return [`SessionError::SendClosed`] and calling `close`
    /// again resumes finishing the stream.
    pub async fn close(&mut self) -> Result<(), SessionError> {
        std::future::poll_fn(|cx| {
            match self.state {
                SendState::Open => {
                    if self.remainder > 0 {
                        return Poll::Ready(Err(SessionError::CapsuleInProgress));
                    }
                    ready!(self.poll_write_pending(cx))?;
                    self.state = SendState::Closing;
                }
                SendState::Closing => (),
                SendState::Failed(_) | SendState::NativeClosed => {
                    return Poll::Ready(self.check_open());
                }
            }
            let result = ready!(self.io.with(Half::Write, cx, |io, cx| io.poll_shutdown(cx)));
            Poll::Ready(result.map_err(|error| self.failed(error)))
        })
        .await
    }

    fn check_open(&self) -> Result<(), SessionError> {
        if self.io.is_aborted() && matches!(self.state, SendState::Open | SendState::Closing) {
            return Err(SessionError::Io(aborted()));
        }
        match self.state {
            SendState::Open => Ok(()),
            SendState::Closing => Err(SessionError::SendClosed),
            SendState::Failed(kind) => Err(SessionError::Io(kind.into())),
            SendState::NativeClosed => Err(SessionError::Native(NativeSendError::Closed)),
        }
    }

    /// Open and not inside a streamed capsule.
    fn check_idle(&self) -> Result<(), SessionError> {
        self.check_open()?;
        if self.remainder > 0 {
            return Err(SessionError::CapsuleInProgress);
        }
        Ok(())
    }

    fn accept_header(&mut self, header: CapsuleHeader) {
        self.scratch.reserve(CapsuleHeader::MAX_SIZE);
        header.encode(&mut self.scratch);
        self.pending[0] = self.scratch.split().freeze();
    }

    fn poll_write_and_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SessionError>> {
        ready!(self.poll_write_pending(cx))?;
        let result = ready!(self.io.with(Half::Write, cx, |io, cx| io.poll_flush(cx)));
        Poll::Ready(result.map_err(|error| self.failed(error)))
    }

    fn poll_write_pending(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SessionError>> {
        self.check_open()?;
        for i in 0..self.pending.len() {
            while !self.pending[i].is_empty() {
                let chunk = &self.pending[i];
                let written = match ready!(
                    self.io
                        .with(Half::Write, cx, |io, cx| io.poll_write(cx, chunk))
                ) {
                    Ok(0) => {
                        return Poll::Ready(Err(self.failed(io::ErrorKind::WriteZero.into())));
                    }
                    Ok(written) => written,
                    Err(error) => return Poll::Ready(Err(self.failed(error))),
                };
                self.on_wire = true;
                self.pending[i].advance(written);
            }
        }
        if self.remainder == 0 {
            self.on_wire = false;
        }
        Poll::Ready(Ok(()))
    }

    fn failed(&mut self, error: io::Error) -> SessionError {
        self.state = SendState::Failed(error.kind());
        SessionError::Io(error)
    }
}

/// How the receiving direction ended.
#[derive(Clone, Copy, Debug)]
enum RecvEnd {
    Clean,
    Malformed(CapsuleError),
    Failed(io::ErrorKind),
    Native(NativeRecvError),
}

/// Reads and decoded skips a receive poll performs before yielding to other work.
const MAX_READS_PER_POLL: usize = 16;

/// The receiving half of an [`HttpDatagramSession`].
pub struct SessionReceiver<T> {
    io: SharedIo<T>,
    native: Option<NativeDatagrams>,
    decoder: CapsuleDecoder,
    buf: BytesMut,
    read_chunk_size: usize,
    native_first: bool,
    native_open: bool,
    end: Option<RecvEnd>,
}

impl<T> fmt::Debug for SessionReceiver<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionReceiver")
            .field("native", &self.native)
            .field("decoder", &self.decoder)
            .finish_non_exhaustive()
    }
}

impl<T> Drop for SessionReceiver<T> {
    fn drop(&mut self) {
        // Nobody consumes native datagrams any more; the transport stops queueing them.
        if let Some(native) = &self.native {
            native.channel().release_recv();
        }
    }
}

impl<T: AsyncRead> SessionReceiver<T> {
    /// Receive the next datagram or capsule.
    ///
    /// Native datagrams and the data stream are served fairly. `None` means the peer
    /// finished the data stream at a capsule boundary; later native datagrams are dropped
    /// (RFC 9297 §2.1). A Capsule Protocol violation aborts the stream as malformed. Errors
    /// are terminal and returned again by later calls.
    pub async fn recv(&mut self) -> Result<Option<SessionEvent>, SessionError> {
        std::future::poll_fn(|cx| self.poll_recv(cx)).await
    }

    /// Received datagrams discarded by this session or its native carrier.
    #[must_use]
    pub fn dropped_datagrams(&self) -> u64 {
        self.decoder.dropped_datagrams()
            + self
                .native
                .as_ref()
                .map_or(0, |native| native.channel().dropped())
    }

    /// Poll for the next event; see [`Self::recv`].
    pub fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<SessionEvent>, SessionError>> {
        if let Some(end) = self.end {
            return Poll::Ready(match end {
                RecvEnd::Clean => Ok(None),
                RecvEnd::Malformed(error) => Err(SessionError::Malformed(error)),
                RecvEnd::Failed(kind) => Err(SessionError::Io(kind.into())),
                RecvEnd::Native(error) => Err(SessionError::NativeRecv(error)),
            });
        }
        // An abort by either half discards events already decoded or queued.
        if self.io.is_aborted() {
            self.end = Some(RecvEnd::Failed(io::ErrorKind::ConnectionAborted));
            return Poll::Ready(Err(SessionError::Io(aborted())));
        }
        // Alternate sources per event so neither can starve the other.
        self.native_first = !self.native_first;
        if self.native_first
            && let Poll::Ready(Some(result)) = self.poll_native(cx)
        {
            return Poll::Ready(result.map(|payload| Some(native_event(payload))));
        }
        match self.poll_stream(cx) {
            Poll::Ready(result) => return Poll::Ready(result),
            Poll::Pending => (),
        }
        if !self.native_first
            && let Poll::Ready(Some(result)) = self.poll_native(cx)
        {
            return Poll::Ready(result.map(|payload| Some(native_event(payload))));
        }
        Poll::Pending
    }

    fn poll_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<SessionEvent>, SessionError>> {
        for _ in 0..MAX_READS_PER_POLL {
            match self.decoder.poll() {
                Ok(Some(event)) => return Poll::Ready(Ok(Some(event.into()))),
                Ok(None) => (),
                Err(error) => return Poll::Ready(Err(self.fail(error))),
            }
            self.buf.reserve(self.read_chunk_size);
            let buf = &mut self.buf;
            match ready!(
                self.io
                    .with(Half::Read, cx, |io, cx| poll_read_buf(io, cx, buf))
            ) {
                Ok(0) => {
                    return Poll::Ready(match self.decoder.finish() {
                        Ok(()) => {
                            self.end = Some(RecvEnd::Clean);
                            Ok(None)
                        }
                        Err(error) => Err(self.fail(error)),
                    });
                }
                Ok(_) => {
                    let chunk = self.buf.split().freeze();
                    if let Err(error) = self.decoder.feed(chunk) {
                        return Poll::Ready(Err(self.fail(error)));
                    }
                }
                Err(error) => {
                    self.end = Some(RecvEnd::Failed(error.kind()));
                    return Poll::Ready(Err(SessionError::Io(error)));
                }
            }
        }
        // Budget spent on reads and skips without an event: let other work run first.
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_native(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Bytes, SessionError>>> {
        let Some(native) = self.native.as_ref().filter(|_| self.native_open) else {
            return Poll::Ready(None);
        };
        match ready!(native.channel().poll_recv(cx)) {
            Ok(Some(payload)) => Poll::Ready(Some(Ok(payload))),
            Ok(None) => {
                self.native_open = false;
                Poll::Ready(None)
            }
            Err(error) => {
                self.end = Some(RecvEnd::Native(error));
                Poll::Ready(Some(Err(SessionError::NativeRecv(error))))
            }
        }
    }

    fn fail(&mut self, error: CapsuleError) -> SessionError {
        self.end = Some(RecvEnd::Malformed(error));
        // RFC 9297 §3.3: treat the message as malformed; the carrier chooses the abort code.
        self.io.abort();
        SessionError::Malformed(error)
    }
}

fn native_event(payload: Bytes) -> SessionEvent {
    SessionEvent::Datagram {
        payload,
        transport: DatagramTransport::Native,
    }
}

impl From<CapsuleEvent> for SessionEvent {
    fn from(event: CapsuleEvent) -> Self {
        match event {
            CapsuleEvent::Datagram(payload) => Self::Datagram {
                payload,
                transport: DatagramTransport::Capsule,
            },
            CapsuleEvent::Capsule { ty, value } => Self::Capsule { ty, value },
            CapsuleEvent::Unknown(header) => Self::UnknownCapsule(header),
            CapsuleEvent::UnknownData(data) => Self::UnknownCapsuleData(data),
        }
    }
}

#[cfg(test)]
mod tests;
