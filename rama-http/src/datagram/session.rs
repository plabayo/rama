//! One request-associated HTTP Datagram session over any HTTP version (RFC 9297).

use super::{
    capsule::{CapsuleConfig, CapsuleDecoder, CapsuleError, CapsuleEvent},
    native::{NativeDatagrams, NativeSendError, NativeSendPolicy},
};
use crate::io::upgrade::{OnMalformedMessage, Upgraded};
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
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};

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
#[derive(Debug)]
pub enum SessionError {
    /// The peer violated the Capsule Protocol; the stream was aborted as malformed.
    Malformed(CapsuleError),
    /// A native datagram was not sent.
    Native(NativeSendError),
    /// A capsule exceeds the variable-length integer range.
    InvalidCapsule,
    /// The data stream failed.
    Io(io::Error),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(error) => write!(f, "malformed capsule stream: {error}"),
            Self::Native(error) => write!(f, "native datagram: {error}"),
            Self::InvalidCapsule => f.write_str("capsule exceeds the varint range"),
            Self::Io(error) => write!(f, "data stream: {error}"),
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Malformed(error) => Some(error),
            Self::Native(error) => Some(error),
            Self::InvalidCapsule => None,
            Self::Io(error) => Some(error),
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
        let (read, write) = tokio::io::split(io);
        Self {
            sender: SessionSender {
                io: write,
                native: native.clone(),
                policy: config.native_send,
                pending: [Bytes::new(), Bytes::new()],
                scratch: BytesMut::new(),
            },
            receiver: SessionReceiver {
                io: read,
                native,
                decoder: CapsuleDecoder::new(config.capsules),
                buf: BytesMut::new(),
                read_chunk_size: config.read_chunk_size.max(1),
                malformed,
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

/// The sending half of an [`HttpDatagramSession`].
pub struct SessionSender<T> {
    io: WriteHalf<T>,
    native: Option<NativeDatagrams>,
    policy: NativeSendPolicy,
    // A capsule stays owned here until written, so cancelling a send never truncates it.
    pending: [Bytes; 2],
    scratch: BytesMut,
}

impl<T> fmt::Debug for SessionSender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionSender")
            .field("native", &self.native)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl<T: AsyncWrite> SessionSender<T> {
    /// Send an HTTP Datagram.
    ///
    /// With a negotiated native carrier the datagram is handed to it without waiting and may
    /// be lost; a payload above the current native maximum fails with
    /// [`NativeSendError::TooLarge`] rather than silently switching to reliable delivery
    /// (RFC 9297 §3.5). Otherwise it is written as a DATAGRAM capsule, waiting for
    /// data-stream flow control.
    pub async fn send_datagram(
        &mut self,
        payload: Bytes,
    ) -> Result<DatagramTransport, SessionError> {
        if let Some(native) = &self.native
            && let Some(max) = native.channel().max_payload_size()
        {
            if payload.len() > max {
                return Err(SessionError::Native(NativeSendError::TooLarge { max }));
            }
            native
                .channel()
                .send(payload, self.policy)
                .map_err(SessionError::Native)?;
            return Ok(DatagramTransport::Native);
        }
        self.send_capsule(CapsuleType::DATAGRAM, payload).await?;
        Ok(DatagramTransport::Capsule)
    }

    /// Send a capsule on the reliable data stream and flush it.
    pub async fn send_capsule(
        &mut self,
        ty: CapsuleType,
        value: Bytes,
    ) -> Result<(), SessionError> {
        std::future::poll_fn(|cx| self.poll_write_pending(cx)).await?;
        let header = CapsuleHeader::new(ty, value.len() as u64)?;
        self.scratch.reserve(CapsuleHeader::MAX_SIZE);
        header.encode(&mut self.scratch);
        self.pending = [self.scratch.split().freeze(), value];
        std::future::poll_fn(|cx| self.poll_write_pending(cx)).await?;
        std::future::poll_fn(|cx| Pin::new(&mut self.io).poll_flush(cx))
            .await
            .map_err(SessionError::Io)
    }

    /// Flush any partially sent capsule and finish the data stream cleanly.
    pub async fn close(&mut self) -> Result<(), SessionError> {
        std::future::poll_fn(|cx| self.poll_write_pending(cx)).await?;
        std::future::poll_fn(|cx| Pin::new(&mut self.io).poll_shutdown(cx))
            .await
            .map_err(SessionError::Io)
    }

    fn poll_write_pending(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SessionError>> {
        for chunk in &mut self.pending {
            while !chunk.is_empty() {
                let written = ready!(Pin::new(&mut self.io).poll_write(cx, chunk))
                    .map_err(SessionError::Io)?;
                if written == 0 {
                    return Poll::Ready(Err(SessionError::Io(io::ErrorKind::WriteZero.into())));
                }
                chunk.advance(written);
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// The receiving half of an [`HttpDatagramSession`].
pub struct SessionReceiver<T> {
    io: ReadHalf<T>,
    native: Option<NativeDatagrams>,
    decoder: CapsuleDecoder,
    buf: BytesMut,
    read_chunk_size: usize,
    malformed: Option<OnMalformedMessage>,
    native_first: bool,
    native_open: bool,
    end: Option<Result<(), CapsuleError>>,
}

impl<T> fmt::Debug for SessionReceiver<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionReceiver")
            .field("native", &self.native)
            .field("decoder", &self.decoder)
            .finish_non_exhaustive()
    }
}

impl<T: AsyncRead> SessionReceiver<T> {
    /// Receive the next datagram or capsule.
    ///
    /// Native datagrams and the data stream are served fairly. `None` means the peer
    /// finished the data stream at a capsule boundary; later native datagrams are dropped
    /// (RFC 9297 §2.1). A Capsule Protocol violation aborts the stream as malformed.
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
            return Poll::Ready(end.map(|()| None).map_err(SessionError::Malformed));
        }
        // Alternate sources per event so neither can starve the other.
        self.native_first = !self.native_first;
        if self.native_first
            && let Poll::Ready(Some(payload)) = self.poll_native(cx)
        {
            return Poll::Ready(Ok(Some(native_event(payload))));
        }
        match self.poll_stream(cx) {
            Poll::Ready(result) => return Poll::Ready(result),
            Poll::Pending => (),
        }
        if !self.native_first
            && let Poll::Ready(Some(payload)) = self.poll_native(cx)
        {
            return Poll::Ready(Ok(Some(native_event(payload))));
        }
        Poll::Pending
    }

    fn poll_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<SessionEvent>, SessionError>> {
        loop {
            match self.decoder.poll() {
                Ok(Some(event)) => return Poll::Ready(Ok(Some(event.into()))),
                Ok(None) => (),
                Err(error) => return Poll::Ready(Err(self.fail(error))),
            }
            self.buf.reserve(self.read_chunk_size);
            match ready!(poll_read_buf(Pin::new(&mut self.io), cx, &mut self.buf)) {
                Ok(0) => {
                    let end = self.decoder.finish();
                    self.end = Some(end);
                    return Poll::Ready(match end {
                        Ok(()) => Ok(None),
                        Err(error) => Err(self.fail(error)),
                    });
                }
                Ok(_) => {
                    let chunk = self.buf.split().freeze();
                    if let Err(error) = self.decoder.feed(chunk) {
                        return Poll::Ready(Err(self.fail(error)));
                    }
                }
                Err(error) => return Poll::Ready(Err(SessionError::Io(error))),
            }
        }
    }

    fn poll_native(&mut self, cx: &mut Context<'_>) -> Poll<Option<Bytes>> {
        let Some(native) = self.native.as_ref().filter(|_| self.native_open) else {
            return Poll::Ready(None);
        };
        let result = native.channel().poll_recv(cx);
        if matches!(result, Poll::Ready(None)) {
            self.native_open = false;
        }
        result
    }

    fn fail(&mut self, error: CapsuleError) -> SessionError {
        self.end = Some(Err(error));
        // RFC 9297 §3.3: treat the message as malformed; the carrier chooses the abort code.
        if let Some(malformed) = self.malformed.take() {
            malformed.call();
        }
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
