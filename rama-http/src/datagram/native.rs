//! The replaceable contract for unreliable HTTP Datagram delivery.

use rama_core::{bytes::Bytes, extensions::Extension};
use std::{
    fmt,
    sync::Arc,
    task::{Context, Poll},
};

/// How a native send behaves when the transport's datagram buffer is full.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NativeSendPolicy {
    /// Always queue the new datagram; older unsent datagrams may be discarded.
    #[default]
    DropOldest,
    /// Keep queued datagrams and report [`NativeSendError::Full`].
    RejectWhenFull,
}

/// A native datagram could not be handed to the transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeSendError {
    /// Larger than the current maximum payload, which can shrink with the path MTU.
    TooLarge {
        /// The maximum payload accepted when the send was attempted.
        max: usize,
    },
    /// No room in the send buffer ([`NativeSendPolicy::RejectWhenFull`]).
    Full,
    /// Not negotiated (yet). Reliable delivery on the data stream remains possible.
    Unavailable,
    /// The association's send side is closed (finished, reset, stopped by the peer) or its
    /// connection is gone. No datagram may follow (RFC 9297 §2.1).
    Closed,
}

impl fmt::Display for NativeSendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { max } => write!(f, "datagram exceeds maximum payload of {max} bytes"),
            Self::Full => f.write_str("datagram send buffer full"),
            Self::Unavailable => f.write_str("native datagrams unavailable"),
            Self::Closed => f.write_str("datagram transport closed"),
        }
    }
}

impl std::error::Error for NativeSendError {}

/// The receive side of a native association ended abnormally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeRecvError {
    /// The peer reset the request stream with this application error code.
    Reset(u64),
    /// This endpoint aborted the request stream with this application error code.
    Aborted(u64),
    /// The connection failed.
    Lost,
}

impl fmt::Display for NativeRecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reset(code) => write!(f, "request stream reset by peer (code {code:#x})"),
            Self::Aborted(code) => write!(f, "request stream aborted locally (code {code:#x})"),
            Self::Lost => f.write_str("datagram connection lost"),
        }
    }
}

impl std::error::Error for NativeRecvError {}

/// How peer violations of HTTP Datagram rules that do not affect framing are handled.
///
/// Rama is proxy-first: by default it drops and counts the offending item, so traffic
/// between peers that tolerate each other keeps flowing. [`Reject`](Self::Reject) applies
/// the RFC 9297 reaction instead.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ViolationPolicy {
    /// Drop the offending item, count it and keep the exchange.
    #[default]
    Ignore,
    /// Apply the RFC 9297 error.
    Reject,
}

/// Unreliable delivery of HTTP Datagrams associated with one request, such as
/// HTTP/3 QUIC DATAGRAM frames (RFC 9297 §2.1).
///
/// A transport publishes its implementation as a [`NativeDatagrams`] extension on the
/// upgraded I/O. Receiving is demultiplexed by the transport; one association has at most
/// one consumer. Enqueueing a datagram never implies delivery.
pub trait NativeDatagramChannel: Send + Sync + 'static {
    /// The largest payload that can currently be sent, or `None` while native datagrams are
    /// not negotiated. A snapshot: [`send`](Self::send) decides.
    fn max_payload_size(&self) -> Option<usize>;

    /// Hand a datagram to the transport without waiting.
    ///
    /// Eligibility follows the transport's send state of the request stream, whoever holds
    /// the channel: once it is closed this returns [`NativeSendError::Closed`].
    fn send(&self, payload: Bytes, policy: NativeSendPolicy) -> Result<(), NativeSendError>;

    /// Receive the next datagram. `Ok(None)` once the request's receive side ended cleanly.
    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, NativeRecvError>>;

    /// Received datagrams discarded: this association's queue or the connection's buffer
    /// budget was full, or they arrived after its receive side closed.
    fn dropped(&self) -> u64;

    /// The consumer is gone: discard queued datagrams and drop (count) later ones. The
    /// request stream itself is unaffected.
    fn release_recv(&self) {}
}

/// A request's native datagram carrier, published on the upgraded I/O's extensions.
#[derive(Clone, Extension)]
#[extension(tags(http))]
pub struct NativeDatagrams(Arc<dyn NativeDatagramChannel>);

impl NativeDatagrams {
    /// Publish a transport's native datagram implementation.
    pub fn new(channel: impl NativeDatagramChannel) -> Self {
        Self(Arc::new(channel))
    }

    /// The channel.
    #[must_use]
    pub fn channel(&self) -> &dyn NativeDatagramChannel {
        self.0.as_ref()
    }
}

impl fmt::Debug for NativeDatagrams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeDatagrams")
            .field("max_payload_size", &self.0.max_payload_size())
            .field("dropped", &self.0.dropped())
            .finish()
    }
}
