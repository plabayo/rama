//! Gates that pace the streams of a multiplexed connection, such as a QUIC one, and admit
//! or drop its datagrams.
//!
//! A connection that carries many streams opens a [`StreamGate`] per stream direction
//! through the [`StreamGates`] added to it, and moves that direction's bytes only as the
//! gate admits them; it asks the [`DatagramGates`] added to it about each datagram. The
//! throttle layers throttle such connections with gates.
//!
//! A gate is consulted only when there is data to read or the stream may still send; a
//! write blocked by flow control settles zero. It is never called while the transport holds
//! a lock, and it is dropped with the handle of its stream direction.
//!
//! Only QUIC opens gates today. HTTP/2 could open them per stream too, should it need
//! per-stream budgets: when sending in `PipeToSendStream` (rama-http-core `proto/h2/mod.rs`),
//! when receiving where `Incoming` releases window capacity (rama-http-core `body/incoming.rs`).

use core::task::{Context, Poll};

/// Paces one direction of one stream.
pub trait StreamGate: Send + Sync + 'static {
    /// Wait until up to `want` (more than zero) bytes may move; yields between one and
    /// `want` of them.
    ///
    /// A pending gate arranges its own wake-up and must admit eventually: data it holds
    /// back stays unread until it does, even past a lost connection. The stream also wakes
    /// the task on its own events, such as a reset.
    fn poll_admit(&mut self, cx: &mut Context<'_>, want: u64) -> Poll<u64>;

    /// `used` of the bytes the last admission yielded moved, at most all of them.
    ///
    /// Called once per admission, in the same poll: zero when nothing moved.
    fn settle(&mut self, used: u64);
}

/// Opens the gates of a multiplexed connection's streams.
pub trait StreamGates: Send + Sync + 'static {
    /// The gate of one stream direction.
    type Gate: StreamGate;

    /// The gate for `stream`, or `None` to leave it ungated.
    fn open(&self, stream: GatedStream) -> Option<Self::Gate>;
}

/// The stream direction a gate is opened for.
#[derive(Debug, Clone, Copy)]
pub struct GatedStream {
    /// The transport's stream identifier.
    ///
    /// Unique among the live streams of a connection, except that a stream the peer
    /// rejected as early data gives its identifier to the stream opened in its place.
    pub id: u64,
    /// Which side of the stream the gate paces.
    pub direction: GateDirection,
    /// Whether the stream carries data both ways.
    pub bidirectional: bool,
    /// Who opened the stream.
    pub initiator: Initiator,
}

/// Which side of a stream a gate paces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDirection {
    /// What the peer sends and the application reads.
    Read,
    /// What the application writes towards the peer.
    Write,
}

/// Which end of a connection opened a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Initiator {
    /// This end.
    Local,
    /// The peer.
    Peer,
}

/// Admits or drops the datagrams of a multiplexed connection, such as QUIC DATAGRAM frames.
///
/// Datagrams are unreliable, so a gate never makes one wait: a refused datagram is dropped,
/// and the connection counts it. A gate is never called while the transport holds a lock,
/// and only for a datagram the transport would otherwise deliver or accept for sending.
pub trait DatagramGates: Send + Sync + 'static {
    /// Whether a datagram of `len` bytes may move in `direction`: received from the peer
    /// ([`GateDirection::Read`]) or sent to it ([`GateDirection::Write`]).
    fn admit(&self, direction: GateDirection, len: usize) -> bool;
}
