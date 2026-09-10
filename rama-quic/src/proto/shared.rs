use std::{fmt, net::SocketAddr, ops::Range};

use rama_core::bytes::{Buf, BufMut, BytesMut};

use crate::proto::{Instant, MAX_CID_SIZE, ResetToken, coding::BufExt, packet::PartialDecode};

/// Events sent from an Endpoint to a Connection
#[derive(Debug)]
pub(crate) struct ConnectionEvent(pub(crate) ConnectionEventInner);

#[derive(Debug)]
pub(crate) enum ConnectionEventInner {
    /// A datagram has been received for the Connection
    Datagram(DatagramConnectionEvent),
    /// New connection identifiers have been issued for the Connection
    NewIdentifiers(Vec<IssuedCid>, Instant),
    /// The route a stateless reset for this identifier at this address would arrive by is now
    /// installed, so a datagram carrying that identifier may go to that address. The last field
    /// names the installation, and an acknowledgement naming any other one is stale.
    ResetRouteInstalled(SocketAddr, u64, u64),
    /// The endpoint has no room to route a reset for this identifier at this address, so the
    /// route does not exist and the datagram waiting on it can never be sent.
    ResetRouteRefused(SocketAddr, u64, u64),
}

impl ConnectionEvent {
    /// Whether this event issues connection identifiers. Identifier issuance is the only thing
    /// the test seam that withholds events should withhold, and it is reached from more than one
    /// request — a connection asking for more, and a retirement that allows more.
    #[cfg(test)]
    pub(crate) fn is_new_identifiers(&self) -> bool {
        matches!(self.0, ConnectionEventInner::NewIdentifiers(..))
    }
}

/// Variant of [`ConnectionEventInner`].
#[derive(Debug)]
pub(crate) struct DatagramConnectionEvent {
    pub(crate) now: Instant,
    pub(crate) remote: SocketAddr,
    /// The local socket address the datagram arrived on (ip and port), when known. The ip may
    /// be unspecified for a wildcard-bound socket whose platform reports no destination address.
    pub(crate) local: Option<SocketAddr>,
    pub(crate) ecn: Option<EcnCodepoint>,
    pub(crate) first_decode: PartialDecode,
    pub(crate) remaining: Option<BytesMut>,
}

/// Events sent from a Connection to an Endpoint
#[derive(Debug)]
pub(crate) struct EndpointEvent(pub(crate) EndpointEventInner);

impl EndpointEvent {
    /// Construct an event that indicating that a `Connection` will no longer emit events
    ///
    /// Useful for notifying an `Endpoint` that a `Connection` has been destroyed outside of the
    /// usual state machine flow, e.g. when being dropped by the user.
    pub(crate) fn drained() -> Self {
        Self(EndpointEventInner::Drained)
    }

    /// Whether this event installs the route a stateless reset would arrive by. It is the only
    /// endpoint event the send path waits on, so a synchronous test harness applies these before
    /// offering a datagram and leaves the rest of its ordering alone.
    #[cfg(test)]
    pub(crate) fn is_reset_route(&self) -> bool {
        matches!(self.0, EndpointEventInner::ResetTokenUsed(..))
    }

    /// The refusal a full routing table would answer this installation with, if it is one.
    #[cfg(test)]
    pub(crate) fn route_refusal(&self) -> Option<ConnectionEvent> {
        match self.0 {
            EndpointEventInner::ResetTokenUsed(remote, seq, _, generation) => {
                Some(ConnectionEvent(ConnectionEventInner::ResetRouteRefused(
                    remote, seq, generation,
                )))
            }
            _ => None,
        }
    }

    /// Determine whether this is the last event a `Connection` will emit
    ///
    /// Useful for determining when connection-related event loop state can be freed.
    pub(crate) fn is_drained(&self) -> bool {
        self.0 == EndpointEventInner::Drained
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EndpointEventInner {
    /// The connection has been drained
    Drained,
    /// The connection now sends the remote connection ID with this sequence number to this
    /// address: a stateless reset from there carrying this token belongs to it.
    /// A datagram carrying this identifier reached the network for this address: install the
    /// route a stateless reset would arrive by. The last field names the installation.
    ResetTokenUsed(SocketAddr, u64, ResetToken, u64),
    /// This identifier is no longer sent to this address: release that route. The last field names
    /// the installation being released, so a newer one is left in place.
    ResetTokenReleased(SocketAddr, u64, ResetToken, u64),
    /// The remote connection IDs with these sequence numbers were retired: their tokens no longer
    /// identify a reset for this connection.
    ResetTokensRetired(Range<u64>),
    /// The connection needs connection identifiers
    NeedIdentifiers(Instant, u64),
    /// Stop routing connection ID for this sequence number to the connection
    /// When `bool == true`, a new connection ID will be issued to peer
    RetireConnectionId(Instant, u64, bool),
}

/// Protocol-level identifier for a connection.
///
/// Mainly useful for identifying this connection's packets on the wire with tools like Wireshark.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ConnectionId {
    /// length of CID
    len: u8,
    /// CID in byte array
    bytes: [u8; MAX_CID_SIZE],
}

impl ConnectionId {
    /// Construct cid from byte array
    pub(crate) fn new(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() <= MAX_CID_SIZE);
        let mut res = Self {
            len: bytes.len() as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        res.bytes[..bytes.len()].copy_from_slice(bytes);
        res
    }

    /// Constructs cid by reading `len` bytes from a `Buf`
    ///
    /// Callers need to assure that `buf.remaining() >= len`
    pub(crate) fn from_buf(buf: &mut (impl Buf + ?Sized), len: usize) -> Self {
        debug_assert!(len <= MAX_CID_SIZE);
        let mut res = Self {
            len: len as u8,
            bytes: [0; MAX_CID_SIZE],
        };
        buf.copy_to_slice(&mut res[..len]);
        res
    }

    /// Decode from long header format
    pub(crate) fn decode_long(buf: &mut impl Buf) -> Option<Self> {
        let len = buf.get::<u8>().ok()? as usize;
        match len > MAX_CID_SIZE || buf.remaining() < len {
            false => Some(Self::from_buf(buf, len)),
            true => None,
        }
    }

    /// Encode in long header format
    pub(crate) fn encode_long(&self, buf: &mut impl BufMut) {
        buf.put_u8(self.len() as u8);
        buf.put_slice(self);
    }
}

impl ::std::ops::Deref for ConnectionId {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[0..self.len as usize]
    }
}

impl ::std::ops::DerefMut for ConnectionId {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[0..self.len as usize]
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.bytes[0..self.len as usize].fmt(f)
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.iter() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Explicit congestion notification codepoint
#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum EcnCodepoint {
    /// The ECT(0) codepoint, indicating that an endpoint is ECN-capable
    Ect0 = 0b10,
    /// The ECT(1) codepoint, indicating that an endpoint is ECN-capable
    Ect1 = 0b01,
    /// The CE codepoint, signalling that congestion was experienced
    Ce = 0b11,
}

impl EcnCodepoint {
    /// Returns whether the codepoint is a CE, signalling that congestion was experienced
    pub(crate) fn is_ce(self) -> bool {
        matches!(self, Self::Ce)
    }
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct IssuedCid {
    pub(crate) sequence: u64,
    pub(crate) id: ConnectionId,
    pub(crate) reset_token: ResetToken,
}
