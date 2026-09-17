//! Deterministic QUIC v1 protocol engine.
//!
//! This module contains the protocol state machines only: no sockets, no timers and no clock.
//! The async driver feeds it received datagrams and the current time and transmits what it
//! produces, which keeps the engine fully testable with the simulator in `tests`.
//!
//! `Endpoint` represents the protocol state for a single socket: it manages configuration and
//! dispatches incoming datagrams to the related `Connection`. `Connection` holds the bulk of the
//! per-connection logic and state (streams, recovery, congestion control, migration).

#![cfg_attr(test, allow(dead_code))]
#![expect(clippy::too_many_arguments)]

use std::{fmt, net::SocketAddr, ops};

pub(crate) mod cid_queue;
pub(crate) mod coding;
mod constant_time;
mod range_set;
#[cfg(test)]
#[cfg(any(
    feature = "boring",
    all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
))]
mod tests;
pub(crate) mod transport_parameters;
mod varint;
pub(crate) mod version;
pub use version::Version;

pub use varint::{VarInt, VarIntBoundsExceeded};
mod bloom_token_log;
pub use bloom_token_log::BloomTokenLog;

mod connection;
/// Names the crate's own tests reach for through this module.
#[cfg(test)]
pub(crate) use crate::proto::connection::RecvStream;
pub use crate::proto::connection::{
    Chunk, ClosedStream, ConnectionError, ConnectionStats, FrameStats, PathStats, UdpStats, Written,
};
pub(crate) use crate::proto::connection::{
    Chunks, Connection, Event, FinishError, ReadError, ReadableError, SendDatagramError,
    SendStream, StreamEvent, WriteError,
};
#[cfg(all(
    test,
    any(
        feature = "boring",
        any(
            feature = "boring",
            all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
        )
    )
))]
pub(crate) use crate::proto::connection::{Datagrams, StreamResourceUsage, Streams};
#[cfg(all(
    test,
    any(
        feature = "boring",
        any(
            feature = "boring",
            all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
        )
    )
))]
pub(crate) use crate::proto::endpoint::AcceptError;
#[cfg(all(
    test,
    any(
        feature = "boring",
        any(
            feature = "boring",
            all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
        )
    )
))]
pub(crate) use crate::proto::frame::Datagram;
#[cfg(feature = "test-utils")]
pub(crate) use connection::benchmarks;

#[cfg(test)]
pub(crate) use connection::qlog::ConnectionQlog;

mod config;
#[cfg(any(feature = "aws-lc", feature = "ring", feature = "boring"))]
pub use config::AddressTokenKey;
pub use config::{
    AckFrequencyConfig, ClientConfig, ConfigError, CongestionControl, EndpointConfig, IdleTimeout,
    MIN_INITIAL_CONGESTION_WINDOW, MtuDiscoveryConfig, PreferredAddressPolicy, ReceiveQueueLimits,
    ServerConfig, StdSystemTime, TimeSource, TransportConfig, ValidationTokenConfig,
};
pub use config::{KEY_MATERIAL_SIZE, StatelessResetKey};

pub(crate) mod crypto;

pub(crate) mod frame;

/// Whether a datagram carrying a particular connection ID may go to a particular address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendPermit {
    /// It may go now.
    Sendable,
    /// The endpoint has not yet confirmed the route a stateless reset for it would arrive by.
    /// The datagram is kept, exactly as it is, until the confirmation lands.
    AwaitingInstallation,
    /// The identifier may never be sent again: retired, or bound to another path. Only the part
    /// of the datagram that has not already left is dropped.
    Obsolete,
}
use crate::proto::frame::Frame;
pub use crate::proto::frame::{ApplicationClose, ConnectionClose, FrameType};

mod endpoint;
pub use crate::proto::endpoint::ConnectError;
pub use crate::proto::endpoint::RetryRefused;
pub(crate) use crate::proto::endpoint::{
    ConnectionHandle, DatagramEvent, Endpoint, Incoming, RetryError,
};

pub use crate::proto::crypto::{ExportKeyingMaterialError, NegotiatedTlsParameters};

pub(crate) mod packet;
pub use packet::SpaceId;

mod shared;
pub(crate) use crate::proto::shared::{ConnectionEvent, EndpointEvent};
pub use crate::proto::shared::{ConnectionId, EcnCodepoint};

mod transport_error;
pub use crate::proto::transport_error::{Code as TransportErrorCode, Error as TransportError};

pub(crate) mod congestion;

pub(crate) mod cid_generator;
pub use crate::proto::cid_generator::{
    ConnectionIdGenerator, ConnectionIdGeneratorFactory, HashedConnectionIdGenerator, InvalidCid,
    RandomConnectionIdGenerator,
};

mod token;
use token::ResetToken;
#[cfg(all(
    test,
    any(
        feature = "boring",
        any(
            feature = "boring",
            all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
        )
    )
))]
pub(crate) use token::ResetToken as TestResetToken;
pub use token::{NoneTokenLog, NoneTokenStore, StoredToken, TokenLog, TokenReuseError, TokenStore};

mod token_memory_cache;
pub use token_memory_cache::TokenMemoryCache;

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;

pub(crate) use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(fuzzing)]
pub(crate) mod fuzzing {
    pub use crate::proto::connection::{Retransmits, State as ConnectionState, StreamsState};
    pub use crate::proto::connection::{SendStream, Streams};
    pub use crate::proto::frame::ResetStream;
    pub use crate::proto::packet::{
        ConnectionIdParser, FixedLengthConnectionIdParser, PartialDecode,
    };
    pub use crate::proto::transport_parameters::TransportParameters;
    pub use rama_core::bytes::{BufMut, Bytes, BytesMut};

    use crate::proto::{
        TransportError,
        frame::{Frame, Iter},
    };

    /// Decode `payload` as the frames of one received packet, up to its end or the first
    /// frame it rejects, walking every ACK range as loss detection would. Answers how many
    /// frames it decoded.
    pub fn decode_frames(payload: Bytes) -> Result<usize, TransportError> {
        let mut decoded = 0;
        for frame in Iter::new(payload)? {
            if let Frame::Ack(ack) = frame? {
                // Ranges are decoded lazily from bytes `Iter` only scanned: each must sit strictly
                // below the one before it.
                let mut floor = None;
                for range in ack.iter() {
                    assert!(range.start() <= range.end());
                    assert!(floor.is_none_or(|floor| *range.end() < floor));
                    floor = Some(*range.start());
                }
            }
            decoded += 1;
        }
        Ok(decoded)
    }

    #[cfg(feature = "arbitrary")]
    use arbitrary::{Arbitrary, Result, Unstructured};

    #[cfg(feature = "arbitrary")]
    impl<'arbitrary> Arbitrary<'arbitrary> for TransportParameters {
        fn arbitrary(u: &mut Unstructured<'arbitrary>) -> Result<Self> {
            Ok(Self {
                initial_max_streams_bidi: u.arbitrary()?,
                initial_max_streams_uni: u.arbitrary()?,
                ack_delay_exponent: u.arbitrary()?,
                max_udp_payload_size: u.arbitrary()?,
                ..Self::default()
            })
        }
    }

    #[derive(Debug)]
    pub struct PacketParams {
        pub local_cid_len: usize,
        pub buf: BytesMut,
        pub grease_quic_bit: bool,
    }

    #[cfg(feature = "arbitrary")]
    impl<'arbitrary> Arbitrary<'arbitrary> for PacketParams {
        fn arbitrary(u: &mut Unstructured<'arbitrary>) -> Result<Self> {
            let local_cid_len: usize = u.int_in_range(0..=crate::proto::MAX_CID_SIZE)?;
            let bytes: Vec<u8> = Vec::arbitrary(u)?;
            let mut buf = BytesMut::new();
            buf.put_slice(&bytes[..]);
            Ok(Self {
                local_cid_len,
                buf,
                grease_quic_bit: bool::arbitrary(u)?,
            })
        }
    }
}

/// The QUIC protocol versions accepted by default: version 1 and version 2.
///
/// Draft versions remain decodable for explicit test fixtures but are not offered as
/// product support.
pub const DEFAULT_SUPPORTED_VERSIONS: &[Version] = &[Version::V1, Version::V2];

/// Pre-standard draft versions 29 through 34, kept only for explicit tests.
#[cfg(test)]
pub(crate) const DRAFT_VERSIONS: &[Version] = &[
    Version::from_u32(0xff00_001d),
    Version::from_u32(0xff00_001e),
    Version::from_u32(0xff00_001f),
    Version::from_u32(0xff00_0020),
    Version::from_u32(0xff00_0021),
    Version::from_u32(0xff00_0022),
];

/// Whether an endpoint was the initiator of a connection
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Side {
    /// The initiator of a connection
    Client = 0,
    /// The acceptor of a connection
    Server = 1,
}

impl Side {
    #[inline]
    /// Shorthand for `self == Side::Client`
    pub(crate) fn is_client(self) -> bool {
        self == Self::Client
    }

    #[inline]
    /// Shorthand for `self == Side::Server`
    pub(crate) fn is_server(self) -> bool {
        self == Self::Server
    }
}

impl ops::Not for Side {
    type Output = Self;
    fn not(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

/// Whether a stream communicates data in both directions or only from the initiator
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Dir {
    /// Data flows in both directions
    Bi = 0,
    /// Data flows only from the stream's initiator
    Uni = 1,
}

impl Dir {
    fn iter() -> impl Iterator<Item = Self> {
        [Self::Bi, Self::Uni].iter().cloned()
    }
}

impl fmt::Display for Dir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match *self {
            Self::Bi => "bidirectional",
            Self::Uni => "unidirectional",
        })
    }
}

/// Identifier for a stream within a particular connection
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StreamId(u64);

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let initiator = match self.initiator() {
            Side::Client => "client",
            Side::Server => "server",
        };
        let dir = match self.dir() {
            Dir::Uni => "uni",
            Dir::Bi => "bi",
        };
        write!(
            f,
            "{} {}directional stream {}",
            initiator,
            dir,
            self.index()
        )
    }
}

impl StreamId {
    /// Create a new StreamId
    pub fn new(initiator: Side, dir: Dir, index: u64) -> Self {
        Self((index << 2) | ((dir as u64) << 1) | initiator as u64)
    }
    /// Which side of a connection initiated the stream
    pub fn initiator(self) -> Side {
        if self.0 & 0x1 == 0 {
            Side::Client
        } else {
            Side::Server
        }
    }
    /// Which directions data flows in
    pub fn dir(self) -> Dir {
        if self.0 & 0x2 == 0 { Dir::Bi } else { Dir::Uni }
    }
    /// Distinguishes streams of the same initiator and directionality
    pub fn index(self) -> u64 {
        self.0 >> 2
    }
}

impl From<StreamId> for VarInt {
    fn from(x: StreamId) -> Self {
        unsafe { Self::from_u64_unchecked(x.0) }
    }
}

impl From<VarInt> for StreamId {
    fn from(v: VarInt) -> Self {
        Self(v.0)
    }
}

impl From<StreamId> for u64 {
    fn from(x: StreamId) -> Self {
        x.0
    }
}

impl coding::Codec for StreamId {
    fn decode<B: rama_core::bytes::Buf>(buf: &mut B) -> coding::Result<Self> {
        VarInt::decode(buf).map(|x| Self(x.into_inner()))
    }
    fn encode<B: rama_core::bytes::BufMut>(&self, buf: &mut B) {
        #[expect(
            clippy::unwrap_used,
            reason = "`StreamId` values come from varints or from indices below 2^62"
        )]
        VarInt::from_u64(self.0).unwrap().encode(buf);
    }
}

/// An outgoing packet
#[derive(Debug)]
#[must_use]
pub(crate) struct Transmit {
    /// The socket this datagram should be sent to
    pub(crate) destination: SocketAddr,
    /// Explicit congestion notification bits to set on the packet
    pub(crate) ecn: Option<EcnCodepoint>,
    /// Amount of data written to the caller-supplied buffer
    pub(crate) size: usize,
    /// The segment size if this transmission contains multiple datagrams.
    /// This is `None` if the transmit only contains a single datagram
    pub(crate) segment_size: Option<usize>,
    /// The local socket address this datagram belongs to (ip and port): the socket that received
    /// the path's packets, when the endpoint knows it. The driver sends from that socket and
    /// selects the source ip when it is specified.
    pub(crate) local: Option<SocketAddr>,
    /// Sequence number of the peer's connection ID this datagram carries, when it carries one.
    /// The sender asks whether that identifier may still be sent and reports the datagram once
    /// it is gone, which is what makes the identifier one this connection has used.
    pub(crate) cid_used: Option<u64>,
}

// Useful internal constants

/// The maximum number of CIDs we bother to issue per connection
const LOC_CID_COUNT: u64 = 8;
const RESET_TOKEN_SIZE: usize = 16;
/// The longest connection ID QUIC version 1 carries, in bytes (RFC 9000 §17.2).
pub const MAX_CID_SIZE: usize = 20;
pub(crate) const MIN_INITIAL_SIZE: u16 = 1200;
/// <https://www.rfc-editor.org/rfc/rfc9000.html#name-datagram-size>
pub(crate) const INITIAL_MTU: u16 = 1200;
const MAX_UDP_PAYLOAD: u16 = 65527;
const TIMER_GRANULARITY: Duration = Duration::from_millis(1);
/// Maximum number of streams that can be uniquely identified by a stream ID
pub(crate) const MAX_STREAM_COUNT: u64 = 1 << 60;
