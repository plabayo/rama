//! QUIC v1 (RFC 9000) transport for Rama.
//!
//! The deterministic protocol engine lives in the private `proto` module and
//! the asynchronous connection driver in `driver`; only Rama-owned types are
//! part of this crate's public API.
//!
//! UDP I/O is provided by [`rama_udp`]; TLS 1.3 comes from the common
//! [`rama_tls`] configuration converted through `rama-tls-rustls`.
//!
//! # Rama
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod proto;

// Engine types that are part of the public transport API. The runtime facade
// (endpoints, connections, streams) is Rama-owned and lives in `driver`.
pub use proto::{
    AckFrequencyConfig, ApplicationClose, BloomTokenLog, Chunk, ClientConfig, ClosedStream,
    ConfigError, ConnectionClose, ConnectionError, ConnectionId, ConnectionIdGenerator,
    ConnectionStats, DEFAULT_SUPPORTED_VERSIONS, Dir, EcnCodepoint, EndpointConfig, FrameStats,
    FrameType, HashedConnectionIdGenerator, IdleTimeout, InvalidCid, MtuDiscoveryConfig,
    NoneTokenLog, NoneTokenStore, PathStats, PreferredAddressPolicy, RandomConnectionIdGenerator,
    ReceiveQueueLimits, ServerConfig, Side, StdSystemTime, StreamId, TimeSource, TokenLog,
    TokenMemoryCache, TokenReuseError, TokenStore, TransportConfig, TransportError,
    TransportErrorCode, UdpStats, ValidationTokenConfig, VarInt, VarIntBoundsExceeded, Written,
};

mod driver;

#[cfg(fuzzing)]
pub mod fuzzing {
    //! Byte-oriented entry points for the workspace fuzz targets.
    pub use crate::proto::fuzzing::*;
}
