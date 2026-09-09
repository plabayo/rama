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
    ConfigError, ConnectError, ConnectionClose, ConnectionError, ConnectionId,
    ConnectionIdGenerator, ConnectionStats, DEFAULT_SUPPORTED_VERSIONS, Dir, EcnCodepoint,
    EndpointConfig, ExportKeyingMaterialError, FrameStats, FrameType, HandshakeSummary,
    HashedConnectionIdGenerator, IdleTimeout, InvalidCid, MtuDiscoveryConfig, NoneTokenLog,
    NoneTokenStore, PathStats, PreferredAddressPolicy, RandomConnectionIdGenerator,
    ReceiveQueueLimits, ServerConfig, ServerName, Side, StdSystemTime, StreamId, TimeSource,
    TokenLog, TokenMemoryCache, TokenReuseError, TokenStore, TransportConfig, TransportError,
    TransportErrorCode, UdpStats, ValidationTokenConfig, VarInt, VarIntBoundsExceeded, Written,
};

/// TLS for QUIC: how a connection's identity and application protocol are configured.
///
/// The configuration itself is the common Rama TLS client and server configuration; this module
/// carries only what QUIC adds to it. The provider behind it follows this crate's features, and
/// no Rustls type appears in any signature here.
#[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
#[cfg_attr(
    docsrs,
    doc(cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))))
)]
pub mod tls {
    pub use crate::proto::crypto::rustls::{
        AlpnPolicy, NoInitialCipherSuite, TlsConfigError, TlsOptions,
    };
}

mod driver;

// The runtime: endpoints, connections, streams and the errors they report. Rama owns these
// types; the engine that drives them and the TLS provider behind them stay private.
pub use driver::{
    Accept, AcceptBi, AcceptUni, Connecting, Connection, Endpoint, EndpointStats, Incoming,
    IncomingFuture, OpenBi, OpenUni, ReadDatagram, ReadError, ReadExactError, ReadToEndError,
    RecvStream, ResetError, RetryError, SendDatagram, SendDatagramError, SendStream,
    ShutdownOutcome, StoppedError, WriteError, ZeroRttAccepted,
};

#[cfg(fuzzing)]
pub mod fuzzing {
    //! Byte-oriented entry points for the workspace fuzz targets.
    pub use crate::proto::fuzzing::*;
}
