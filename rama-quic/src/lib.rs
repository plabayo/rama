//! QUIC v1 (RFC 9000) transport for Rama.
//!
//! The deterministic protocol engine lives in the private `proto` module and
//! the asynchronous connection driver in `driver`; only Rama-owned types are
//! part of this crate's public API.
//!
//! UDP I/O is provided by [`rama_udp`]; TLS 1.3 comes from the common
//! [`rama_tls`] configuration converted through `rama-tls-rustls` or `rama-tls-boring`.
//! Custom TLS implementations can use [`tls::provider`].
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

#[cfg(feature = "test-utils")]
#[doc(hidden)]
pub mod benchmarks;

#[cfg(all(
    test,
    any(
        feature = "boring",
        all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
    )
))]
mod test_helpers;

mod proto;
pub mod qlog;

// Engine types that are part of the public transport API. The runtime facade
// (endpoints, connections, streams) is Rama-owned and lives in `driver`.
#[cfg(any(feature = "aws-lc", feature = "ring", feature = "boring"))]
pub use proto::AddressTokenKey;
pub use proto::{
    AckFrequencyConfig, ApplicationClose, BloomTokenLog, Chunk, ClientConfig, ClosedStream,
    ConfigError, CongestionControl, ConnectError, ConnectionClose, ConnectionError, ConnectionId,
    ConnectionIdGenerator, ConnectionIdGeneratorFactory, ConnectionStats,
    DEFAULT_SUPPORTED_VERSIONS, Dir, EcnCodepoint, EndpointConfig, ExportKeyingMaterialError,
    FrameStats, FrameType, HashedConnectionIdGenerator, IdleTimeout, InvalidCid, MAX_CID_SIZE,
    MIN_INITIAL_CONGESTION_WINDOW, MtuDiscoveryConfig, NegotiatedTlsParameters, NoneTokenLog,
    NoneTokenStore, PathStats, PreferredAddressPolicy, RandomConnectionIdGenerator,
    ReceiveQueueLimits, RetryRefused, ServerConfig, Side, StdSystemTime, StreamId, TimeSource,
    TokenLog, TokenMemoryCache, TokenReuseError, TokenStore, TransportConfig, TransportError,
    TransportErrorCode, UdpStats, ValidationTokenConfig, VarInt, VarIntBoundsExceeded, Written,
};
pub use proto::{KEY_MATERIAL_SIZE, StatelessResetKey};

/// TLS for QUIC: how a connection's identity and application protocol are configured.
///
/// The configuration itself is the common Rama TLS client and server configuration; this module
/// carries only what QUIC adds to it. The provider behind it follows this crate's features, and
/// no Rustls type appears in any signature here.
pub mod tls {
    /// Interfaces for supplying a QUIC TLS 1.3 implementation.
    ///
    /// Implement [`provider::ClientConfig`] and [`provider::ServerConfig`] and pass them to
    /// [`crate::ClientConfig::new`] and [`crate::ServerConfig::new`]. The latter also
    /// accepts a custom address-token key, so no built-in crypto feature is required.
    /// A provider encodes local [`provider::TransportParameters`] into its TLS extension and
    /// decodes its peer's extension with [`provider::TransportParameters::read`].
    ///
    /// Sessions must preserve the order of [`provider::HandshakeEvent`] values, distinguish read
    /// and write keys, and report TLS failures through Rama's transport error types.
    pub mod provider {
        pub use crate::proto::SpaceId as EncryptionLevel;
        pub use crate::proto::crypto::{
            AeadKey, ClientConfig, CryptoError, DirectionalKeys, ExportKeyingMaterialError,
            HandshakeEvent, HandshakeTokenKey, HeaderKey, InitialKeysError, KeyPair, Keys,
            PacketKey, ServerConfig, Session, UnsupportedVersion,
        };
        pub use crate::proto::transport_parameters::{
            Error as TransportParametersError, TransportParameters,
        };
    }

    pub use crate::proto::crypto::config::{
        AlpnPolicy, NoInitialCipherSuite, TlsBackend, TlsConfigError, TlsOptions,
    };
}

mod driver;

// The runtime: endpoints, connections, streams and the errors they report. Rama owns these
// types; the engine that drives them and the TLS provider behind them stay private.
pub use driver::{
    Accept, AcceptBi, AcceptUni, Connecting, Connection, DEFAULT_SHUTDOWN_BUDGET,
    DEFAULT_SOCKET_BUFFER_SIZE, DriverStats, Endpoint, EndpointBuilder, EndpointStats, Incoming,
    IncomingFuture, OpenBi, OpenUni, PacketQueueStats, ReadDatagram, ReadError, ReadExactError,
    ReadToEndError, RecvStream, ResetError, RetryError, SendDatagram, SendDatagramError,
    SendStream, ShutdownOutcome, StoppedError, WriteError, ZeroRttAccepted,
};

#[cfg(fuzzing)]
pub mod fuzzing {
    //! Byte-oriented entry points for the workspace fuzz targets.
    pub use crate::proto::fuzzing::*;
}
