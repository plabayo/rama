//! QUIC transport for Rama: version 1 (RFC 9000) and version 2 (RFC 9369), with RFC 9368
//! version negotiation between them.
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

pub mod profile;
mod proto;
pub mod qlog;

// Engine types that are part of the public transport API. The runtime facade
// (endpoints, connections, streams) is Rama-owned and lives in `driver`.
#[cfg(any(feature = "aws-lc", feature = "ring", feature = "boring"))]
pub use proto::AddressTokenKey;
pub use proto::{
    AckFrequencyConfig, BloomTokenLog, Chunk, ClientConfig, ClosedStream, ConfigError,
    CongestionControl, ConnectError, ConnectionError, ConnectionIdGenerator,
    ConnectionIdGeneratorFactory, ConnectionStats, EndpointConfig, ExportKeyingMaterialError,
    FrameStats, HashedConnectionIdGenerator, IdleTimeout, MIN_INITIAL_CONGESTION_WINDOW,
    MtuDiscoveryConfig, NegotiatedTlsParameters, NoneTokenLog, NoneTokenStore, PathStats,
    PreferredAddressPolicy, RandomConnectionIdGenerator, ReceiveQueueLimits, RetryRefused,
    ServerConfig, StdSystemTime, StoredToken, TimeSource, TokenLog, TokenMemoryCache,
    TokenReuseError, TokenStore, TransportConfig, UdpStats, ValidationTokenConfig, Written,
};
pub use proto::{KEY_MATERIAL_SIZE, StatelessResetKey};

/// TLS for QUIC: how a connection's identity and application protocol are configured.
///
/// The configuration itself is the common Rama TLS client and server configuration; this module
/// carries only what QUIC adds to it. Inject a configuration provider explicitly,
/// or use the convenience constructors to select the feature-default provider.
pub mod tls {
    mod cache;
    pub use cache::ClientConfigCache;

    mod factory;
    pub use factory::*;

    /// Interfaces for supplying a QUIC TLS 1.3 implementation.
    ///
    /// Implement [`provider::ClientConfig`] and [`provider::ServerConfig`] and pass them to
    /// [`crate::ClientConfig::new`] and [`crate::ServerConfig::new`]. The latter also
    /// accepts a custom address-token key, so no built-in crypto feature is required.
    /// A provider encodes local [`rama_quic_proto::transport_parameters::TransportParameters`]
    /// into its TLS extension and decodes its peer's extension with that type's `read`.
    ///
    /// Sessions must preserve the order of [`provider::HandshakeEvent`] values, distinguish read
    /// and write keys, and report TLS failures through Rama's transport error types.
    pub mod provider {
        pub use crate::proto::crypto::{
            AeadKey, ClientConfig, DirectionalKeys, ExportKeyingMaterialError, HandshakeEvent,
            HandshakeTokenKey, InitialKeysError, KeyPair, Keys, ServerConfig, Session,
            UnsupportedVersion,
        };
    }

    pub use crate::proto::crypto::config::{
        AlpnPolicy, NoInitialCipherSuite, TlsConfigError, TlsOptions,
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
    SendStream, ShutdownOutcome, StoppedError, StreamAbortHandle, WriteError, ZeroRttAccepted,
};

#[cfg(fuzzing)]
pub mod fuzzing {
    //! Byte-oriented entry points for the workspace fuzz targets.
    pub use crate::proto::fuzzing::*;
}
