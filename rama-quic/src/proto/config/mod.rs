#![cfg_attr(
    not(any(
        feature = "boring",
        all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
    )),
    allow(
        dead_code,
        reason = "without a TLS backend and a crypto provider nothing can drive a handshake, so the code that serves one has no caller"
    )
)]
use rama_core::error::BoxError;
use rama_crypto::hmac::HmacSha2;
use rama_utils::octets;
use std::{
    fmt,
    net::{SocketAddrV4, SocketAddrV6},
    num::TryFromIntError,
    sync::Arc,
};

use crate::proto::BloomTokenLog;
#[cfg(all(test, feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
use crate::proto::crypto::rustls::QuicServerConfig;
#[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
use crate::proto::crypto::rustls::configured_provider;
use crate::proto::{
    DEFAULT_SUPPORTED_VERSIONS, Duration, RandomConnectionIdGenerator, SystemTime, TokenLog,
    TokenMemoryCache, TokenStore, VarInt, VarIntBoundsExceeded,
    cid_generator::{
        ConnectionIdGenerator, ConnectionIdGeneratorFactory, HashedConnectionIdGenerator,
    },
    crypto::{self, HandshakeTokenKey},
    shared::ConnectionId,
};
#[cfg(all(test, feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
use rama_crypto::pki_types::{CertificateDer, PrivateKeyDer};
#[cfg(all(test, feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
use rama_tls_rustls::dep::rustls::client::WebPkiServerVerifier;

mod keys;
#[cfg(any(feature = "aws-lc", feature = "ring", feature = "boring"))]
pub use keys::AddressTokenKey;
pub use keys::{KEY_MATERIAL_SIZE, StatelessResetKey};

mod transport;
pub use transport::{
    AckFrequencyConfig, CongestionControl, IdleTimeout, MIN_INITIAL_CONGESTION_WINDOW,
    MtuDiscoveryConfig, TransportConfig,
};

/// Bounds for received packets queued between the endpoint driver and a connection driver.
///
/// Every queued datagram is counted once and charged its retained capacity plus a fixed
/// per-message overhead. Both limits must be nonzero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveQueueLimits {
    datagrams: usize,
    bytes: usize,
}

impl ReceiveQueueLimits {
    /// Build limits; both values must be nonzero.
    pub fn new(datagrams: usize, bytes: usize) -> Result<Self, ConfigError> {
        if datagrams == 0 || bytes == 0 {
            return Err(ConfigError::OutOfBounds);
        }
        Ok(Self { datagrams, bytes })
    }

    /// Maximum number of queued datagrams.
    #[must_use]
    pub fn datagrams(&self) -> usize {
        self.datagrams
    }

    /// Maximum queued bytes, including per-message overhead.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

/// Global configuration for the endpoint, affecting all connections
///
/// Supply a secret reset key with [`Self::new`]; the remaining settings suit most
/// internet applications. [`crate::EndpointBuilder`] generates a fresh random key
/// when no endpoint configuration is supplied.
#[derive(Clone)]
pub struct EndpointConfig {
    pub(crate) reset_key: HmacSha2,
    pub(crate) max_udp_payload_size: VarInt,
    /// CID generator factory
    ///
    /// Create a cid generator for local cid in Endpoint struct
    pub(crate) connection_id_generator_factory: ConnectionIdGeneratorFactory,
    pub(crate) supported_versions: Vec<u32>,
    pub(crate) grease_quic_bit: bool,
    /// Minimum interval between outgoing stateless reset packets
    pub(crate) min_reset_interval: Duration,
    /// Local deadline for completing a handshake, independent of idle timeout.
    pub(crate) handshake_timeout: Duration,
    pub(crate) connection_receive_queue: ReceiveQueueLimits,
    pub(crate) endpoint_receive_queue: ReceiveQueueLimits,
    /// Optional seed to be used internally for random number generation
    pub(crate) rng_seed: Option<[u8; 32]>,
}

impl EndpointConfig {
    /// Create an endpoint configuration with the supplied secret reset key.
    ///
    /// Reuse the same key and HMAC algorithm to keep reset tokens stable across restarts.
    ///
    /// ```
    /// use rama_crypto::hmac::HmacSha2;
    /// use rama_quic::EndpointConfig;
    ///
    /// let key = HmacSha2::try_rand_256()?;
    /// let config = EndpointConfig::new(key);
    /// # Ok::<(), rama_core::error::BoxError>(())
    /// ```
    pub fn new(reset_key: HmacSha2) -> Self {
        let cid_factory =
            || -> Box<dyn ConnectionIdGenerator> { Box::<HashedConnectionIdGenerator>::default() };
        Self {
            reset_key,
            max_udp_payload_size: (1500u32 - 28).into(), // Ethernet MTU minus IP + UDP headers
            connection_id_generator_factory: Arc::new(cid_factory),
            supported_versions: DEFAULT_SUPPORTED_VERSIONS.to_vec(),
            grease_quic_bit: true,
            min_reset_interval: Duration::from_millis(20),
            handshake_timeout: Duration::from_secs(10),
            connection_receive_queue: ReceiveQueueLimits {
                datagrams: 256,
                bytes: octets::kib(512),
            },
            endpoint_receive_queue: ReceiveQueueLimits {
                datagrams: octets::kib(8),
                bytes: octets::mib(16),
            },
            rng_seed: None,
        }
    }

    /// Create a configuration with a fresh operating-system-generated reset key.
    pub(crate) fn try_with_rand_key() -> Result<Self, BoxError> {
        HmacSha2::try_rand_256().map(Self::new)
    }

    /// Maximum time to complete a handshake, including time awaiting application acceptance.
    ///
    /// Defaults to ten seconds. This local resource limit remains active when the
    /// negotiated idle timeout is disabled. The duration must be nonzero and fit
    /// the runtime clock when the endpoint is constructed.
    pub fn handshake_timeout(&mut self, value: Duration) -> Result<&mut Self, ConfigError> {
        if value.is_zero() {
            return Err(ConfigError::OutOfBounds);
        }
        self.handshake_timeout = value;
        Ok(self)
    }

    rama_utils::macros::generate_set_and_with! {
        /// Bound each connection's queue of received packets awaiting its driver, and the
        /// aggregate storage across the endpoint including queued incoming connection attempts.
        ///
        /// Defaults to 256 datagrams / 512 KiB per connection and 8192 datagrams / 16 MiB per
        /// endpoint. Each queued datagram is charged its retained capacity plus a fixed
        /// per-message overhead. A saturated queue drops and counts further packets; protocol
        /// stream buffers and pending-handshake buffers have their own limits. The endpoint
        /// checks at construction that one maximum-size datagram fits each limit.
        pub fn receive_queue_limits(
            mut self,
            connection: ReceiveQueueLimits,
            endpoint: ReceiveQueueLimits,
        ) -> Self {
            self.connection_receive_queue = connection;
            self.endpoint_receive_queue = endpoint;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// How this endpoint generates the connection IDs it asks peers to send to.
        ///
        /// The factory is called once per [`Endpoint`](crate::Endpoint) built from this
        /// configuration, and that generator issues the identifiers of every connection on
        /// it. [`HashedConnectionIdGenerator`] is the default; [`RandomConnectionIdGenerator`]
        /// gives identifiers of a chosen length, and a generator of your own can carry
        /// whatever a load balancer in front of the endpoint needs to read, as long as it
        /// keeps to what [`ConnectionIdGenerator::generate_cid`] requires.
        pub fn cid_generator(mut self, factory: ConnectionIdGeneratorFactory) -> Self {
            self.connection_id_generator_factory = factory;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the secret used to derive stateless reset tokens.
        ///
        /// Keep the key secret and reuse it across endpoint restarts when peers should
        /// recognise resets for connections whose state was lost.
        pub fn stateless_reset_key(mut self, key: StatelessResetKey) -> Self {
            self.reset_key = key.into_key();
            self
        }
    }

    /// Maximum UDP payload size accepted from peers (excluding UDP and IP overhead).
    ///
    /// Must be greater or equal than 1200.
    ///
    /// Defaults to 1472, which is the largest UDP payload that can be transmitted in the typical
    /// 1500 byte Ethernet MTU. Deployments on links with larger MTUs (e.g. loopback or Ethernet
    /// with jumbo frames) can raise this to improve performance at the cost of a linear increase in
    /// datagram receive buffer size.
    pub fn max_udp_payload_size(&mut self, value: u16) -> Result<&mut Self, ConfigError> {
        if !(1200..=65_527).contains(&value) {
            return Err(ConfigError::OutOfBounds);
        }

        self.max_udp_payload_size = value.into();
        Ok(self)
    }

    /// Get the current value of [`max_udp_payload_size`](Self::max_udp_payload_size)
    //
    // While most parameters don't need to be readable, this must be exposed to allow higher-level
    // layers, e.g. the async driver, to determine how large a receive buffer to allocate to
    // support an externally-defined `EndpointConfig`.
    //
    // While `get_` accessors are typically unidiomatic in Rust, we favor concision for setters,
    // which will be used far more heavily.
    pub(crate) fn get_max_udp_payload_size(&self) -> u64 {
        self.max_udp_payload_size.into()
    }

    rama_utils::macros::generate_set_and_with! {
        /// Override supported QUIC versions
        pub fn supported_versions(mut self, supported_versions: Vec<u32>) -> Self {
            self.supported_versions = supported_versions;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Whether to accept QUIC packets containing any value for the fixed bit
        ///
        /// Enabled by default. Helps protect against protocol ossification and makes traffic less
        /// identifiable to observers. Disable if helping observers identify this traffic as QUIC is
        /// desired.
        pub fn grease_quic_bit(mut self, value: bool) -> Self {
            self.grease_quic_bit = value;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Minimum interval between outgoing stateless reset packets
        ///
        /// Defaults to 20ms. Limits the impact of attacks which flood an endpoint with garbage packets,
        /// e.g. [ISAKMP/IKE amplification]. Larger values provide a stronger defense, but may delay
        /// detection of some error conditions by clients. Using a [`ConnectionIdGenerator`] with a low
        /// rate of false positives in [`validate`](ConnectionIdGenerator::validate) reduces the risk
        /// incurred by a small minimum reset interval.
        ///
        /// [ISAKMP/IKE
        /// amplification]: https://bughunters.google.com/blog/5960150648750080/preventing-cross-service-udp-loops-in-quic#isakmp-ike-amplification-vs-quic
        pub fn min_reset_interval(mut self, value: Duration) -> Self {
            self.min_reset_interval = value;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Optional seed to be used internally for random number generation
        ///
        /// By default, an endpoint's rng is initialized using a platform entropy source.
        /// However, you can seed the rng yourself through this method (e.g. if you need to run
        /// deterministically or if you are running in an environment that doesn't have a source of
        /// entropy available).
        pub fn rng_seed(mut self, seed: Option<[u8; 32]>) -> Self {
            self.rng_seed = seed;
            self
        }
    }
}

impl fmt::Debug for EndpointConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("EndpointConfig")
            // reset_key not debug
            .field("max_udp_payload_size", &self.max_udp_payload_size)
            // cid_generator_factory not debug
            .field("supported_versions", &self.supported_versions)
            .field("grease_quic_bit", &self.grease_quic_bit)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("connection_receive_queue", &self.connection_receive_queue)
            .field("endpoint_receive_queue", &self.endpoint_receive_queue)
            .field("rng_seed", &self.rng_seed)
            .finish_non_exhaustive()
    }
}

/// Parameters governing incoming connections
///
/// Default values should be suitable for most internet applications.
#[derive(Clone)]
pub struct ServerConfig {
    /// Transport configuration to use for incoming connections
    pub(crate) transport: Arc<TransportConfig>,

    /// TLS configuration used for incoming connections
    ///
    /// Must be set to use TLS 1.3 only.
    pub(crate) crypto: Arc<dyn crypto::ServerConfig>,

    /// Configuration for sending and handling validation tokens
    pub(crate) validation_token: ValidationTokenConfig,

    /// Used to generate one-time AEAD keys to protect handshake tokens
    pub(crate) token_key: Arc<dyn HandshakeTokenKey>,

    /// Duration after a retry token was issued for which it's considered valid
    pub(crate) retry_token_lifetime: Duration,

    /// Whether to allow clients to migrate to new addresses
    ///
    /// Improves behavior for clients that move between different internet connections or suffer NAT
    /// rebinding. Enabled by default.
    pub(crate) migration: bool,

    pub(crate) preferred_address_v4: Option<SocketAddrV4>,
    pub(crate) preferred_address_v6: Option<SocketAddrV6>,

    pub(crate) max_incoming: usize,
    pub(crate) incoming_buffer_size: u64,
    pub(crate) incoming_buffer_size_total: u64,

    pub(crate) time_source: Arc<dyn TimeSource>,
}

impl ServerConfig {
    /// Create a server with a custom TLS implementation and address-token key.
    pub fn new(
        crypto: Arc<dyn crypto::ServerConfig>,
        token_key: Arc<dyn HandshakeTokenKey>,
    ) -> Self {
        Self {
            transport: Arc::new(TransportConfig::default()),
            crypto,

            token_key,
            retry_token_lifetime: Duration::from_secs(15),

            migration: true,

            validation_token: ValidationTokenConfig::default(),

            preferred_address_v4: None,
            preferred_address_v6: None,

            max_incoming: 1 << 16,
            incoming_buffer_size: 10 << 20,
            incoming_buffer_size_total: 100 << 20,

            time_source: Arc::new(StdSystemTime),
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set a custom [`TransportConfig`]
        pub fn transport_config(mut self, transport: Arc<TransportConfig>) -> Self {
            self.transport = transport;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set a custom [`ValidationTokenConfig`], which governs the tokens this server sends
        /// in NEW_TOKEN frames and how long it accepts them for.
        pub fn validation_token_config(mut self, validation_token: ValidationTokenConfig) -> Self {
            self.validation_token = validation_token;
            self
        }
    }

    #[cfg(test)]
    /// Private key used to authenticate data included in handshake tokens
    pub(crate) fn token_key(&mut self, value: Arc<dyn HandshakeTokenKey>) -> &mut Self {
        self.token_key = value;
        self
    }

    #[cfg(any(feature = "aws-lc", feature = "ring", feature = "boring"))]
    rama_utils::macros::generate_set_and_with! {
        /// The key this server seals address-validation tokens with.
        ///
        /// Servers given the same key can read one another's Retry and NEW_TOKEN tokens; the
        /// address, lifetime and reuse checks still decide whether one is accepted. Defaults
        /// to material from the operating system's random source, generated per configuration.
        pub fn address_token_key(mut self, key: AddressTokenKey) -> Self {
            self.token_key = key.into_key();
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Duration after a retry token was issued for which it's considered valid
        ///
        /// Defaults to 15 seconds.
        pub fn retry_token_lifetime(mut self, value: Duration) -> Self {
            self.retry_token_lifetime = value;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Whether to allow clients to migrate to new addresses
        ///
        /// Improves behavior for clients that move between different internet connections or suffer NAT
        /// rebinding. Enabled by default.
        pub fn migration(mut self, value: bool) -> Self {
            self.migration = value;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// The preferred IPv4 address that will be communicated to clients during handshaking
        ///
        /// If the client is able to reach this address, it will switch to it.
        pub fn preferred_address_v4(mut self, address: Option<SocketAddrV4>) -> Self {
            self.preferred_address_v4 = address;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// The preferred IPv6 address that will be communicated to clients during handshaking
        ///
        /// If the client is able to reach this address, it will switch to it.
        pub fn preferred_address_v6(mut self, address: Option<SocketAddrV6>) -> Self {
            self.preferred_address_v6 = address;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Maximum number of [`Incoming`][crate::proto::Incoming] to allow to exist at a time
        ///
        /// An [`Incoming`][crate::proto::Incoming] comes into existence when an incoming connection attempt
        /// is received and stops existing when the application either accepts it or otherwise disposes
        /// of it. While this limit is reached, new incoming connection attempts are immediately
        /// refused. Larger values have greater worst-case memory consumption, but accommodate greater
        /// application latency in handling incoming connection attempts.
        ///
        /// The default value is set to 65536. With a typical Ethernet MTU of 1500 bytes, this limits
        /// memory consumption from this to under 100 MiB--a generous amount that still prevents memory
        /// exhaustion in most contexts.
        pub fn max_incoming(mut self, max_incoming: usize) -> Self {
            self.max_incoming = max_incoming;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Maximum number of received bytes to buffer for each [`Incoming`][crate::proto::Incoming]
        ///
        /// An [`Incoming`][crate::proto::Incoming] comes into existence when an incoming connection attempt
        /// is received and stops existing when the application either accepts it or otherwise disposes
        /// of it. This limit governs only packets received within that period, and does not include
        /// the first packet. Packets received in excess of this limit are dropped, which may cause
        /// 0-RTT or handshake data to have to be retransmitted.
        ///
        /// The default value is set to 10 MiB--an amount such that in most situations a client would
        /// not transmit that much 0-RTT data faster than the server handles the corresponding
        /// [`Incoming`][crate::proto::Incoming].
        pub fn incoming_buffer_size(mut self, incoming_buffer_size: u64) -> Self {
            self.incoming_buffer_size = incoming_buffer_size;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Maximum number of received bytes to buffer for all [`Incoming`][crate::proto::Incoming]
        /// collectively
        ///
        /// An [`Incoming`][crate::proto::Incoming] comes into existence when an incoming connection attempt
        /// is received and stops existing when the application either accepts it or otherwise disposes
        /// of it. This limit governs only packets received within that period, and does not include
        /// the first packet. Packets received in excess of this limit are dropped, which may cause
        /// 0-RTT or handshake data to have to be retransmitted.
        ///
        /// The default value is set to 100 MiB--a generous amount that still prevents memory
        /// exhaustion in most contexts.
        pub fn incoming_buffer_size_total(mut self, incoming_buffer_size_total: u64) -> Self {
            self.incoming_buffer_size_total = incoming_buffer_size_total;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Object to get current [`SystemTime`]
        ///
        /// This exists to allow system time to be mocked in tests, or wherever else desired.
        ///
        /// Defaults to [`StdSystemTime`], which simply calls [`SystemTime::now()`](SystemTime::now).
        pub fn time_source(mut self, time_source: Arc<dyn TimeSource>) -> Self {
            self.time_source = time_source;
            self
        }
    }

    pub(crate) fn has_preferred_address(&self) -> bool {
        self.preferred_address_v4.is_some() || self.preferred_address_v6.is_some()
    }
}

#[cfg(any(
    feature = "boring",
    all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
))]
impl ServerConfig {
    /// Build a server configuration from the common Rama TLS server configuration: the identity
    /// to present, the protocols to accept and everything else TLS decides, with the provider
    /// chosen by this crate's features.
    pub fn try_from_rama_tls(
        config: &rama_tls::server::TlsServerConfig,
        options: crypto::config::TlsOptions,
    ) -> Result<Self, crypto::config::TlsConfigError> {
        match options.resolve_backend()? {
            #[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
            rama_tls::TlsBackend::Rustls => Ok(Self::with_crypto(Arc::new(
                crypto::rustls::QuicServerConfig::from_rama(
                    config,
                    configured_provider(),
                    options,
                )?,
            ))),
            #[cfg(feature = "boring")]
            rama_tls::TlsBackend::Boring => Ok(Self::with_crypto(Arc::new(
                crypto::boring::QuicServerConfig::from_rama(config, options)?,
            ))),
            backend => Err(crypto::config::TlsConfigError::BackendUnavailable(backend)),
        }
    }

    #[cfg(all(test, feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
    /// Create a server config with the given certificate chain to be presented to clients
    ///
    /// Uses a randomized handshake token key.
    pub(crate) fn with_single_cert(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, rama_tls_rustls::dep::rustls::Error> {
        Ok(Self::with_crypto(Arc::new(QuicServerConfig::new(
            cert_chain, key,
        )?)))
    }
}

#[cfg(any(feature = "aws-lc", feature = "ring", feature = "boring"))]
impl ServerConfig {
    /// Create a server config with the given [`crypto::ServerConfig`]
    ///
    /// Uses a randomized handshake token key.
    pub fn with_crypto(crypto: Arc<dyn crypto::ServerConfig>) -> Self {
        use rand::Rng;

        let rng = &mut rand::rng();
        let mut master_key = [0u8; 64];
        rng.fill_bytes(&mut master_key);
        Self::new(
            crypto,
            AddressTokenKey::from_material(&master_key).into_key(),
        )
    }
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("ServerConfig")
            .field("transport", &self.transport)
            // crypto not debug
            // token not debug
            .field("retry_token_lifetime", &self.retry_token_lifetime)
            .field("validation_token", &self.validation_token)
            .field("migration", &self.migration)
            .field("preferred_address_v4", &self.preferred_address_v4)
            .field("preferred_address_v6", &self.preferred_address_v6)
            .field("max_incoming", &self.max_incoming)
            .field("incoming_buffer_size", &self.incoming_buffer_size)
            .field(
                "incoming_buffer_size_total",
                &self.incoming_buffer_size_total,
            )
            // system_time_clock not debug
            .finish_non_exhaustive()
    }
}

/// Configuration for sending and handling validation tokens in incoming connections
///
/// Default values should be suitable for most internet applications.
///
/// ## QUIC Tokens
///
/// The QUIC protocol defines a concept of "[address validation][1]". Essentially, one side of a
/// QUIC connection may appear to be receiving QUIC packets from a particular remote UDP address,
/// but it will only consider that remote address "validated" once it has convincing evidence that
/// the address is not being [spoofed][2].
///
/// Validation is important primarily because of QUIC's "anti-amplification limit." This limit
/// prevents a QUIC server from sending a client more than three times the number of bytes it has
/// received from the client on a given address until that address is validated. This is designed
/// to mitigate the ability of attackers to use QUIC-based servers as reflectors in [amplification
/// attacks][3].
///
/// A path may become validated in several ways. The server is always considered validated by the
/// client. The client usually begins in an unvalidated state upon first connecting or migrating,
/// but then becomes validated through various mechanisms that usually take one network round trip.
/// However, in some cases, a client which has previously attempted to connect to a server may have
/// been given a one-time use cryptographically secured "token" that it can send in a subsequent
/// connection attempt to be validated immediately.
///
/// There are two ways these tokens can originate:
///
/// - If the server responds to an incoming connection with `retry`, a "retry token" is minted and
///   sent to the client, which the client immediately uses to attempt to connect again. Retry
///   tokens operate on short timescales, such as 15 seconds.
/// - If a client's path within an active connection is validated, the server may send the client
///   one or more "validation tokens," which the client may store for use in later connections to
///   the same server. Validation tokens may be valid for much longer lifetimes than retry token.
///
/// The usage of validation tokens is most impactful in situations where 0-RTT data is also being
/// used--in particular, in situations where the server sends the client more than three times more
/// 0.5-RTT data than it has received 0-RTT data. Since the successful completion of a connection
/// handshake implicitly causes the client's address to be validated, transmission of 0.5-RTT data
/// is the main situation where a server might be sending application data to an address that could
/// be validated by token usage earlier than it would become validated without token usage.
///
/// [1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-8
/// [2]: https://en.wikipedia.org/wiki/IP_address_spoofing
/// [3]: https://en.wikipedia.org/wiki/Denial-of-service_attack#Amplification
///
/// These tokens should not be confused with "stateless reset tokens," which are similarly named
/// but entirely unrelated.
#[derive(Clone)]
pub struct ValidationTokenConfig {
    pub(crate) lifetime: Duration,
    pub(crate) log: Arc<dyn TokenLog>,
    pub(crate) sent: u32,
}

impl ValidationTokenConfig {
    rama_utils::macros::generate_set_and_with! {
        /// Duration after an address validation token was issued for which it's considered valid
        ///
        /// This refers only to tokens sent in NEW_TOKEN frames, in contrast to retry tokens.
        ///
        /// Defaults to 2 weeks.
        pub fn lifetime(mut self, value: Duration) -> Self {
            self.lifetime = value;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set a custom [`TokenLog`]
        ///
        /// Defaults to a default [`BloomTokenLog`], which is suitable for most internet applications.
        /// Use [`NoneTokenLog`] to make the server ignore all address validation tokens (that is,
        /// tokens originating from NEW_TOKEN frames--retry tokens are not affected).
        pub fn log(mut self, log: Arc<dyn TokenLog>) -> Self {
            self.log = log;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Number of address validation tokens sent to a client when its path is validated
        ///
        /// This refers only to tokens sent in NEW_TOKEN frames, in contrast to retry tokens.
        ///
        /// Defaults to 2.
        pub fn sent(mut self, value: u32) -> Self {
            self.sent = value;
            self
        }
    }
}

impl Default for ValidationTokenConfig {
    fn default() -> Self {
        let log = Arc::new(BloomTokenLog::default());
        Self {
            lifetime: Duration::from_secs(2 * 7 * 24 * 60 * 60),
            log,
            sent: 2,
        }
    }
}

impl fmt::Debug for ValidationTokenConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("ServerValidationTokenConfig")
            .field("lifetime", &self.lifetime)
            // log not debug
            .field("sent", &self.sent)
            .finish_non_exhaustive()
    }
}

/// Configuration for outgoing connections
///
/// Default values should be suitable for most internet applications.
#[derive(Clone)]
#[non_exhaustive]
pub struct ClientConfig {
    /// Transport configuration to use
    pub(crate) transport: Arc<TransportConfig>,

    /// Cryptographic configuration to use
    pub(crate) crypto: Arc<dyn crypto::ClientConfig>,

    /// Validation token store to use
    pub(crate) token_store: Arc<dyn TokenStore>,

    /// Provider that populates the destination connection ID of Initial Packets
    pub(crate) initial_dst_cid_provider: Arc<dyn Fn() -> ConnectionId + Send + Sync>,

    /// QUIC protocol version to use
    pub(crate) version: u32,

    /// What to do with a server's preferred address
    pub(crate) preferred_address_policy: PreferredAddressPolicy,
}

/// How a client answers a server's preferred address (RFC 9000 §9.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PreferredAddressPolicy {
    /// Probe the address advertised for the family in use and move there once it answers.
    #[default]
    Migrate,
    /// Stay on the address the connection was established with.
    Decline,
}

impl ClientConfig {
    /// Create a default config with a particular cryptographic config
    pub fn new(crypto: Arc<dyn crypto::ClientConfig>) -> Self {
        Self {
            transport: Default::default(),
            crypto,
            token_store: Arc::new(TokenMemoryCache::default()),
            initial_dst_cid_provider: Arc::new(|| {
                RandomConnectionIdGenerator::of_max_size().generate_cid()
            }),
            version: 1,
            preferred_address_policy: PreferredAddressPolicy::default(),
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// What to do with the address a server advertises as preferred (RFC 9000 §9.6).
        ///
        /// Defaults to [`PreferredAddressPolicy::Migrate`]: the address advertised for the family
        /// in use is probed once the handshake is confirmed, and the connection moves there with
        /// the connection ID the server bound to it as soon as a probe is answered.
        pub fn preferred_address_policy(mut self, policy: PreferredAddressPolicy) -> Self {
            self.preferred_address_policy = policy;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set a custom [`TransportConfig`]
        pub fn transport_config(mut self, transport: Arc<TransportConfig>) -> Self {
            self.transport = transport;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set a custom [`TokenStore`]
        ///
        /// Defaults to [`TokenMemoryCache`], which is suitable for most internet applications.
        pub fn token_store(mut self, store: Arc<dyn TokenStore>) -> Self {
            self.token_store = store;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the QUIC version to use
        pub fn version(mut self, version: u32) -> Self {
            self.version = version;
            self
        }
    }
}

#[cfg(any(
    feature = "boring",
    all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
))]
impl ClientConfig {
    /// Build a client configuration from the common Rama TLS client configuration: the peer
    /// identity to trust, the protocols to offer and everything else TLS decides, with the
    /// provider chosen by this crate's features.
    ///
    /// The destination address is not part of it. A connection is made to an address with
    /// [`Endpoint::connect_with`](crate::Endpoint::connect_with), and the identity it must prove
    /// comes from here and from the server name given there.
    pub fn try_from_rama_tls(
        config: &rama_tls::client::TlsClientConfig,
        options: crypto::config::TlsOptions,
    ) -> Result<Self, crypto::config::TlsConfigError> {
        match options.resolve_backend()? {
            #[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
            rama_tls::TlsBackend::Rustls => Ok(Self::new(Arc::new(
                crypto::rustls::QuicClientConfig::from_rama(
                    config,
                    configured_provider(),
                    options,
                )?,
            ))),
            #[cfg(feature = "boring")]
            rama_tls::TlsBackend::Boring => Ok(Self::new(Arc::new(
                crypto::boring::QuicClientConfig::from_rama(config, options)?,
            ))),
            backend => Err(crypto::config::TlsConfigError::BackendUnavailable(backend)),
        }
    }

    #[cfg(all(test, feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
    /// Create a client configuration that trusts specified trust anchors
    pub(crate) fn with_root_certificates(
        roots: Arc<rama_tls_rustls::dep::rustls::RootCertStore>,
    ) -> Result<Self, rama_tls_rustls::dep::rustls::client::VerifierBuilderError> {
        Ok(Self::new(Arc::new(crypto::rustls::QuicClientConfig::new(
            WebPkiServerVerifier::builder_with_provider(roots, configured_provider()).build()?,
        ))))
    }
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("ClientConfig")
            .field("transport", &self.transport)
            // crypto not debug
            // token_store not debug
            .field("version", &self.version)
            .field("preferred_address_policy", &self.preferred_address_policy)
            .finish_non_exhaustive()
    }
}

/// Errors in the configuration of an endpoint
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// Value exceeds supported bounds
    OutOfBounds,
    /// Key material is shorter than the minimum this crate keys with
    KeyMaterialTooShort,
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutOfBounds => f.write_str("value exceeds supported bounds"),
            Self::KeyMaterialTooShort => {
                f.write_str("key material is shorter than the minimum accepted")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<TryFromIntError> for ConfigError {
    fn from(_: TryFromIntError) -> Self {
        Self::OutOfBounds
    }
}

impl From<VarIntBoundsExceeded> for ConfigError {
    fn from(_: VarIntBoundsExceeded) -> Self {
        Self::OutOfBounds
    }
}

/// Object to get current [`SystemTime`]
///
/// This exists to allow system time to be mocked in tests, or wherever else desired.
pub trait TimeSource: Send + Sync {
    /// Get [`SystemTime::now()`](SystemTime::now) or the mocked equivalent
    fn now(&self) -> SystemTime;
}

/// Default implementation of [`TimeSource`]
///
/// Implements `now` by calling [`SystemTime::now()`](SystemTime::now).
pub struct StdSystemTime;

impl TimeSource for StdSystemTime {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

#[cfg(test)]
mod endpoint_key_tests {
    use super::*;
    use crate::proto::token::ResetToken;

    #[test]
    fn generated_endpoint_keys_are_independent_and_clones_keep_the_key() {
        let first = EndpointConfig::try_with_rand_key().unwrap();
        let second = EndpointConfig::try_with_rand_key().unwrap();
        let cid = ConnectionId::new(&[1, 2, 3, 4]);
        let token = ResetToken::new(&first.reset_key, cid);
        assert_ne!(token, ResetToken::new(&second.reset_key, cid));
        assert_eq!(
            ResetToken::new(&first.clone().reset_key, cid),
            ResetToken::new(&first.reset_key, cid)
        );
    }

    #[test]
    fn explicit_keys_survive_endpoint_reconstruction() {
        let cid = ConnectionId::new(&[1, 2, 3, 4]);
        for key in [
            HmacSha2::new_256(&[0x4b; 32]),
            HmacSha2::new_512(&[0x4b; 64]),
        ] {
            let first = EndpointConfig::new(key.clone());
            let restarted = EndpointConfig::new(key);
            assert_eq!(
                ResetToken::new(&first.reset_key, cid),
                ResetToken::new(&restarted.reset_key, cid)
            );
        }
    }
}
