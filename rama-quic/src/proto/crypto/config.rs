use rama_crypto::digest::sha256;
#[cfg(any(
    feature = "boring",
    all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
))]
use rama_quic_proto::transport_parameters::TransportParameters;
use std::fmt;

use rama_core::error::BoxError;
use rama_net::tls::AlpnPolicy;
pub use rama_tls::client::ClientHandshake;
use rama_utils::macros::generate_set_and_with;

/// Client TLS ticket policy, independent of transport connection pooling.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientSessionPolicy {
    /// Store and offer compatible tickets when the provider has a session cache.
    #[default]
    Reuse,
    /// Always use a full handshake; do not read or retain session tickets.
    /// This also prevents client 0-RTT, even when early application data is allowed.
    Fresh,
}

/// QUIC requirements applied to the common Rama TLS configuration.
#[derive(Clone, Copy, Debug, Default)]
pub struct TlsOptions {
    pub(crate) alpn: AlpnPolicy,
    pub(crate) early_data: bool,
    pub(crate) early_data_context: Option<[u8; 32]>,
    pub(crate) client_sessions: ClientSessionPolicy,
}

impl TlsOptions {
    generate_set_and_with! {
        /// Bind server 0-RTT acceptance to compatible application settings.
        /// Required when a server enables early data; clients ignore it.
        /// Include every application setting or state a resumed early request
        /// could violate. A changed context rejects early data; Rustls also
        /// declines ordinary resumption. QUIC transport parameters are bound
        /// separately by the provider. This does not prevent cross-connection replay.
        pub fn early_data_context(mut self, context: impl AsRef<[u8]>) -> Self {
            self.early_data_context = Some(application_context(context.as_ref()));
            self
        }
    }

    #[cfg(any(
        feature = "boring",
        all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
    ))]
    pub(crate) fn validate_server(&self) -> Result<(), TlsConfigError> {
        if self.early_data && self.early_data_context.is_none() {
            return Err(TlsConfigError::EarlyDataContextRequired);
        }
        Ok(())
    }

    generate_set_and_with! {
        /// Client ticket policy. Servers ignore this client-only option.
        /// Connection pooling remains an independent application decision.
        pub fn client_sessions(mut self, policy: ClientSessionPolicy) -> Self {
            self.client_sessions = policy;
            self
        }
    }

    generate_set_and_with! {
        /// How peers agree on their application protocol.
        /// Direct constructors honor this value over the common TLS configuration.
        /// ClientConfigCache resolves request/config overrides before calling constructors.
        pub fn alpn(mut self, policy: AlpnPolicy) -> Self {
            self.alpn = policy;
            self
        }
    }
    generate_set_and_with! {
        /// Allow early application data, which a peer may replay. Disabled by default.
        /// Servers must also supply [`Self::with_early_data_context`]; construction
        /// fails without it. Clients only need this explicit send capability.
        pub fn early_data(mut self, allowed: bool) -> Self {
            self.early_data = allowed;
            self
        }
    }
}

#[derive(Debug)]
pub enum TlsConfigError {
    BackendUnavailable,
    UnsupportedOutOfBandAgreement,
    Tls13Required,
    AlpnRequired,
    InvalidAlpn,
    UnsupportedDynamicConfig,
    EarlyDataNotEnabled,
    EarlyDataContextRequired,
    NoInitialCipherSuite(NoInitialCipherSuite),
    InvalidConfiguration(BoxError),
}

impl fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendUnavailable => {
                f.write_str("no built-in QUIC TLS configuration provider is available")
            }
            Self::UnsupportedOutOfBandAgreement => f.write_str(
                "this QUIC TLS backend requires ALPN even with out-of-band protocol agreement",
            ),
            Self::Tls13Required => f.write_str("QUIC requires TLS 1.3"),
            Self::AlpnRequired => {
                f.write_str("QUIC requires ALPN unless another protocol agreement is explicit")
            }
            Self::InvalidAlpn => f.write_str("invalid ALPN protocol list"),
            Self::UnsupportedDynamicConfig => f.write_str(
                "per-ClientHello TLS configuration needs a resolving QUIC server configuration",
            ),
            Self::EarlyDataNotEnabled => {
                f.write_str("TLS configuration enables early data without QUIC application opt-in")
            }
            Self::EarlyDataContextRequired => {
                f.write_str("server early data requires an application compatibility context")
            }
            Self::NoInitialCipherSuite(error) => error.fmt(f),
            Self::InvalidConfiguration(error) => {
                write!(f, "invalid QUIC TLS configuration: {error}")
            }
        }
    }
}

impl std::error::Error for TlsConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NoInitialCipherSuite(error) => Some(error),
            Self::InvalidConfiguration(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

impl From<BoxError> for TlsConfigError {
    fn from(error: BoxError) -> Self {
        Self::InvalidConfiguration(error)
    }
}

impl From<NoInitialCipherSuite> for TlsConfigError {
    fn from(error: NoInitialCipherSuite) -> Self {
        Self::NoInitialCipherSuite(error)
    }
}

/// The QUIC initial cipher suite, AES-128-GCM-SHA256, is unavailable or invalid.
#[derive(Clone, Debug)]
pub struct NoInitialCipherSuite {
    pub(crate) specific: bool,
}

impl fmt::Display for NoInitialCipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.specific {
            "invalid cipher suite specified"
        } else {
            "no initial cipher suite found"
        })
    }
}

impl std::error::Error for NoInitialCipherSuite {}

/// Domain-separated application context, retained without allocations in TLS options.
pub(crate) fn application_context(context: &[u8]) -> [u8; 32] {
    sha256([b"rama-quic-application-0rtt-v1".as_slice(), context])
}

/// Bind tickets to stable transport parameters and the application's configuration.
#[cfg(any(
    feature = "boring",
    all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
))]
pub(crate) fn server_early_context(
    params: &TransportParameters,
    application: Option<[u8; 32]>,
) -> [u8; 32] {
    let stable = TransportParameters {
        initial_src_cid: None,
        original_dst_cid: None,
        retry_src_cid: None,
        stateless_reset_token: None,
        preferred_address: None,
        grease_transport_parameter: None,
        extra: Vec::new(),
        write_plan: None,
        version_information: None,
        ..params.clone()
    };
    let mut encoded = Vec::new();
    stable.write(&mut encoded);
    sha256([
        b"rama-quic-server-0rtt-v1".as_slice(),
        &encoded,
        &[u8::from(application.is_some())],
        application.as_ref().map_or(&[], |value| value.as_slice()),
    ])
}
