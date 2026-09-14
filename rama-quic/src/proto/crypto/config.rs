use rama_core::error::BoxError;
use std::fmt;

pub use rama_tls::TlsBackend;
pub use rama_tls::alpn::AlpnPolicy;

/// QUIC requirements applied to the common Rama TLS configuration.
#[derive(Clone, Copy, Debug, Default)]
pub struct TlsOptions {
    pub(crate) backend: rama_tls::TlsBackend,
    pub(crate) alpn: AlpnPolicy,
    pub(crate) early_data: bool,
}

impl TlsOptions {
    pub(crate) fn resolve_backend(self) -> Result<TlsBackend, TlsConfigError> {
        let rustls = cfg!(all(
            feature = "rustls",
            any(feature = "aws-lc", feature = "ring")
        ));
        let boring = cfg!(feature = "boring");
        match self.backend {
            TlsBackend::Auto | TlsBackend::Rustls if rustls => Ok(TlsBackend::Rustls),
            TlsBackend::Auto | TlsBackend::Boring if boring => Ok(TlsBackend::Boring),
            backend => Err(TlsConfigError::BackendUnavailable(backend)),
        }
    }
    rama_utils::macros::generate_set_and_with! {
        /// TLS implementation. Auto prefers Rustls when its crypto provider is enabled.
        pub fn backend(mut self, backend: rama_tls::TlsBackend) -> Self {
            self.backend = backend;
            self
        }
    }
    rama_utils::macros::generate_set_and_with! {
        /// How peers agree on their application protocol.
        pub fn alpn(mut self, policy: AlpnPolicy) -> Self {
            self.alpn = policy;
            self
        }
    }
    rama_utils::macros::generate_set_and_with! {
        /// Allow early application data, which a peer may replay. Disabled by default.
        pub fn early_data(mut self, allowed: bool) -> Self {
            self.early_data = allowed;
            self
        }
    }
}

#[derive(Debug)]
pub enum TlsConfigError {
    BackendUnavailable(rama_tls::TlsBackend),
    UnsupportedOutOfBandAgreement,
    Tls13Required,
    AlpnRequired,
    InvalidAlpn,
    UnsupportedDynamicConfig,
    EarlyDataNotEnabled,
    NoInitialCipherSuite(NoInitialCipherSuite),
    InvalidConfiguration(BoxError),
}

impl fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendUnavailable(backend) => write!(f, "QUIC TLS backend {backend:?} is unavailable"),
            Self::UnsupportedOutOfBandAgreement => f.write_str("this QUIC TLS backend requires ALPN even with out-of-band protocol agreement"),
            Self::Tls13Required => f.write_str("QUIC requires TLS 1.3"),
            Self::AlpnRequired => f.write_str("QUIC requires ALPN unless another protocol agreement is explicit"),
            Self::InvalidAlpn => f.write_str("invalid ALPN protocol list"),
            Self::UnsupportedDynamicConfig => f.write_str("asynchronous per-ClientHello TLS configuration is not supported by this QUIC backend"),
            Self::EarlyDataNotEnabled => f.write_str("TLS configuration enables early data without QUIC application opt-in"),
            Self::NoInitialCipherSuite(error) => error.fmt(f),
            Self::InvalidConfiguration(error) => write!(f, "invalid QUIC TLS configuration: {error}"),
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
