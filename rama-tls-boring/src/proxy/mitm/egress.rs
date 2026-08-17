use rama_boring::x509::store::X509Store;
use rama_core::error::BoxError;
use rama_crypto::pki_types::CertificateDer;
use rama_net::address::Host;
use rama_tls::client::{ServerVerifyMode, TlsClientConfig, TlsServerCertPins, TlsServerTrust};
use rama_utils::macros::generate_set_and_with;
use std::sync::Arc;

use crate::client::BoringClientConfigExt as _;

/// Server-authentication policy for upstream TLS connections made by a
/// [`TlsMitmRelay`](super::TlsMitmRelay).
///
/// This deliberately exposes only certificate/identity verification controls.
/// TLS fingerprint and protocol-negotiation settings remain owned by the relay
/// and mirrored from the ingress ClientHello.
///
/// Merely configuring this policy enables normal certificate and hostname
/// verification. Use [`ServerVerifyMode::Disable`] explicitly to opt out.
#[derive(Debug, Clone)]
pub struct TlsMitmEgressServerAuth {
    config: TlsClientConfig,
}

impl Default for TlsMitmEgressServerAuth {
    fn default() -> Self {
        Self {
            config: TlsClientConfig::new().with_server_verify(ServerVerifyMode::Auto),
        }
    }
}

impl TlsMitmEgressServerAuth {
    /// Create an empty policy using normal server verification and default
    /// trust roots.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    generate_set_and_with! {
        /// Set the upstream identity used for certificate verification.
        ///
        /// A DNS identity is also sent as SNI. Without an explicit identity,
        /// the relay uses the ingress SNI and then the connector-target host.
        pub fn server_name(mut self, server_name: Host) -> Self {
            self.config.set_server_name(server_name);
            self
        }
    }

    generate_set_and_with! {
        /// Set how the upstream certificate is verified.
        pub fn server_verify(mut self, mode: ServerVerifyMode) -> Self {
            self.config.set_server_verify(mode);
            self
        }
    }

    generate_set_and_with! {
        /// Require the upstream leaf certificate to match an applicable pin set.
        pub fn server_cert_pins(mut self, pins: TlsServerCertPins) -> Self {
            self.config.set_server_cert_pins(pins);
            self
        }
    }

    generate_set_and_with! {
        /// Replace the complete upstream trust policy.
        pub fn server_trust(mut self, trust: TlsServerTrust) -> Self {
            self.config.set_server_trust(trust);
            self
        }
    }

    generate_set_and_with! {
        /// Replace the default roots with the supplied upstream trust anchors.
        pub fn server_trust_anchors(
            mut self,
            certificates: impl IntoIterator<Item = CertificateDer<'static>>,
        ) -> Result<Self, BoxError> {
            self.config.try_set_server_trust_anchors(certificates)?;
            Ok(self)
        }
    }

    generate_set_and_with! {
        /// Add certificates to the configured upstream trust roots.
        pub fn extra_server_trust_anchors(
            mut self,
            certificates: impl IntoIterator<Item = CertificateDer<'static>>,
        ) -> Result<Self, BoxError> {
            self.config.try_set_extra_server_trust_anchors(certificates)?;
            Ok(self)
        }
    }

    generate_set_and_with! {
        /// Use Rama's bundled Mozilla roots for upstream verification.
        pub fn webpki_roots(mut self) -> Self {
            self.config.set_webpki_roots();
            self
        }
    }

    generate_set_and_with! {
        /// Set a BoringSSL certificate store for upstream verification.
        ///
        /// The store takes precedence over the backend-neutral trust policy and
        /// is ignored when verification is explicitly disabled.
        pub fn server_verify_cert_store(mut self, store: Arc<X509Store>) -> Self {
            self.config.set_server_verify_cert_store(store);
            self
        }
    }

    pub(super) fn write_to(&self, config: &TlsClientConfig) {
        self.config.write_to(config.as_extensions());
    }
}
