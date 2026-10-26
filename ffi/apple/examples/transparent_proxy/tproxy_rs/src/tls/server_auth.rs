//! Upstream policy shared by intercepted TCP TLS and QUIC associations.

use rama::{
    error::BoxError,
    tls::{
        KeyLogIntent,
        boring::proxy::TlsMitmEgressServerAuth,
        client::{
            DistrustedServerKeys, DynTlsServerCertChainPolicy, ServerVerifyMode, TlsClientConfig,
        },
    },
};
use std::sync::LazyLock;

#[cfg(any(test, feature = "e2e"))]
use rama::{crypto::pki_types::pem::PemObject as _, error::ErrorContext as _};

static DENIED_KEYS: LazyLock<DynTlsServerCertChainPolicy> = LazyLock::new(|| {
    include_str!("../../testdata/distrusted-spki.txt")
        .parse::<DistrustedServerKeys>()
        .expect("checked-in demo SPKI denylist")
        .into()
});

#[derive(Debug, Clone)]
pub(crate) struct DemoServerAuth {
    pub(crate) verify: bool,
    tcp: TlsMitmEgressServerAuth,
    quic: TlsClientConfig,
}

impl DemoServerAuth {
    pub(crate) fn new(config: &crate::config::DemoProxyConfig) -> Result<Self, BoxError> {
        #[allow(unused_mut)]
        let mut additional_anchors: Vec<rama::crypto::pki_types::CertificateDer<'static>> =
            Vec::new();
        #[cfg(any(test, feature = "e2e"))]
        if let Some(pem) = &config.upstream_test_ca_pem {
            additional_anchors.push(
                rama::crypto::pki_types::CertificateDer::from_pem_slice(pem.as_bytes())
                    .context("parse e2e upstream trust anchor")?,
            );
        }
        // Initialize and validate the embedded policy before accepting traffic.
        LazyLock::force(&DENIED_KEYS);
        // Prepare trust configuration once per engine, including test anchors.
        // Verification mode alone changes on live updates; disabled verification
        // never invokes the configured platform verifier.
        let mut tcp = TlsMitmEgressServerAuth::new()
            .with_platform_verifier()
            .with_server_cert_chain_policy(DENIED_KEYS.clone());
        let mut quic = TlsClientConfig::new()
            .with_platform_verifier()
            .with_server_cert_chain_policy(DENIED_KEYS.clone());
        if !additional_anchors.is_empty() {
            tcp = tcp.try_with_extra_server_trust_anchors(additional_anchors.clone())?;
            quic = quic.try_with_extra_server_trust_anchors(additional_anchors)?;
        }
        Ok(Self {
            verify: config.verify_upstream_certificates,
            tcp,
            quic,
        })
    }

    fn mode(&self) -> ServerVerifyMode {
        if self.verify {
            ServerVerifyMode::Auto
        } else {
            ServerVerifyMode::Disable
        }
    }

    pub(crate) fn tcp(&self) -> TlsMitmEgressServerAuth {
        self.tcp.clone().with_server_verify(self.mode())
    }

    pub(crate) fn quic(&self, keylog: KeyLogIntent) -> TlsClientConfig {
        self.quic
            .clone()
            .with_server_verify(self.mode())
            .with_keylog(keylog)
    }
}

#[cfg(test)]
mod tests;
