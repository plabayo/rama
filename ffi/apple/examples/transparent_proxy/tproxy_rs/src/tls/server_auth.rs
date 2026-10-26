//! Upstream policy shared by intercepted TCP TLS and QUIC associations.

use rama::{
    crypto::pki_types::CertificateDer,
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
    additional_anchors: Vec<CertificateDer<'static>>,
}

impl DemoServerAuth {
    pub(crate) fn new(config: &crate::config::DemoProxyConfig) -> Result<Self, BoxError> {
        #[allow(unused_mut)]
        let mut additional_anchors = Vec::new();
        #[cfg(any(test, feature = "e2e"))]
        if let Some(pem) = &config.upstream_test_ca_pem {
            additional_anchors.push(
                CertificateDer::from_pem_slice(pem.as_bytes())
                    .context("parse e2e upstream trust anchor")?,
            );
        }
        // Initialize and validate the embedded policy before accepting traffic.
        LazyLock::force(&DENIED_KEYS);
        Ok(Self {
            verify: config.verify_upstream_certificates,
            additional_anchors,
        })
    }

    pub(crate) fn tcp(&self) -> Result<TlsMitmEgressServerAuth, BoxError> {
        let mut auth =
            TlsMitmEgressServerAuth::new().with_server_cert_chain_policy(DENIED_KEYS.clone());
        if self.verify {
            auth = auth.with_platform_verifier();
        }
        if self.additional_anchors.is_empty() {
            Ok(auth)
        } else {
            auth.try_with_extra_server_trust_anchors(self.additional_anchors.clone())
        }
    }

    pub(crate) fn quic(&self, keylog: KeyLogIntent) -> Result<TlsClientConfig, BoxError> {
        let mut config = TlsClientConfig::new()
            .with_server_verify(if self.verify {
                ServerVerifyMode::Auto
            } else {
                ServerVerifyMode::Disable
            })
            .with_server_cert_chain_policy(DENIED_KEYS.clone())
            .with_keylog(keylog);
        if self.verify {
            config = config.with_platform_verifier();
        }
        if self.additional_anchors.is_empty() {
            Ok(config)
        } else {
            config.try_with_extra_server_trust_anchors(self.additional_anchors.clone())
        }
    }
}

#[cfg(test)]
mod tests;
