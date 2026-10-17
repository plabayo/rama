//! Prepare captured QUIC connection state with the actual consuming provider.
//!
//! The returned configuration stays local to the dial. No request extension,
//! copied destination or provider snapshot is needed to transfer ownership.

#[cfg(feature = "boring")]
pub(crate) mod boring;

use super::QuicClientConfigProvider;
use crate::ClientConfig;
use rama_core::error::BoxError;
use rama_net::address::Host;
use rama_tls::client::TlsClientConfig;
use rama_ua::profile::{
    capture::{joint::CapturedSlotKind, tls::TlsCaptureTransport},
    replay::connection::{PreparedConnectionComponents, compiler::CompiledConnectionProfile},
};

/// Native configuration prepared by the configured provider, if supported.
#[derive(Debug)]
pub struct PreparedConfig(Option<ClientConfig>);

impl PreparedConfig {
    /// Consume native state locally after the complete profile passes admission.
    pub fn into_config(self) -> Option<ClientConfig> {
        self.0
    }
}

impl CompiledConnectionProfile for PreparedConfig {
    fn supports(&self, component: CapturedSlotKind) -> bool {
        self.0.is_some() && component == CapturedSlotKind::QuicTls
    }
}

/// Prepare TLS from already decoded components for this dial's final peer and
/// security policy. Other QUIC components remain subject to whole-profile admission.
pub fn prepare(
    provider: &dyn QuicClientConfigProvider,
    policy: &TlsClientConfig,
    peer: Host,
    components: &mut PreparedConnectionComponents,
) -> Result<PreparedConfig, BoxError> {
    let Some(capture) = components.tls.take() else {
        return Ok(PreparedConfig(None));
    };
    if !matches!(capture.transport, TlsCaptureTransport::Quic) {
        return Ok(PreparedConfig(None));
    }
    Ok(PreparedConfig(
        provider.captured_client_config(policy, peer, capture)?,
    ))
}
