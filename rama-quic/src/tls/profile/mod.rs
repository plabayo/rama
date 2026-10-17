//! Prepare captured QUIC connection state with the actual consuming provider.
//!
//! The returned configuration stays local to the dial. No request extension,
//! copied destination or provider snapshot is needed to transfer ownership.

#[cfg(feature = "boring")]
pub(crate) mod boring;

use super::ClientConfigCache;
use crate::ClientConfig;
use rama_core::error::BoxError;
use rama_net::address::Host;
use rama_tls::client::{TlsClientConfig, TlsSessionProfileScope};
use rama_ua::profile::{
    capture::{joint::CapturedSlotKind, tls::TlsCaptureTransport},
    format::canonical::ValueId,
    replay::connection::{PreparedConnectionComponents, compiler::CompiledConnectionProfile},
};
use rama_utils::fmt::hex;

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
/// security policy. `profile` is the stable client identity, independent of its
/// connection draws; tickets remain isolated by both it and the caller's existing
/// session scope. Other QUIC components still require whole-profile admission.
pub fn prepare(
    cache: &ClientConfigCache,
    policy: &TlsClientConfig,
    peer: Host,
    profile: ValueId,
    components: &mut PreparedConnectionComponents,
) -> Result<PreparedConfig, BoxError> {
    let Some(capture) = components.tls.take() else {
        return Ok(PreparedConfig(None));
    };
    if !matches!(capture.transport, TlsCaptureTransport::Quic) {
        return Ok(PreparedConfig(None));
    }
    let scope = match policy.as_extensions().get_ref::<TlsSessionProfileScope>() {
        Some(caller) => format!("rama-quic-profile:{}:scope:{}", hex(&profile.0), caller.0),
        None => format!("rama-quic-profile:{}:none", hex(&profile.0)),
    };
    let scoped = policy
        .clone()
        .with_session_profile_scope(TlsSessionProfileScope(scope.into()));
    Ok(PreparedConfig(
        cache.captured_client_config(&scoped, peer, capture)?,
    ))
}
