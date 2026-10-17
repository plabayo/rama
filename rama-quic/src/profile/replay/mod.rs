//! Prepare a selected QUIC tuple with its consuming provider and current policy.
//!
//! Prepared native state stays local to the dial. TLS and transport parameters
//! are validated together before native handshake output; HTTP/3 stays with its
//! HTTP consumer. Preparing transport rules does not claim first-flight scheduling.

pub mod parameters;
#[cfg(feature = "boring")]
pub(crate) mod tls;
mod transport;

use crate::{ClientConfig, tls::ClientConfigCache};
use rama_core::error::BoxError;
use rama_net::address::Host;
use rama_quic_proto::profile::QuicProfile;
use rama_tls::client::{TlsClientConfig, TlsSessionProfileScope};
use rama_ua::profile::{
    capture::{joint::CapturedSlotKind, tls::TlsCaptureTransport},
    format::canonical::ValueId,
    replay::connection::{PreparedConnectionComponents, compiler::CompiledConnectionProfile},
};
use rama_utils::fmt::hex;

/// Native configuration prepared by the configured provider, if supported.
#[derive(Debug)]
pub struct PreparedConfig {
    client: Option<ClientConfig>,
    transport: Option<QuicProfile>,
}

impl PreparedConfig {
    /// Consume the admitted native TLS configuration and optional QUIC recipe.
    /// The consumer applies the same recipe to its client, transport and endpoint.
    pub fn into_parts(self) -> (Option<ClientConfig>, Option<QuicProfile>) {
        (self.client, self.transport)
    }
}

impl CompiledConnectionProfile for PreparedConfig {
    fn supports(&self, component: CapturedSlotKind) -> bool {
        match component {
            CapturedSlotKind::QuicTls => self.client.is_some(),
            CapturedSlotKind::QuicParameters | CapturedSlotKind::QuicVersions => {
                self.transport.is_some()
            }
            _ => false,
        }
    }
}

/// Prepare correlated TLS and transport rules for the final peer and security policy.
///
/// `profile` is the stable client identity, independent of connection draws; tickets remain isolated by both it and the caller's existing
/// session scope. Parameter replay currently requires version_information and
/// supports at most one literal reserved version at an end of the offered list.
/// Unsupported bindings or layouts fail before dialing. First-flight scheduling
/// and HTTP state require separate admission.
pub fn prepare(
    cache: &ClientConfigCache,
    policy: &TlsClientConfig,
    peer: Host,
    profile: ValueId,
    components: &mut PreparedConnectionComponents,
) -> Result<PreparedConfig, BoxError> {
    let Some(capture) = components.tls.take() else {
        return Ok(PreparedConfig {
            client: None,
            transport: None,
        });
    };
    if !matches!(capture.transport, TlsCaptureTransport::Quic) {
        return Ok(PreparedConfig {
            client: None,
            transport: None,
        });
    }
    let transport = match components.quic_parameters.take() {
        Some(parameters) => Some(transport::prepare(
            parameters,
            components.quic_versions.take().as_ref(),
            components.quic_first_flight.as_ref(),
        )?),
        None => None,
    };
    let (transport, expected_parameters) = match transport {
        Some((transport, expected)) => (Some(transport), Some(expected)),
        None => (None, None),
    };
    let scope = match policy.as_extensions().get_ref::<TlsSessionProfileScope>() {
        Some(caller) => format!("rama-quic-profile:{}:scope:{}", hex(&profile.0), caller.0),
        None => format!("rama-quic-profile:{}:none", hex(&profile.0)),
    };
    let scoped = policy
        .clone()
        .with_session_profile_scope(TlsSessionProfileScope(scope.into()));
    #[cfg(feature = "boring")]
    let client = tls::prepare(cache, &scoped, peer, capture, expected_parameters)?;
    #[cfg(not(feature = "boring"))]
    let client = {
        let _ = (cache, scoped, peer, capture, expected_parameters);
        None
    };
    let transport = client.as_ref().and(transport);
    Ok(PreparedConfig { client, transport })
}
