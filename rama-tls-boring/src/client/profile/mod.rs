//! Compile captured TLS connections for this connector's native backend.
//!
//! The compiler prepares fresh native state before transport I/O. Its output
//! carries only wire overrides and a one-use session bound to the current
//! destination and effective TLS policy.

use std::sync::Arc;

use parking_lot::Mutex;
use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extension, Extensions, ExtensionsRef},
};
use rama_net::{
    AuthorityInputExt, Protocol, ProtocolInputExt,
    address::{Host, HostWithOptPort},
};
use rama_tls::client::{TlsClientConfig, TlsPoolId};
use rama_ua::profile::{
    capture::{
        joint::CapturedSlotKind,
        tls::{TlsCapture, TlsCaptureTransport, TlsCapturedExtensionValue},
    },
    replay::{
        connection::{
            PreparedConnectionComponents,
            compiler::{CompiledConnectionProfile, ConnectionProfileCompiler},
        },
        request::ProfilePreservationMode,
    },
    selection::variants::ConnectionSelection,
};

use super::{
    BoringTlsConnectorConfig,
    connector::{HandshakeMetadata, PreparedHandshake},
    session::ConnectorSessions,
};

#[cfg(feature = "http")]
use rama_net::http::{TargetHttpVersion, Version};

#[cfg(feature = "http")]
pub(super) mod reuse;
mod tls;

/// Backend compiler obtained from the TLS connector that will consume it.
///
/// Supports fresh TCP TLS 1.3 first hellos. QUIC captures remain unsupported;
/// selected PSK shapes and configured session stores are rejected. Captures
/// containing explicit padding extensions remain unsupported.
///
/// Existing certificate verification, client credentials and key logging remain
/// application policy. Captured keys, tickets and ciphertext are never reused.
#[derive(Debug, Clone)]
pub struct ConnectionCompiler {
    pub(super) base: Option<TlsClientConfig>,
    pub(super) sessions: Option<Arc<ConnectorSessions>>,
}

/// Validated compiler output; only the registered connector installs it.
#[derive(Debug)]
pub struct CompiledConnection {
    tls: Option<(TlsClientConfig, PendingTlsProfile)>,
}

#[derive(Debug, Extension)]
pub(super) struct PendingTlsProfile {
    authority: HostWithOptPort,
    protocol: Protocol,
    #[cfg(feature = "http")]
    target_version: Option<Version>,
    policy: TlsPoolId,
    metadata: HandshakeMetadata,
    prepared: Mutex<Option<PreparedHandshake>>,
}

fn invalid(message: &'static str) -> BoxError {
    BoxError::from_static_str(message)
}

fn effective(extensions: &Extensions, base: Option<&TlsClientConfig>) -> Extensions {
    let effective = extensions.fork();
    match base {
        Some(base) => effective.with_base(base.as_extensions()),
        None => effective,
    }
}

impl<Input> ConnectionProfileCompiler<Input> for ConnectionCompiler
where
    Input: AuthorityInputExt + ProtocolInputExt + ExtensionsRef,
{
    type Compiled = CompiledConnection;

    fn compile(
        &self,
        input: &Input,
        selection: &ConnectionSelection,
        components: &PreparedConnectionComponents,
        _mode: ProfilePreservationMode,
    ) -> Result<CompiledConnection, BoxError> {
        let Some(capture) = &components.tls else {
            return Ok(CompiledConnection { tls: None });
        };
        let compiled = self.prepare(input, capture)?;
        #[cfg(feature = "http")]
        let compiled = reuse::bind(compiled, input.extensions(), selection)?;
        #[cfg(not(feature = "http"))]
        let _ = selection;
        Ok(compiled)
    }
}

impl ConnectionCompiler {
    fn prepare(
        &self,
        input: &(impl AuthorityInputExt + ProtocolInputExt + ExtensionsRef),
        capture: &TlsCapture,
    ) -> Result<CompiledConnection, BoxError> {
        if !matches!(capture.transport, TlsCaptureTransport::Tcp) {
            return Ok(CompiledConnection { tls: None });
        }
        // A fresh-only compiler cannot silently ignore a configured session
        // store, or offer a ticket absent from the selected captured variant.
        if self.sessions.is_some() {
            return Err(invalid(
                "captured TLS replay with a session store is not implemented",
            ));
        }
        let authority = input
            .target_authority()
            .ok_or_else(|| invalid("captured TLS replay requires a destination"))?;
        let protocol = input
            .target_protocol()
            .filter(|protocol| protocol.is_secure())
            .ok_or_else(|| invalid("captured TLS replay requires a secure protocol"))?
            .clone();
        let effective = effective(input.extensions(), self.base.as_ref());
        let current = BoringTlsConnectorConfig::from_extensions(&effective);
        let wire = tls::compile(capture, current.requested_trust_anchors)?;
        let identity = current
            .server_name
            .map(|name| &name.0)
            .unwrap_or(&authority.host);
        let sends_sni = matches!(identity, Host::Name(_));
        let captured_sni = capture.extensions.iter().any(|extension| {
            matches!(
                extension.value,
                TlsCapturedExtensionValue::ServerName { present: true }
            )
        });
        if sends_sni != captured_sni {
            return Err(invalid(
                "destination identity and captured SNI presence differ",
            ));
        }
        tls::validate_version_bounds(
            capture,
            current.min_version.map(|version| version.0),
            current.max_version.map(|version| version.0),
        )?;
        if let Some(ciphers) = current.cipher_suites
            && !ciphers
                .0
                .iter()
                .copied()
                .map(u16::from)
                .eq(capture.ciphers.iter().copied())
        {
            return Err(invalid(
                "caller cipher policy conflicts with captured TLS ciphers",
            ));
        }
        #[cfg(feature = "http")]
        let target_version = input
            .extensions()
            .get_ref::<TargetHttpVersion>()
            .map(|version| version.0);
        #[cfg(feature = "http")]
        if let Some(target) = target_version {
            let wanted = match target {
                Version::HTTP_11 => rama_net::tls::ApplicationProtocol::HTTP_11,
                Version::HTTP_2 => rama_net::tls::ApplicationProtocol::HTTP_2,
                _ => {
                    return Err(invalid(
                        "captured TCP TLS target HTTP version is unsupported",
                    ));
                }
            };
            if !wire.alpn().is_some_and(|offer| offer.0.contains(&wanted)) {
                return Err(invalid(
                    "captured ALPN offer excludes the required HTTP version",
                ));
            }
        }
        wire.write_to(&effective);
        let native = BoringTlsConnectorConfig::from_extensions(&effective);
        let policy = native
            .pool_id()
            .filter(TlsPoolId::is_reusable)
            .ok_or_else(|| invalid("captured TLS policy cannot be compared safely"))?;
        let mut data = super::TlsConnectorData::try_from(native)?;
        if data.server_name.is_none() {
            data.server_name = Some(authority.host.clone());
        }
        let prepared = PreparedHandshake::try_from(data)?;
        let pending = PendingTlsProfile {
            authority,
            protocol,
            #[cfg(feature = "http")]
            target_version,
            policy,
            metadata: prepared.metadata.clone(),
            prepared: Mutex::new(Some(prepared)),
        };
        Ok(CompiledConnection {
            tls: Some((wire, pending)),
        })
    }
}

impl CompiledConnectionProfile for CompiledConnection {
    fn supports(&self, component: CapturedSlotKind) -> bool {
        self.tls.is_some() && component == CapturedSlotKind::TcpTls
    }

    fn apply(self, extensions: &Extensions) {
        if let Some((wire, pending)) = self.tls {
            wire.write_to(extensions);
            extensions.insert(pending);
        }
    }
}

impl PendingTlsProfile {
    pub(super) fn check(
        &self,
        input: &(impl AuthorityInputExt + ProtocolInputExt + ExtensionsRef),
        base: Option<&TlsClientConfig>,
    ) -> Result<(), BoxError> {
        let effective = effective(input.extensions(), base);
        let policy = BoringTlsConnectorConfig::from_extensions(&effective).pool_id();
        if input.target_authority().as_ref() != Some(&self.authority)
            || input.target_protocol() != Some(&self.protocol)
            || policy.as_ref() != Some(&self.policy)
        {
            return Err(invalid(
                "prepared TLS destination or policy changed before handshake",
            ));
        }
        #[cfg(feature = "http")]
        if input
            .extensions()
            .get_ref::<TargetHttpVersion>()
            .map(|version| version.0)
            != self.target_version
        {
            return Err(invalid(
                "prepared TLS target HTTP version changed before handshake",
            ));
        }
        if self.prepared.lock().is_none() {
            return Err(invalid("prepared TLS session was already consumed"));
        }
        Ok(())
    }

    pub(super) fn metadata(&self) -> &HandshakeMetadata {
        &self.metadata
    }

    pub(super) fn take(&self) -> Result<PreparedHandshake, BoxError> {
        self.prepared
            .lock()
            .take()
            .ok_or_else(|| invalid("prepared TLS session was already consumed"))
    }
}

#[cfg(test)]
mod tests;
