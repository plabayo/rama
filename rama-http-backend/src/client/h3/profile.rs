//! Backend-owned captured TLS preparation for the HTTP/3 connector.
//!
//! The configured provider returns actual native state or declines the capture.
//! Input bindings and provider ownership are checked again before that state is
//! consumed; source data cannot grant the connector additional capabilities.

use std::sync::Arc;

use parking_lot::Mutex;
use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extension, Extensions, ExtensionsRef},
};
use rama_http_types::{Version, conn::TargetHttpVersion};
use rama_net::{
    AuthorityInputExt, Protocol, ProtocolInputExt,
    address::HostWithOptPort,
    client::{
        ConnectRequest,
        pool::{ConnectionReuse, ConnectionReusePolicy, ReuseKey},
    },
    tls::ApplicationProtocol,
};
use rama_quic::{ClientConfig, tls::QuicClientConfigProvider};
use rama_tls::{
    ExtensionId,
    client::{TlsClientConfig, TlsPoolId, TlsServerName},
};
use rama_ua::profile::{
    capture::{
        joint::CapturedSlotKind,
        tls::{TlsCaptureTransport, TlsCapturedExtensionValue},
    },
    model::identity::ConnectionContext,
    replay::{
        connection::{
            PreparedConnectionComponents,
            compiler::{CompiledConnectionProfile, ConnectionProfileCompiler},
        },
        request::ProfilePreservationMode,
    },
    selection::variants::{ConnectionSelection, EmulationContext, ProfileConnectionReuse},
};

/// Native capture compiler from the connector that will consume its output.
///
/// Provider support is discovered by preparing the selected capture. The default
/// provider hook declines it; the Boring hook prepares fresh TLS state. This
/// compiler does not yet implement captured QUIC layouts or H3 sequence contents.
#[derive(Debug, Clone)]
pub struct ConnectionCompiler {
    pub(super) tls: TlsClientConfig,
    pub(super) provider: Arc<dyn QuicClientConfigProvider>,
}

/// Prepared output, applied only after the whole connection passes admission.
#[derive(Debug)]
pub struct CompiledConnection {
    pending: Option<Pending>,
}

#[derive(Debug)]
pub(super) struct Prepared {
    pub config: ClientConfig,
    pub reuse: Box<ReusePolicy>,
}

/// A manually prepared capture without an emulation context cannot match a
/// future request before its connection draw. Keep that connection exclusive.
#[derive(Debug)]
pub(super) enum ReusePolicy {
    Profile(ProfileConnectionReuse),
    Exclusive,
}

impl ReusePolicy {
    pub(super) fn publish(self, extensions: &Extensions) {
        let restriction = ConnectionReuse::restriction(self);
        let policy = match extensions.get_ref::<ConnectionReuse>() {
            Some(tls) => tls.clone().and(restriction),
            None => restriction,
        };
        extensions.insert(policy);
    }
}

impl ConnectionReusePolicy for ReusePolicy {
    fn classifier(&self) -> ReuseKey {
        match self {
            Self::Profile(profile) => profile.classifier(),
            Self::Exclusive => ReuseKey::of::<Self>(),
        }
    }

    fn connection_key(&self) -> Option<ReuseKey> {
        match self {
            Self::Profile(profile) => profile.connection_key(),
            Self::Exclusive => None,
        }
    }

    fn request_key(&self, input: &Extensions) -> Option<ReuseKey> {
        match self {
            Self::Profile(profile) => profile.request_key(input),
            Self::Exclusive => None,
        }
    }
}

#[derive(Debug, Extension)]
pub(super) struct Pending {
    authority: HostWithOptPort,
    protocol: Protocol,
    target: Option<Version>,
    policy: TlsPoolId,
    provider: Arc<dyn QuicClientConfigProvider>,
    connection: ConnectionContext,
    emulation: Option<EmulationContext>,
    prepared: Mutex<Option<Prepared>>,
}

fn invalid(message: &'static str) -> BoxError {
    BoxError::from_static_str(message)
}

/// The same application requirement the ordinary H3 path applies. Native wire
/// overrides stay in the returned configuration, never in the caller's store.
pub(super) fn effective(input: &impl ExtensionsRef, base: &TlsClientConfig) -> TlsClientConfig {
    base.clone()
        .with_overrides(input.extensions())
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect())
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
            return Ok(CompiledConnection { pending: None });
        };
        if !matches!(capture.transport, TlsCaptureTransport::Quic) {
            return Ok(CompiledConnection { pending: None });
        }
        let authority = input
            .target_authority()
            .ok_or_else(|| invalid("captured H3 TLS requires a destination"))?;
        let protocol = input
            .target_protocol()
            .filter(|protocol| protocol.is_secure())
            .ok_or_else(|| invalid("captured H3 TLS requires a secure protocol"))?
            .clone();
        let target = input
            .extensions()
            .get_ref::<TargetHttpVersion>()
            .map(|target| target.0);
        if target.is_some_and(|target| target != Version::HTTP_3) {
            return Err(invalid("captured H3 TLS requires an HTTP/3 target"));
        }
        let offers_h3 = capture.extensions.iter().any(|extension| {
            extension.id == u16::from(ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
                && matches!(&extension.value, TlsCapturedExtensionValue::Protocols(protocols)
                    if protocols.iter().any(|protocol| protocol.as_ref() == ApplicationProtocol::HTTP_3.as_bytes()))
        });
        if !offers_h3 {
            return Err(invalid("captured TLS offer excludes HTTP/3 ALPN"));
        }
        let tls = effective(input, &self.tls);
        let peer = tls
            .as_extensions()
            .get_ref::<TlsServerName>()
            .map_or_else(|| authority.host.clone(), |name| name.0.clone());
        let reuse = if let Some(context) = EmulationContext::of(input.extensions()) {
            if context.selected.profile_id() != selection.profile
                || context.connection_key != selection.draw
                || context
                    .pins
                    .connection
                    .is_some_and(|pin| pin != selection.variant)
            {
                return Err(invalid(
                    "captured H3 TLS selection differs from its emulation context",
                ));
            }
            ReusePolicy::Profile(ProfileConnectionReuse::new(context, Version::HTTP_3))
        } else {
            ReusePolicy::Exclusive
        };
        let Some(config) = self.provider.captured_client_config(&tls, peer, capture)? else {
            return Ok(CompiledConnection { pending: None });
        };
        let policy = self
            .provider
            .pool_id(tls.as_extensions())
            .filter(TlsPoolId::is_reusable)
            .ok_or_else(|| invalid("captured H3 TLS policy cannot be compared safely"))?;
        Ok(CompiledConnection {
            pending: Some(Pending {
                authority,
                protocol,
                target,
                policy,
                provider: self.provider.clone(),
                connection: input
                    .extensions()
                    .get_ref::<ConnectionContext>()
                    .cloned()
                    .unwrap_or_default(),
                emulation: EmulationContext::of(input.extensions()).cloned(),
                prepared: Mutex::new(Some(Prepared {
                    config,
                    reuse: Box::new(reuse),
                })),
            }),
        })
    }
}

impl CompiledConnectionProfile for CompiledConnection {
    fn supports(&self, component: CapturedSlotKind) -> bool {
        self.pending.is_some() && component == CapturedSlotKind::QuicTls
    }

    fn apply(self, extensions: &Extensions) {
        if let Some(pending) = self.pending {
            extensions.insert(pending);
        }
    }
}

impl Pending {
    // Connection draws remain stable across request draws on a pooled connection.
    // Bind the selected immutable view, seed, connection key and connection pin;
    // request keys and request pins do not determine the native TLS offer.
    fn matches_selection(&self, extensions: &Extensions) -> bool {
        if extensions
            .get_ref::<ConnectionContext>()
            .cloned()
            .unwrap_or_default()
            != self.connection
        {
            return false;
        }
        match (&self.emulation, EmulationContext::of(extensions)) {
            (None, None) => true,
            (Some(prepared), Some(current)) => {
                Arc::ptr_eq(&prepared.selected, &current.selected)
                    && prepared.seed == current.seed
                    && prepared.connection_key == current.connection_key
                    && prepared.pins.connection == current.pins.connection
            }
            _ => false,
        }
    }

    pub(super) fn take(
        &self,
        input: &ConnectRequest,
        tls: &TlsClientConfig,
        provider: &Arc<dyn QuicClientConfigProvider>,
    ) -> Result<Prepared, BoxError> {
        if !self.matches_selection(input.extensions())
            || !Arc::ptr_eq(&self.provider, provider)
            || input.target_authority().as_ref() != Some(&self.authority)
            || input.target_protocol() != Some(&self.protocol)
            || input
                .extensions()
                .get_ref::<TargetHttpVersion>()
                .map(|target| target.0)
                != self.target
            || provider.pool_id(tls.as_extensions()).as_ref() != Some(&self.policy)
        {
            return Err(invalid(
                "prepared H3 TLS owner, destination or policy changed before handshake",
            ));
        }
        self.prepared
            .lock()
            .take()
            .ok_or_else(|| invalid("prepared H3 TLS configuration was already consumed"))
    }
}

#[cfg(all(test, feature = "boring"))]
mod tests;
