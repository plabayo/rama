//! Compile a selected QUIC tuple into ordinary native configuration extensions.
//!
//! The outer UA connect modifier selects and admits a complete connection tuple,
//! then this compiler supplies `TlsClientConfig` and `QuicProfile` extensions.
//! The native connector consumes those settings exactly as it would settings from
//! a custom layer or relay. It owns the endpoint, configuration cache, peer-bound
//! TLS session and connection I/O; it never receives a counted profile.
//!
//! Supply the same fixed policy and provider to the compiler and native connector.
//! Current request overrides retain their ordinary precedence. The common UA
//! modifier applies admitted HTTP settings before connecting and publishes profile
//! facts only after its inner connector succeeds. Its context check is at that
//! boundary; this compiler introduces no native callback or generated-hello check.
//!
//! The ticket namespace combines the stable profile identity with the caller's
//! scope, independently of each connection draw. A private UA marker shares the
//! installed and original scope values so a repeated preparation cannot wrap the
//! namespace again. It holds no native session, provider or TLS configuration.
//!
//! Capability admission covers only the native subset actually compiled here.
//! In particular, HTTP/3 startup/QPACK sequences need their own implementation;
//! a decoded capture alone does not grant replay support.

#[cfg(feature = "boring")]
pub(crate) mod tls;
#[cfg(feature = "boring")]
mod transport;

use std::sync::Arc;

use crate::tls::QuicClientConfigProvider;
use rama_core::{
    error::BoxError,
    extensions::{Extensions, ExtensionsRef},
};
use rama_net::{AuthorityInputExt, ProtocolInputExt};
use rama_quic_proto::profile::{InitialFlightLayout, QuicProfile};
use rama_tls::client::{TlsClientConfig, TlsDerivedPolicy};
use rama_ua::profile::{
    capture::joint::CapturedSlotKind,
    replay::{
        connection::{
            PreparedConnectionComponents,
            compiler::{
                CompiledConnectionProfile, ConnectionProfileCompiler as Compiler,
                InstalledConnectionProfile,
            },
        },
        request::ProfilePreservationMode,
    },
    selection::variants::ConnectionSelection,
};

#[cfg(feature = "boring")]
use {
    crate::tls::BoringTlsProvider,
    rama_core::{error::BoxErrorExt as _, extensions::Extension},
    rama_net::{
        address::Host,
        tls::{ApplicationProtocol, TlsAlpn},
    },
    rama_tls::{
        alpn::required_alpn_override,
        client::{
            TlsClientConfigProvider as _, TlsConnectionReuse, TlsServerName, TlsSessionProfileScope,
        },
    },
    rama_ua::profile::capture::tls::{TlsCaptureTransport, TlsCapturedExtensionValue},
    rama_utils::fmt::hex,
};

/// Register with the outer UA connect modifier around a native QUIC connector.
///
/// Supply the same fixed TLS policy and provider as that connector. Request
/// overrides retain their normal precedence. Compile once for each connection
/// input; use a fresh input to select a different native recipe. Captured TLS
/// currently requires BoringSSL; other providers report unsupported components
/// during admission.
#[derive(Debug, Clone)]
pub struct ConnectionProfileCompiler {
    policy: TlsClientConfig,
    provider: Arc<dyn QuicClientConfigProvider>,
}

impl ConnectionProfileCompiler {
    pub fn new(policy: TlsClientConfig, provider: Arc<dyn QuicClientConfigProvider>) -> Self {
        Self { policy, provider }
    }
}

impl<Input> Compiler<Input> for ConnectionProfileCompiler
where
    Input: AuthorityInputExt + ProtocolInputExt + ExtensionsRef,
{
    type Compiled = CompiledConnection;

    fn compile(
        &self,
        input: &Input,
        selection: &ConnectionSelection,
        components: &mut PreparedConnectionComponents,
        _mode: ProfilePreservationMode,
    ) -> Result<CompiledConnection, BoxError> {
        self.compile_recipe(input, selection, components)
    }
}

/// Admitted settings moved into the request before the native connector runs.
#[derive(Debug)]
pub struct CompiledConnection {
    native: Option<CompiledQuic>,
}

#[derive(Debug)]
struct CompiledQuic {
    tls: TlsClientConfig,
    transport: Option<QuicProfile>,
    reuse: TlsDerivedPolicy,
    #[cfg(feature = "boring")]
    scope: AppliedSessionScope,
}

// Retry the same request without treating our installed scope as new caller
// input. Arc identity also distinguishes a later caller replacement. Both values
// share their existing storage; no native session or copied settings are kept.
#[cfg(feature = "boring")]
#[derive(Debug, Clone, Extension)]
#[extension(tags(ua))]
struct AppliedSessionScope {
    caller: Option<Arc<TlsSessionProfileScope>>,
    installed: Arc<TlsSessionProfileScope>,
}

impl CompiledConnectionProfile for CompiledConnection {
    fn supports(&self, component: CapturedSlotKind) -> bool {
        let Some(native) = &self.native else {
            return false;
        };
        match component {
            CapturedSlotKind::QuicTls => true,
            CapturedSlotKind::QuicFirstFlight => native.transport.as_ref().is_some_and(|profile| {
                matches!(
                    profile.packetization().layout(),
                    InitialFlightLayout::Recorded(_)
                )
            }),
            CapturedSlotKind::QuicParameters | CapturedSlotKind::QuicVersions => {
                native.transport.is_some()
            }
            _ => false,
        }
    }
}

impl<Input> InstalledConnectionProfile<Input> for CompiledConnection {
    type Bindings = ();

    fn apply(self, extensions: &Extensions) {
        if let Some(native) = self.native {
            native.tls.write_to(extensions);
            if let Some(transport) = native.transport {
                extensions.insert(transport);
            }
            extensions.insert(native.reuse);
            #[cfg(feature = "boring")]
            extensions.insert(native.scope);
        }
    }
}

impl ConnectionProfileCompiler {
    #[cfg(not(feature = "boring"))]
    fn compile_recipe(
        &self,
        _input: &(impl AuthorityInputExt + ProtocolInputExt + ExtensionsRef),
        _selection: &ConnectionSelection,
        _components: &mut PreparedConnectionComponents,
    ) -> Result<CompiledConnection, BoxError> {
        let _ = (&self.policy, &self.provider);
        Ok(CompiledConnection { native: None })
    }

    #[cfg(feature = "boring")]
    fn compile_recipe(
        &self,
        input: &(impl AuthorityInputExt + ProtocolInputExt + ExtensionsRef),
        selection: &ConnectionSelection,
        components: &mut PreparedConnectionComponents,
    ) -> Result<CompiledConnection, BoxError> {
        let unsupported = || CompiledConnection { native: None };
        if self.provider.pool_classifier() != BoringTlsProvider.pool_classifier() {
            return Ok(unsupported());
        }
        let Some(capture) = components.tls.take() else {
            return Ok(unsupported());
        };
        if !matches!(capture.transport, TlsCaptureTransport::Quic) {
            return Ok(unsupported());
        }
        if input
            .target_protocol()
            .is_none_or(|protocol| !protocol.is_secure())
        {
            return Err(BoxError::from_static_str(
                "captured QUIC requires a secure origin",
            ));
        }
        let authority = input
            .target_authority()
            .ok_or_else(|| BoxError::from_static_str("captured QUIC requires a destination"))?;
        // Admit the original caller offer before installing captured settings.
        // Connector defaults may be replaced; an explicit offer may not.
        let caller_alpn = input.extensions().get_ref::<TlsAlpn>();
        required_alpn_override(ApplicationProtocol::HTTP_3, caller_alpn)?;
        let policy = self.policy.clone().with_overrides(input.extensions());
        let identity = policy
            .as_extensions()
            .get_ref::<TlsServerName>()
            .map_or(&authority.host, |name| &name.0);
        let captured_sni = capture.extensions.iter().any(|extension| {
            matches!(
                extension.value,
                TlsCapturedExtensionValue::ServerName { present: true }
            )
        });
        if captured_sni != matches!(identity, Host::Name(_)) {
            return Err(BoxError::from_static_str(
                "destination identity and captured SNI presence differ",
            ));
        }
        let flight = components.quic_first_flight.take();
        let transport = match components.quic_parameters.take() {
            Some(parameters) => Some(transport::prepare(
                &parameters,
                components.quic_versions.take().as_ref(),
                flight.as_ref(),
            )?),
            None => None,
        };
        if let Some(transport) = &transport
            && input
                .extensions()
                .get_ref::<QuicProfile>()
                .is_some_and(|caller| caller != transport)
        {
            return Err(BoxError::from_static_str(
                "caller and captured QUIC profiles conflict",
            ));
        }
        let wire = tls::compile(&policy, &capture)?;
        if let Some(caller) = caller_alpn {
            let captured = wire.as_extensions().get_ref::<TlsAlpn>();
            if captured.is_none_or(|captured| {
                !caller
                    .0
                    .iter()
                    .map(ApplicationProtocol::as_bytes)
                    .eq(captured.0.iter().map(ApplicationProtocol::as_bytes))
            }) {
                return Err(BoxError::from_static_str(
                    "caller and captured ALPN offers conflict",
                ));
            }
        }
        let current_scope = policy.as_extensions().get_arc::<TlsSessionProfileScope>();
        let caller_scope = match input.extensions().get_ref::<AppliedSessionScope>() {
            Some(previous)
                if current_scope
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &previous.installed)) =>
            {
                previous.caller.clone()
            }
            _ => current_scope,
        };
        let scope = match &caller_scope {
            Some(caller) => format!(
                "rama-quic-profile:{}:scope:{}",
                hex(&selection.profile.0),
                caller.0
            ),
            None => format!("rama-quic-profile:{}:none", hex(&selection.profile.0)),
        };
        let installed = Arc::new(TlsSessionProfileScope(scope.into()));
        wire.as_extensions().insert_arc(installed.clone());
        let caller = TlsConnectionReuse::new(self.provider.clone(), input.extensions());
        let derived = input.extensions().fork();
        wire.write_to(&derived);
        let reuse = caller.for_derived_settings(&derived).ok_or_else(|| {
            BoxError::from_static_str("captured QUIC TLS policy cannot be compared safely")
        })?;
        Ok(CompiledConnection {
            native: Some(CompiledQuic {
                tls: wire,
                transport,
                reuse,
                scope: AppliedSessionScope {
                    caller: caller_scope,
                    installed,
                },
            }),
        })
    }
}
