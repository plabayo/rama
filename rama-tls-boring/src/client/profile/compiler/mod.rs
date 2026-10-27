//! Compile counted TCP TLS observations into ordinary native configuration.
//!
//! Use this compiler with the common UA connect modifier around a TLS connector,
//! supplying the same fixed TLS policy to both. Admission precedes dialing;
//! profile facts and HTTP reuse are published after the native connector reports
//! its negotiated version. When placing that HTTP modifier directly around TLS,
//! enable this crate's `http` feature so the connector reports negotiated HTTP
//! versions. Low-level wire compilation remains available without it.
//! Input bindings are checked at that outer boundary,
//! before application requests or profile facts are released. There is no native
//! callback, generated-hello check or prepared SSL session in request extensions.

use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extensions, ExtensionsRef},
    telemetry::tracing,
};
use rama_net::{
    AuthorityInputExt, Protocol, ProtocolInputExt,
    address::{Host, HostWithOptPort},
    tls::TlsAlpn,
};
use rama_tls::client::{
    ClientHandshake, TlsClientConfig, TlsConnectionReuse, TlsDerivedPolicy, TlsPoolId,
};
use rama_ua::profile::{
    capture::{
        joint::CapturedSlotKind,
        tls::{TlsCapture, TlsCaptureTransport, TlsCapturedExtensionValue},
    },
    replay::{
        connection::{
            PreparedConnectionComponents,
            compiler::{
                CompiledConnectionProfile, ConnectionProfileBindings,
                ConnectionProfileCompiler as Compiler, InstalledConnectionProfile,
            },
        },
        request::{LoweredProfileItem, ProfilePreservationDifference, ProfilePreservationReport},
    },
    selection::variants::ConnectionSelection,
};

use super::wire;
use crate::client::{BoringTlsClientConfigProvider, BoringTlsConnectorConfig};

#[cfg(feature = "http")]
use rama_net::{
    http::{TargetHttpVersion, Version},
    tls::ApplicationProtocol,
};

/// Register with the common UA connect modifier outside the native TLS connector.
///
/// The fixed policy must match that connector's base configuration. Current
/// request overrides keep their normal precedence. Only fresh captured TCP TLS
/// offers are replayed; the native Full offer suppresses cached tickets without
/// disabling the caller's session store or copying sessions into the adapter.
/// Captured items that conflict with the destination or caller are lowered to
/// that behaviour and reported in the connection's preservation report.
#[derive(Debug, Clone)]
pub struct ConnectionProfileCompiler {
    policy: TlsClientConfig,
}

impl ConnectionProfileCompiler {
    pub fn new(policy: TlsClientConfig) -> Self {
        Self { policy }
    }

    pub(super) fn prepare_capture(
        &self,
        input: &(impl AuthorityInputExt + ProtocolInputExt + ExtensionsRef),
        capture: &TlsCapture,
        report: &mut ProfilePreservationReport,
    ) -> Result<CompiledConnection, BoxError> {
        if !matches!(capture.transport, TlsCaptureTransport::Tcp) {
            return Ok(CompiledConnection { tls: None });
        }
        let authority = input.target_authority().ok_or_else(|| {
            BoxError::from_static_str("captured TLS replay requires a destination")
        })?;
        let protocol = input
            .target_protocol()
            .filter(|protocol| protocol.is_secure())
            .ok_or_else(|| {
                BoxError::from_static_str("captured TLS replay requires a secure protocol")
            })?
            .clone();
        let effective = input
            .extensions()
            .fork()
            .with_base(self.policy.as_extensions());
        let current = BoringTlsConnectorConfig::from_extensions(&effective);
        if current
            .pool_id()
            .as_ref()
            .is_some_and(|policy| !policy.is_reusable())
        {
            return Ok(native(report, "caller TLS policy is not comparable"));
        }
        let handshake = if current.client_handshake == Some(&ClientHandshake::Resumed) {
            // Captures are fresh offers; a required session offer is caller policy.
            lower(report, LoweredProfileItem::CallerTlsSessionOffer);
            ClientHandshake::Resumed
        } else {
            ClientHandshake::Full
        };
        let mut settings =
            wire::compile_for_policy(wire::TransportShape::Tcp, capture, &current, report)?;
        let identity = current
            .server_name
            .map(|name| &name.0)
            .unwrap_or(&authority.host);
        let captured_sni = capture.extensions.iter().any(|extension| {
            matches!(
                extension.value,
                TlsCapturedExtensionValue::ServerName { present: true }
            )
        });
        if matches!(identity, Host::Name(_)) != captured_sni {
            // SNI presence follows the destination identity.
            lower(report, LoweredProfileItem::TlsServerNamePresence);
        }
        if let Some(caller) = input.extensions().get_ref::<TlsAlpn>() {
            let offer = settings.alpn();
            if offer.as_ref().is_none_or(|offer| {
                !caller
                    .0
                    .iter()
                    .map(|protocol| protocol.as_bytes())
                    .eq(offer.0.iter().map(|protocol| protocol.as_bytes()))
            }) {
                lower(report, LoweredProfileItem::CallerTlsAlpn);
                settings.set_alpn(caller.0.clone());
            }
        }
        #[cfg(feature = "http")]
        let target = input
            .extensions()
            .get_ref::<TargetHttpVersion>()
            .map(|target| target.0);
        #[cfg(feature = "http")]
        if let Some(target) = target {
            let wanted = match target {
                Version::HTTP_11 => ApplicationProtocol::HTTP_11,
                Version::HTTP_2 => ApplicationProtocol::HTTP_2,
                _ => return Ok(native(report, "target HTTP version has no captured ALPN")),
            };
            let offer = settings.alpn();
            // Without ALPN a TLS connection speaks HTTP/1.1, so such an offer already fits.
            let fits = offer.as_ref().map_or(target == Version::HTTP_11, |offer| {
                offer.0.contains(&wanted) || (target == Version::HTTP_11 && offer.0.is_empty())
            });
            if !fits {
                // The required HTTP version is offered as the native connector would.
                lower(report, LoweredProfileItem::TlsAlpnTargetVersion);
                settings.set_alpn(std::iter::once(wanted).collect());
            }
        }
        settings.set_client_handshake(handshake);
        settings.write_to(&effective);
        if BoringTlsConnectorConfig::from_extensions(&effective)
            .pool_id()
            .is_none_or(|policy| !policy.is_reusable())
        {
            return Ok(native(report, "derived TLS policy is not comparable"));
        }
        let caller = TlsConnectionReuse::new(BoringTlsClientConfigProvider, input.extensions());
        let derived = input.extensions().fork();
        settings.write_to(&derived);
        let Some(reuse) = caller.for_derived_settings(&derived) else {
            return Ok(native(report, "derived TLS reuse is not comparable"));
        };
        let Some(policy) = BoringTlsConnectorConfig::from_extensions(&derived)
            .pool_id()
            .filter(TlsPoolId::is_reusable)
        else {
            return Ok(native(report, "derived TLS policy is not comparable"));
        };
        Ok(CompiledConnection {
            tls: Some(CompiledTls {
                settings,
                reuse,
                bindings: InputBindings {
                    authority,
                    protocol,
                    policy,
                    handshake,
                    #[cfg(feature = "http")]
                    target,
                },
            }),
        })
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
        _selection: &ConnectionSelection,
        components: &mut PreparedConnectionComponents,
    ) -> Result<Self::Compiled, BoxError> {
        let Some(capture) = components.tls.as_ref() else {
            return Ok(CompiledConnection { tls: None });
        };
        let compiled = self.prepare_capture(input, capture, &mut components.preservation_report)?;
        if compiled.tls.is_some() {
            components.tls.take();
        }
        Ok(compiled)
    }
}

fn lower(report: &mut ProfilePreservationReport, item: LoweredProfileItem) {
    report.push(ProfilePreservationDifference::LoweredProfileItem { item });
}

/// Native TLS for this connection: the captured offer cannot be replayed safely.
fn native(report: &mut ProfilePreservationReport, reason: &'static str) -> CompiledConnection {
    tracing::debug!(reason, "captured TLS replay falls back to native TLS");
    lower(report, LoweredProfileItem::TlsNativeConnection);
    CompiledConnection { tls: None }
}

/// Admitted native settings, consumed once before the inner connector runs.
#[derive(Debug)]
pub struct CompiledConnection {
    tls: Option<CompiledTls>,
}

#[derive(Debug)]
struct CompiledTls {
    settings: TlsClientConfig,
    reuse: TlsDerivedPolicy,
    bindings: InputBindings,
}

/// Minimal request requirements retained by the outer modifier's future.
#[derive(Debug)]
pub struct Bindings(Option<InputBindings>);

#[derive(Debug)]
struct InputBindings {
    authority: HostWithOptPort,
    protocol: Protocol,
    policy: TlsPoolId,
    handshake: ClientHandshake,
    #[cfg(feature = "http")]
    target: Option<Version>,
}

impl CompiledConnectionProfile for CompiledConnection {
    fn supports(&self, component: CapturedSlotKind) -> bool {
        self.tls.is_some() && component == CapturedSlotKind::TcpTls
    }
}

impl<Input> InstalledConnectionProfile<Input> for CompiledConnection
where
    Input: AuthorityInputExt + ProtocolInputExt + ExtensionsRef,
{
    type Bindings = Bindings;

    fn apply(self, extensions: &Extensions) -> Self::Bindings {
        Bindings(self.tls.map(|native| {
            native.settings.write_to(extensions);
            extensions.insert(native.reuse);
            native.bindings
        }))
    }
}

impl<Input> ConnectionProfileBindings<Input> for Bindings
where
    Input: AuthorityInputExt + ProtocolInputExt + ExtensionsRef,
{
    fn check(&self, input: &Input) -> Result<(), BoxError> {
        let Some(bindings) = &self.0 else {
            return Ok(());
        };
        let current = BoringTlsConnectorConfig::from_extensions(input.extensions());
        if input.target_authority().as_ref() != Some(&bindings.authority)
            || input.target_protocol() != Some(&bindings.protocol)
            || current.pool_id().as_ref() != Some(&bindings.policy)
            || current.client_handshake != Some(&bindings.handshake)
        {
            return Err(BoxError::from_static_str(
                "prepared TLS destination or policy changed before publication",
            ));
        }
        #[cfg(feature = "http")]
        if input
            .extensions()
            .get_ref::<TargetHttpVersion>()
            .map(|target| target.0)
            != bindings.target
        {
            return Err(BoxError::from_static_str(
                "prepared TLS target HTTP version changed before publication",
            ));
        }
        Ok(())
    }
}
