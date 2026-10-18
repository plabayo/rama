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
        request::ProfilePreservationMode,
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
/// offers are supported; the native Full offer suppresses cached tickets without
/// disabling the caller's session store or copying sessions into the adapter.
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
            return Err(BoxError::from_static_str(
                "captured TLS caller policy cannot be compared safely",
            ));
        }
        if current.client_handshake == Some(&ClientHandshake::Resumed) {
            return Err(BoxError::from_static_str(
                "fresh captured TLS conflicts with a required session offer",
            ));
        }
        let mut settings = wire::compile_for_policy(wire::TransportShape::Tcp, capture, &current)?;
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
            return Err(BoxError::from_static_str(
                "destination identity and captured SNI presence differ",
            ));
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
                return Err(BoxError::from_static_str(
                    "caller and captured ALPN offers conflict",
                ));
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
                _ => {
                    return Err(BoxError::from_static_str(
                        "captured TCP TLS target HTTP version is unsupported",
                    ));
                }
            };
            if !settings
                .alpn()
                .is_some_and(|offer| offer.0.contains(&wanted))
            {
                return Err(BoxError::from_static_str(
                    "captured ALPN offer excludes the required HTTP version",
                ));
            }
        }
        settings.set_client_handshake(ClientHandshake::Full);
        settings.write_to(&effective);
        BoringTlsConnectorConfig::from_extensions(&effective)
            .pool_id()
            .filter(TlsPoolId::is_reusable)
            .ok_or_else(|| {
                BoxError::from_static_str("captured TLS native policy cannot be compared safely")
            })?;
        let caller = TlsConnectionReuse::new(BoringTlsClientConfigProvider, input.extensions());
        let derived = input.extensions().fork();
        settings.write_to(&derived);
        let reuse = caller.for_derived_settings(&derived).ok_or_else(|| {
            BoxError::from_static_str("captured TLS policy cannot be compared safely")
        })?;
        let policy = BoringTlsConnectorConfig::from_extensions(&derived)
            .pool_id()
            .filter(TlsPoolId::is_reusable)
            .ok_or_else(|| {
                BoxError::from_static_str("captured TLS policy cannot be compared safely")
            })?;
        Ok(CompiledConnection {
            tls: Some(CompiledTls {
                settings,
                reuse,
                bindings: InputBindings {
                    authority,
                    protocol,
                    policy,
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
        _mode: ProfilePreservationMode,
    ) -> Result<Self::Compiled, BoxError> {
        let Some(capture) = components.tls.as_ref() else {
            return Ok(CompiledConnection { tls: None });
        };
        let compiled = self.prepare_capture(input, capture)?;
        if compiled.tls.is_some() {
            components.tls.take();
        }
        Ok(compiled)
    }
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
            || current.client_handshake != Some(&ClientHandshake::Full)
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
