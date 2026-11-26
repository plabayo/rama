//! Compile counted TCP TLS observations into ordinary native configuration.
//!
//! Use this compiler with the common UA connect modifier around a TLS connector,
//! supplying the same fixed TLS policy to both. Admission precedes dialing;
//! profile facts and HTTP reuse are published after the native connector reports
//! its negotiated version. When placing that HTTP modifier directly around TLS,
//! enable this crate's `http` feature so the connector reports negotiated HTTP
//! versions. Low-level wire compilation remains available without it.
//! Input bindings are checked at that outer boundary,
//! before application requests or profile facts are released. A connection-scoped
//! recipe re-prepares the offer after the native connector resolves endpoint ECH.

use std::sync::Arc;

use parking_lot::Mutex;
use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extensions, ExtensionsRef},
    telemetry::tracing,
};
use rama_net::{
    AuthorityInputExt, Protocol, ProtocolInputExt,
    address::HostWithOptPort,
    tls::{ServerName, TlsAlpn},
};
#[cfg(feature = "http")]
use rama_net::{
    http::{TargetHttpVersion, Version},
    tls::ApplicationProtocol,
};
use rama_tls::client::{
    ClientHandshake, TlsClientConfig, TlsClientSni, TlsConnectionReuse, TlsDerivedPolicy,
    TlsEncryptedClientHello, TlsPoolId, TlsProfilePreparation, target_ech_ready,
};
use rama_ua::profile::{
    capture::{
        joint::CapturedSlotKind,
        tls::{TlsCapture, TlsCaptureTransport},
    },
    replay::{
        connection::{
            PreparedConnectionComponents,
            compiler::{
                CompiledConnectionProfile, ConnectionProfileBindings,
                ConnectionProfileCompiler as Compiler, ConnectionProfileInput,
                InstalledConnectionProfile,
            },
            preparation::ConnectionPreparation,
        },
        request::{LoweredProfileItem, ProfilePreservationDifference, ProfilePreservationReport},
    },
    selection::variants::ConnectionSelection,
};

use rama_utils::macros::generate_set_and_with;

use super::wire::{self, NonNegotiableValues};
use crate::client::{BoringTlsClientConfigProvider, BoringTlsConnectorConfig};

/// Register with the common UA connect modifier outside the native TLS connector.
///
/// The fixed policy must match that connector's base configuration. The profile
/// inserts its settings when it prepares a connection, so a setting inserted
/// after that wins and an earlier one is replaced. Only fresh captured TCP TLS
/// offers are replayed; the native Full offer suppresses cached tickets without
/// disabling the caller's session store or copying sessions into the adapter.
/// Captured items that conflict with the destination or caller are lowered to
/// that behaviour and reported in the connection's preservation report.
///
/// Captured values the backend cannot negotiate are filtered out of the offer
/// unless [`NonNegotiableValues`] retains them.
#[derive(Debug, Clone)]
pub struct ConnectionProfileCompiler {
    policy: TlsClientConfig,
    non_negotiable: NonNegotiableValues,
}

impl ConnectionProfileCompiler {
    pub fn new(policy: TlsClientConfig) -> Self {
        Self {
            policy,
            non_negotiable: NonNegotiableValues::new(),
        }
    }

    generate_set_and_with!(
        /// Set per list whether captured values the backend cannot negotiate are
        /// filtered out (the default) or sent as captured.
        pub fn non_negotiable_values(mut self, values: NonNegotiableValues) -> Self {
            self.non_negotiable = values;
            self
        }
    );

    pub(super) fn prepare_capture(
        &self,
        input: &(impl AuthorityInputExt + ProtocolInputExt + ExtensionsRef),
        capture: &TlsCapture,
        captured_policy: Option<TlsClientSni>,
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
            current
                .client_handshake
                .copied()
                .unwrap_or(ClientHandshake::Full)
        };
        let mut settings = wire::compile_for_policy(
            wire::TransportShape::Tcp,
            capture,
            &current,
            self.non_negotiable,
            report,
        )?;
        let captured_policy = captured_policy.unwrap_or_else(|| wire::captured_sni_policy(capture));
        let captured_sni = captured_policy != TlsClientSni::Disabled;
        let sni_policy = current.sni_policy.copied().unwrap_or(captured_policy);
        let sends_sni = match current.server_name {
            Some(name) => sni_policy.sends(name),
            None => sni_policy.sends(&ServerName::try_from(&authority.host)?),
        };
        if sends_sni != captured_sni {
            // SNI presence follows the destination identity.
            lower(report, LoweredProfileItem::TlsServerNamePresence);
        }
        settings.set_sni_policy(sni_policy);
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
                wire::set_alpn(&settings, caller.clone());
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
                Version::HTTP_09 | Version::HTTP_10 => None,
                Version::HTTP_11 => Some(ApplicationProtocol::HTTP_11),
                Version::HTTP_2 => Some(ApplicationProtocol::HTTP_2),
                _ => {
                    return Err(BoxError::from_static_str(
                        "captured TCP TLS cannot carry the requested HTTP version",
                    ));
                }
            };
            let offer = settings.alpn();
            // Earlier HTTP versions use the captured TLS offer without ALPN negotiation.
            let fits = match &wanted {
                None => offer.as_ref().is_none_or(|offer| offer.0.is_empty()),
                Some(wanted) => offer.as_ref().map_or(target == Version::HTTP_11, |offer| {
                    offer.0.iter().all(|protocol| protocol == wanted)
                        && (target == Version::HTTP_11 || !offer.0.is_empty())
                }),
            };
            if !fits {
                lower(report, LoweredProfileItem::TlsAlpnTargetVersion);
                wire::set_alpn(&settings, TlsAlpn(wanted.into_iter().collect()));
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
        let intent = settings
            .as_extensions()
            .get_arc::<TlsEncryptedClientHello>();
        Ok(CompiledConnection {
            tls: Some(CompiledTls {
                settings,
                reuse,
                profile: None,
                bindings: InputBindings {
                    authority,
                    protocol,
                    policy,
                    handshake,
                    sni_policy,
                    #[cfg(feature = "http")]
                    target,
                    finalized: None,
                    intent,
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

    fn ech_ready(&self, input: &Input) -> bool {
        target_ech_ready(input, self.policy.as_extensions())
    }

    fn compile(
        &self,
        input: &Input,
        selection: &ConnectionSelection,
        components: &mut PreparedConnectionComponents,
    ) -> Result<Self::Compiled, BoxError> {
        let captured_policy = if selection.ech_ready {
            components.tls.as_ref().map(wire::captured_sni_policy)
        } else {
            None
        };
        components.use_ech_outer_for_replay(selection.ech_ready)?;
        let Some(capture) = components.tls.as_ref() else {
            return Ok(CompiledConnection { tls: None });
        };
        let mut compiled = self.prepare_capture(
            input,
            capture,
            captured_policy,
            &mut components.preservation_report,
        )?;
        if let Some(tls) = &mut compiled.tls {
            components.tls.take();
            let original = ConnectionProfileInput::new(input);
            let selection = selection.clone();
            let compiler = self.clone();
            let finalized = Arc::new(Mutex::new(None));
            tls.bindings.finalized = Some(finalized.clone());
            let early_facts = Extensions::new();
            early_facts.insert(selection.clone());
            early_facts.insert(components.preservation_report.clone());
            tls.profile = Some(TlsProfilePreparation::new(
                move |resolution, effective, request| {
                    if selection.ech_ready == resolution.config.is_some() {
                        if let Some(report) = request.get_arc::<ProfilePreservationReport>() {
                            let facts = Extensions::new();
                            facts.insert(selection.clone());
                            facts.insert_arc(report);
                            return Ok(facts);
                        }
                        return Ok(early_facts.clone());
                    }
                    let input = ConnectionProfileInput::new(&original);
                    let selected =
                        input.selection_for_ech(&selection, resolution.config.is_some())?;
                    let (components, mut compiled) =
                        selected.prepare_for_replay_with(|components| {
                            let captured_policy = if selected.ech_ready {
                                components.tls.as_ref().map(wire::captured_sni_policy)
                            } else {
                                None
                            };
                            components.use_ech_outer_for_replay(selected.ech_ready)?;
                            let capture = components.tls.as_ref().ok_or_else(|| {
                                BoxError::from_static_str("drawn profile has no TLS offer")
                            })?;
                            compiler.prepare_capture(
                                &input,
                                capture,
                                captured_policy,
                                &mut components.preservation_report,
                            )
                        })?;
                    let native = compiled.tls.take().ok_or_else(|| {
                        BoxError::from_static_str("drawn TLS offer cannot be prepared")
                    })?;
                    native.settings.write_to(effective);
                    native.settings.write_to(request);
                    effective.insert(native.reuse.clone());
                    request.insert(native.reuse);
                    let report = ConnectionPreparation::apply_reprepared_http(
                        selected.clone(),
                        components,
                        request,
                    )?;
                    let facts = Extensions::new();
                    facts.insert(selected);
                    facts.insert(report);
                    *finalized.lock() = Some(native.bindings);
                    Ok(facts)
                },
            ));
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
    profile: Option<TlsProfilePreparation>,
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
    sni_policy: TlsClientSni,
    #[cfg(feature = "http")]
    target: Option<Version>,
    finalized: Option<Arc<Mutex<Option<Self>>>>,
    intent: Option<Arc<TlsEncryptedClientHello>>,
}

impl CompiledConnectionProfile for CompiledConnection {
    fn supports(&self, component: CapturedSlotKind) -> bool {
        self.tls.is_some()
            && matches!(
                component,
                CapturedSlotKind::TcpTls | CapturedSlotKind::TlsOuter
            )
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
            if let Some(profile) = native.profile {
                extensions.insert(profile);
            }
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
        let finalized = bindings.finalized.as_ref().map(|shared| shared.lock());
        let bindings = finalized
            .as_ref()
            .and_then(|bindings| bindings.as_ref())
            .unwrap_or(bindings);
        let mut current = BoringTlsConnectorConfig::from_extensions(input.extensions());
        if finalized
            .as_ref()
            .is_some_and(|finalized| finalized.is_none())
        {
            current.encrypted_client_hello = bindings.intent.as_deref();
            current.sni_policy = Some(&bindings.sni_policy);
        }
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
