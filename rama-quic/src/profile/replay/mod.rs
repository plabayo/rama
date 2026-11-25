//! Compile a selected QUIC tuple into ordinary native configuration extensions.
//!
//! The outer UA connect modifier selects and admits a complete connection tuple,
//! then this compiler supplies `TlsClientConfig` and `QuicProfile` extensions.
//! The native connector consumes those settings exactly as it would settings from
//! a custom layer or relay. It owns the endpoint, configuration cache, peer-bound
//! TLS session and connection I/O; it never receives a counted profile.
//!
//! Supply the same fixed policy and provider to the compiler and native connector.
//! The profile inserts its settings when it prepares a connection, so a setting
//! inserted after that wins and an earlier one is replaced. The common UA
//! modifier applies admitted HTTP settings before connecting and publishes profile
//! facts only after its inner connector succeeds. Its context check is at that
//! boundary; a connection-scoped recipe adapts its offer to final endpoint ECH.
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
pub(in crate::profile) mod transport;

use std::sync::Arc;

use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extensions, ExtensionsRef},
};
#[cfg(feature = "boring")]
use rama_net::tls::ServerName;
use rama_net::{AuthorityInputExt, ProtocolInputExt};
use rama_quic_proto::profile::{InitialFlightLayout, QuicProfile};
use rama_tls::client::{TlsClientConfig, TlsClientSni, TlsDerivedPolicy, TlsProfilePreparation};
use rama_ua::profile::{
    capture::joint::CapturedSlotKind,
    replay::connection::{
        PreparedConnectionComponents,
        compiler::{
            CompiledConnectionProfile, ConnectionProfileCompiler as Compiler,
            ConnectionProfileInput, InstalledConnectionProfile,
        },
        preparation::ConnectionPreparation,
    },
    selection::variants::ConnectionSelection,
};
#[cfg(feature = "boring")]
use {
    crate::tls::BoringTlsProvider,
    rama_core::{extensions::Extension, telemetry::tracing},
    rama_net::tls::{ApplicationProtocol, TlsAlpn},
    rama_tls::{
        alpn::required_alpn_override,
        client::{
            TlsClientConfigProvider as _, TlsConnectionReuse, TlsSessionProfileScope,
            target_ech_ready,
        },
    },
    rama_tls_boring::client::profile::wire,
    rama_ua::{
        TlsAgent, UserAgent,
        profile::{
            capture::tls::TlsCaptureTransport,
            replay::request::{
                LoweredProfileItem, ProfilePreservationDifference, ProfilePreservationReport,
            },
        },
    },
    rama_utils::fmt::hex,
};

use crate::tls::QuicClientConfigProvider;

/// Register with the outer UA connect modifier around a native QUIC connector.
///
/// Supply the same fixed TLS policy and provider as that connector. The profile
/// inserts its settings when it prepares a connection, so a setting inserted
/// after that wins and an earlier one is replaced. Compile once for each connection
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

    fn ech_ready(&self, input: &Input) -> bool {
        #[cfg(feature = "boring")]
        {
            self.provider.pool_classifier() == BoringTlsProvider::new().pool_classifier()
                && target_ech_ready(input, self.policy.as_extensions())
        }
        #[cfg(not(feature = "boring"))]
        {
            let _ = input;
            false
        }
    }

    fn compile(
        &self,
        input: &Input,
        selection: &ConnectionSelection,
        components: &mut PreparedConnectionComponents,
    ) -> Result<CompiledConnection, BoxError> {
        #[cfg(feature = "boring")]
        let captured_policy = if selection.ech_ready {
            components.tls.as_ref().map(wire::captured_sni_policy)
        } else {
            None
        };
        #[cfg(not(feature = "boring"))]
        let captured_policy = None;
        components.use_ech_outer_for_replay(selection.ech_ready)?;
        let mut compiled = self.compile_recipe(input, selection, components, captured_policy)?;
        if let Some(native) = &mut compiled.native {
            let original = ConnectionProfileInput::new(input);
            let selection = selection.clone();
            let compiler = self.clone();
            #[cfg(feature = "boring")]
            let early_facts = {
                let facts = Extensions::new();
                facts.insert(selection.clone());
                facts.insert(components.preservation_report.clone());
                facts
            };
            native.profile = Some(TlsProfilePreparation::new(
                move |resolution, effective, request| {
                    #[cfg(feature = "boring")]
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
                    let (components, compiled) =
                        selected.prepare_for_replay_with(|components| {
                            #[cfg(feature = "boring")]
                            let captured = selected
                                .ech_ready
                                .then(|| components.tls.as_ref().map(wire::captured_sni_policy))
                                .flatten();
                            #[cfg(not(feature = "boring"))]
                            let captured = None;
                            components.use_ech_outer_for_replay(selected.ech_ready)?;
                            compiler.compile_recipe(&input, &selected, components, captured)
                        })?;
                    let native = compiled.native.ok_or_else(|| {
                        BoxError::from_static_str("drawn QUIC offer cannot be prepared")
                    })?;
                    native.tls.write_to(effective);
                    native.tls.write_to(request);
                    if let Some(transport) = native.transport {
                        request.insert_arc(transport);
                    }
                    effective.insert(native.reuse.clone());
                    request.insert(native.reuse);
                    #[cfg(feature = "boring")]
                    {
                        effective.insert(native.scope.clone());
                        request.insert(native.scope);
                    }
                    let report = ConnectionPreparation::apply_reprepared_http(
                        selected.clone(),
                        components,
                        request,
                    )?;
                    let facts = Extensions::new();
                    facts.insert(selected);
                    facts.insert(report);
                    Ok(facts)
                },
            ));
        }
        Ok(compiled)
    }
}

#[cfg(feature = "boring")]
fn lower(report: &mut ProfilePreservationReport, item: LoweredProfileItem) {
    report.push(ProfilePreservationDifference::LoweredProfileItem { item });
}

/// Admitted settings moved into the request before the native connector runs.
#[derive(Debug)]
pub struct CompiledConnection {
    native: Option<CompiledQuic>,
    /// Transport replayed under the caller's own TLS configuration.
    caller_tls_transport: Option<QuicProfile>,
}

#[derive(Debug)]
struct CompiledQuic {
    tls: TlsClientConfig,
    transport: Option<Arc<QuicProfile>>,
    reuse: TlsDerivedPolicy,
    profile: Option<TlsProfilePreparation>,
    #[cfg(feature = "boring")]
    scope: AppliedSessionScope,
}

// Retry the same request without treating our installed scope as new caller
// input. Arc identity also distinguishes a later caller replacement. Both values
// share their existing storage; no native session or copied settings are kept.
#[cfg(feature = "boring")]
#[derive(Debug, Clone, Extension)]
#[extension(tags(ua), scope(connection))]
struct AppliedSessionScope {
    caller: Option<Arc<TlsSessionProfileScope>>,
    installed: Arc<TlsSessionProfileScope>,
}

/// A compiled captured ClientHello owns its connection-dependent wire choices.
#[cfg(feature = "boring")]
pub(crate) fn has_captured_tls(extensions: &Extensions) -> bool {
    extensions.contains::<AppliedSessionScope>()
}

impl CompiledConnectionProfile for CompiledConnection {
    fn supports(&self, component: CapturedSlotKind) -> bool {
        let Some(native) = &self.native else {
            return matches!(
                component,
                CapturedSlotKind::QuicParameters | CapturedSlotKind::QuicVersions
            ) && self.caller_tls_transport.is_some();
        };
        match component {
            CapturedSlotKind::QuicTls | CapturedSlotKind::TlsOuter => true,
            CapturedSlotKind::QuicFirstFlight => native.transport.as_ref().is_some_and(|profile| {
                matches!(
                    profile.packetization().layout(),
                    InitialFlightLayout::Recorded(_)
                )
            }),
            CapturedSlotKind::QuicParameters
            | CapturedSlotKind::QuicOuterParameters
            | CapturedSlotKind::QuicVersions => native.transport.is_some(),
            _ => false,
        }
    }
}

impl<Input> InstalledConnectionProfile<Input> for CompiledConnection {
    type Bindings = ();

    fn apply(self, extensions: &Extensions) {
        if let Some(transport) = self.caller_tls_transport {
            extensions.insert(transport);
        }
        if let Some(native) = self.native {
            native.tls.write_to(extensions);
            if let Some(transport) = native.transport {
                extensions.insert_arc(transport);
            }
            extensions.insert(native.reuse);
            if let Some(profile) = native.profile {
                extensions.insert(profile);
            }
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
        _captured_policy: Option<TlsClientSni>,
    ) -> Result<CompiledConnection, BoxError> {
        let _ = (&self.policy, &self.provider);
        Ok(CompiledConnection {
            native: None,
            caller_tls_transport: None,
        })
    }

    #[cfg(feature = "boring")]
    fn compile_recipe(
        &self,
        input: &(impl AuthorityInputExt + ProtocolInputExt + ExtensionsRef),
        selection: &ConnectionSelection,
        components: &mut PreparedConnectionComponents,
        captured_policy: Option<TlsClientSni>,
    ) -> Result<CompiledConnection, BoxError> {
        let unsupported = || CompiledConnection {
            native: None,
            caller_tls_transport: None,
        };
        if components.tls.is_none() && caller_keeps_tls(input.extensions()) {
            return caller_tls_transport(components);
        }
        if self.provider.pool_classifier() != BoringTlsProvider::new().pool_classifier() {
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
        // An explicit caller offer replaces the captured one, lowered to carry HTTP/3.
        let caller_alpn = input.extensions().get_ref::<TlsAlpn>().map(|offer| {
            required_alpn_override(ApplicationProtocol::HTTP_3, Some(offer)).map_or_else(
                || offer.clone(),
                |required| TlsAlpn([required].into_iter().collect()),
            )
        });
        let policy = self.policy.clone().with_overrides(input.extensions());
        let captured_policy =
            captured_policy.unwrap_or_else(|| wire::captured_sni_policy(&capture));
        let captured_sni = captured_policy != TlsClientSni::Disabled;
        let report = &mut components.preservation_report;
        let sni_policy = policy
            .as_extensions()
            .get_ref::<TlsClientSni>()
            .copied()
            .unwrap_or(captured_policy);
        let sends_sni = match policy.as_extensions().get_ref::<ServerName>() {
            Some(name) => sni_policy.sends(name),
            None => sni_policy.sends(&ServerName::try_from(&authority.host)?),
        };
        if captured_sni != sends_sni {
            // SNI presence follows the destination identity.
            lower(report, LoweredProfileItem::TlsServerNamePresence);
        }
        let transport = compile_transport(components, true, selection.ech_ready)?.map(Arc::new);
        let report = &mut components.preservation_report;
        let mut wire = tls::compile(&policy, &capture, report)?;
        let caller_alpn_differs = caller_alpn.as_ref().is_some_and(|caller| {
            wire.as_extensions()
                .get_ref::<TlsAlpn>()
                .is_none_or(|captured| {
                    !caller
                        .0
                        .iter()
                        .map(ApplicationProtocol::as_bytes)
                        .eq(captured.0.iter().map(ApplicationProtocol::as_bytes))
                })
        });
        wire.set_sni_policy(sni_policy);
        if caller_alpn_differs {
            lower(report, LoweredProfileItem::CallerTlsAlpn);
        }
        if let Some(caller) = caller_alpn {
            wire.set_alpn(caller.0);
        }
        wire::narrow_alps(&wire);
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
        let Some(reuse) = caller.for_derived_settings(&derived) else {
            tracing::debug!("captured QUIC TLS policy is not comparable; using native TLS");
            lower(
                &mut components.preservation_report,
                LoweredProfileItem::TlsNativeConnection,
            );
            return Ok(unsupported());
        };
        Ok(CompiledConnection {
            caller_tls_transport: None,
            native: Some(CompiledQuic {
                tls: wire,
                transport,
                reuse,
                profile: None,
                scope: AppliedSessionScope {
                    caller: caller_scope,
                    installed,
                },
            }),
        })
    }
}

/// The caller asked to keep its own TLS via [`TlsAgent::Preserve`].
#[cfg(feature = "boring")]
fn caller_keeps_tls(extensions: &Extensions) -> bool {
    extensions
        .get_ref::<UserAgent>()
        .and_then(UserAgent::tls_agent)
        == Some(TlsAgent::Preserve)
}

/// QUIC transport under the caller's TLS: its ClientHello sizes the Initial
/// packets, so the recorded layout is left out and admission reports the flight.
#[cfg(feature = "boring")]
fn caller_tls_transport(
    components: &mut PreparedConnectionComponents,
) -> Result<CompiledConnection, BoxError> {
    Ok(CompiledConnection {
        native: None,
        caller_tls_transport: compile_transport(components, false, false)?,
    })
}

/// Compile the captured parameter tuple.
#[cfg(feature = "boring")]
fn compile_transport(
    components: &mut PreparedConnectionComponents,
    recorded_layout: bool,
    ech: bool,
) -> Result<Option<QuicProfile>, BoxError> {
    let flight = components.quic_first_flight.take();
    let outer_parameters = components.quic_outer_parameters.take();
    let distinct_outer = outer_parameters.is_some();
    if distinct_outer
        || ech
            && flight
                .as_ref()
                .zip(components.quic_parameters.as_ref())
                .is_some_and(|(flight, parameters)| {
                    !flight
                        .flight
                        .parameters
                        .iter()
                        .copied()
                        .map(u64::from)
                        .eq(parameters.fields.iter().map(|field| field.id))
                })
    {
        lower(
            &mut components.preservation_report,
            LoweredProfileItem::QuicEchOuterParameters,
        );
    }
    let parameters = components.quic_parameters.take();
    let transport = match &parameters {
        Some(parameters) => transport::prepare(
            parameters,
            components.quic_versions.take().as_ref(),
            flight.as_ref(),
            recorded_layout && !distinct_outer,
            ech || distinct_outer,
        )?,
        None => None,
    };
    if transport.is_some()
        && !ech
        && let Some(outer) = &outer_parameters
        && let Some(parameters) = &parameters
    {
        for field in &parameters.fields {
            if !outer.fields.iter().any(|captured| captured.id == field.id) {
                lower(
                    &mut components.preservation_report,
                    LoweredProfileItem::QuicAddedTransportParameter {
                        parameter: field.id,
                    },
                );
            }
        }
    }
    Ok(transport)
}

#[cfg(all(test, feature = "boring"))]
mod tests {
    use rama_core::extensions::NoExtensionsTransfer;
    use rama_quic_proto::{
        Version, transport_parameters::TransportParameterId, version::VersionInformation,
    };
    use rama_ua::profile::capture::{
        completeness::ProfileCaptureCompleteness,
        order::{OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture},
    };

    use super::*;

    #[test]
    fn applied_session_scope_stops_at_child_connections() {
        let extensions = Extensions::new();
        extensions.insert(AppliedSessionScope {
            caller: None,
            installed: Arc::new(TlsSessionProfileScope("profile".into())),
        });
        assert!(has_captured_tls(&extensions.fork()));
        assert!(!has_captured_tls(
            &extensions.fork_connection(&NoExtensionsTransfer::new())
        ));
    }

    #[test]
    fn a_clear_offer_reports_each_parameter_added_to_the_captured_outer() {
        let mut information = Vec::new();
        VersionInformation::new(Version::V2, vec![Version::V2]).write(&mut information);
        let limits = OrderCaptureLimits::default();
        let outer = OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::Complete,
            OrderNamespace::QuicParameter,
            [
                (
                    u64::from(TransportParameterId::InitialSourceConnectionId),
                    &[][..],
                ),
                (
                    u64::from(TransportParameterId::VersionInformation),
                    information.as_slice(),
                ),
            ],
            limits,
        )
        .unwrap();
        let mut parameters = outer.clone();
        let extra = OrderedProtocolCapture::capture(
            ProfileCaptureCompleteness::Complete,
            OrderNamespace::QuicParameter,
            [(u64::from(TransportParameterId::InitialMaxData), &[1][..])],
            limits,
        )
        .unwrap();
        parameters.fields = parameters
            .fields
            .into_vec()
            .into_iter()
            .chain(extra.fields)
            .collect();
        let mut components = PreparedConnectionComponents {
            tls: None,
            tls_outer: None,
            quic_parameters: Some(parameters),
            quic_outer_parameters: Some(outer),
            h3_peer_settings: None,
            h3_settings_evidence: None,
            quic_versions: None,
            h2_early_frames: None,
            quic_first_flight: None,
            h3_sequence: None,
            h3_bootstrap: None,
            preservation_report: ProfilePreservationReport::default(),
        };
        let profile = compile_transport(&mut components, false, false)
            .unwrap()
            .unwrap();
        assert_eq!(profile.versions().original(), Version::V2);
        let added = components
            .preservation_report
            .differences
            .iter()
            .filter_map(|difference| match difference {
                ProfilePreservationDifference::LoweredProfileItem {
                    item: LoweredProfileItem::QuicAddedTransportParameter { parameter },
                } => Some(*parameter),
                _ => None,
            });
        assert!(added.eq([u64::from(TransportParameterId::InitialMaxData)]));
    }
}
