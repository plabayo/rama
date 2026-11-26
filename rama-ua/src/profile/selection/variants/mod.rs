//! Select correlated connection and request variants within a profile.

pub mod bootstrap;
#[cfg(feature = "tls")]
pub(crate) mod derived;
#[cfg(feature = "tls")]
mod extension_order;
mod reserved_draw;
pub(crate) mod shapes;

use std::{error::Error, fmt, ptr, sync::Arc};

use rama_core::{
    extensions::{Extension, Extensions},
    telemetry::tracing,
};
use rama_http::{HeaderMap, Method, Version};
use rama_net::client::pool::{ConnectionReuse, ConnectionReusePolicy, PoolPartition, ReuseKey};
use rama_utils::octets::kib;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub(crate) use self::shapes::RequestPlanRef;
use self::{
    reserved_draw::ReservedDraws,
    shapes::{RequestShapeCache, request_variants_for_headers},
};
use crate::{
    DeviceKind, HttpAgent, PlatformKind, TlsAgent, UserAgent,
    profile::{
        analysis::{
            capture::{AnalyzedCaptureVariant, VariantValue},
            order::AnalyzedOrderWeight,
            profile::{AnalyzedProfile, AnalyzedProfileScope},
        },
        capture::{
            completeness::ProfileCaptureCompleteness,
            headers::HeaderCapturePolicy,
            joint::{CapturedSlotKind, JointCapture, JointCaptureLimits},
        },
        evidence::counts::ObservationWeight,
        format::canonical::{CanonicalDomain, CanonicalValue, ProfileDataError, ValueId},
        model::{
            identity::{ConnectionContext, FetchContext, FlowKey, ResumptionContext},
            runtime_hints::RequestInitiator,
            scope::ProfileObservationScope,
            ua::UserAgentProfile,
        },
        replay::connection::H3SettingsReplayEvidence,
        selection::{
            DrawDomain, DrawKey, ProfileDraw, ProfileDrawContext, ProfileDrawError, ProfileSeed,
            capabilities::CapabilitySet,
            database::{ProfileCandidateFilter, ProfileCapabilities, UserAgentDatabase},
        },
    },
};

#[cfg(feature = "tls")]
use crate::profile::capture::tls::TlsCaptureLimits;

const SELECTION_PREFIX: &[u8] = b"rama-profile-selection\0";
const MAXIMUM_IDENTITY_BYTES: usize = kib(16);

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
/// Identity filters and evidence preferences applied before a captured profile is drawn.
/// `ech_ready` prefers exact connection captures without excluding derived offers;
/// leaving it unset preserves the observation weights.
pub struct ProfileSelector {
    /// Exact User-Agent of the profiles to draw from, such as one auto-detected
    /// from the request. Emulation relaxes an auto-detected one to the browser family
    /// when no profile has this exact User-Agent; a configured one only by the fallback policy.
    #[serde(default)]
    pub user_agent: Option<Box<str>>,
    /// Captured client family.
    pub client: Option<Box<str>>,
    /// Captured operating-system family.
    pub platform: Option<PlatformKind>,
    /// Captured device class.
    pub device: Option<DeviceKind>,
    /// Maximum number of newest versions per identity group.
    pub latest_versions: Option<usize>,
    /// Known target readiness; exact offers receive twice the observation weight.
    #[serde(default)]
    pub ech_ready: Option<bool>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Extension)]
#[extension(tags(ua))]
/// Optional exact connection and request variant identifiers.
///
/// As a request extension, these replace the profile layer's configured pins for
/// that request only. Unspecified fields remain unpinned.
pub struct VariantPins {
    pub connection: Option<ValueId>,
    pub request: Option<ValueId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Inputs that define one deterministic profile-selection domain.
pub struct SelectionRequest {
    pub client: ProfileSelector,
    pub required: CapabilitySet,
    pub flow: FlowKey,
    pub pins: VariantPins,
}

#[derive(Debug, Clone)]
/// A profile selected for one required capability set and flow.
pub struct SelectedProfile {
    id: ValueId,
    profile: Arc<UserAgentProfile>,
    request_shapes: Arc<RequestShapeCache>,
    #[cfg(feature = "tls")]
    derived_database: Arc<derived::DatabaseEvidence>,
    required: CapabilitySet,
    flow: FlowKey,
    pins: VariantPins,
}

#[derive(Debug, Clone)]
/// Immutable selection and draw coordinates shared by connection and request layers.
/// Only [`Self::publish`] installs it, together with the pool partition that keeps ordinary
/// connections apart; [`Self::of`] reads it back.
///
/// ```
/// # use rama_core::extensions::Extensions;
/// # use rama_ua::profile::selection::variants::EmulationContext;
/// fn install(extensions: &Extensions, context: EmulationContext) {
///     context.publish(extensions);
///     assert!(EmulationContext::of(extensions).is_some());
/// }
/// ```
///
/// Inserting it directly, without its partition, does not compile:
///
/// ```compile_fail
/// # use rama_core::extensions::Extensions;
/// # use rama_ua::profile::selection::variants::EmulationContext;
/// fn install(extensions: &Extensions, context: EmulationContext) {
///     extensions.insert(context);
/// }
/// ```
pub struct EmulationContext {
    pub selected: Arc<SelectedProfile>,
    pub seed: ProfileSeed,
    pub connection_key: DrawKey,
    pub request_key: DrawKey,
    pub pins: VariantPins,
}

/// A published [`EmulationContext`]: private, so no context exists without its partition.
#[derive(Debug, Clone, Extension)]
#[extension(tags(ua))]
struct PublishedEmulation(EmulationContext);

impl EmulationContext {
    /// Publish the selection and its pool partition before looking up a connection.
    /// Existing application partitions are retained, including tenant boundaries.
    pub fn publish(self, extensions: &Extensions) {
        let profile_partition = PoolPartition::of::<Self>();
        let partition = match extensions.get_ref::<PoolPartition>() {
            Some(existing) => existing.and(&profile_partition),
            None => profile_partition,
        };
        extensions.insert(partition);
        extensions.insert(PublishedEmulation(self));
    }

    /// The context [`Self::publish`] installed on `extensions`, if any.
    #[must_use]
    pub fn of(extensions: &Extensions) -> Option<&Self> {
        extensions
            .get_ref::<PublishedEmulation>()
            .map(|published| &published.0)
    }
}

#[derive(Debug, Clone, Serialize, Extension)]
#[extension(tags(ua))]
/// Canonical connection variant and its observation scope.
pub struct PreparedConnectionProfile {
    pub scope: ValueId,
    pub capture: CanonicalValue,
    pub context: ProfileObservationScope,
    pub h3_settings_evidence: Option<H3SettingsReplayEvidence>,
}

/// The evidence used to prepare a connection offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionOfferMode {
    Ordinary,
    RealEch,
    Grease,
    Derived,
}

#[derive(Debug, Clone, Serialize, Extension)]
#[extension(tags(ua), scope(connection))]
/// Deterministic connection draw consumed by protocol connectors, and whether the target was ECH-ready.
pub struct ConnectionSelection {
    pub profile: ValueId,
    pub variant: ValueId,
    pub draw: DrawKey,
    pub analysis_revision: u16,
    pub effective: PreparedConnectionProfile,
    pub ech_ready: bool,
}

#[derive(Debug, Clone, Serialize, Extension)]
#[extension(tags(ua))]
/// Canonical request variant and the flow it must replay.
pub struct PreparedRequestProfile {
    pub scope: ValueId,
    /// Replaced only through [`Self::set_capture`], so a cached plan never outlives it.
    pub(crate) capture: VariantValue,
    pub flow: FlowKey,
    /// How the captured flow relates to [`Self::flow`].
    pub flow_match: FlowMatch,
    /// Cookie layout evidence from this profile for the negotiated HTTP version.
    pub cookie_layout: CookieLayoutEvidence,
    /// Network quality hint values drawn for this request; they fill the capture's placeholders.
    pub network_hints: Box<[(Box<str>, Box<[u8]>)]>,
    /// The capture decoded once for its profile; replay decodes `capture` without it.
    #[serde(skip)]
    pub(crate) plan: Option<RequestPlanRef>,
}

impl PreparedRequestProfile {
    /// The captured request variant to replay.
    #[must_use]
    pub fn capture(&self) -> &VariantValue {
        &self.capture
    }

    /// Replay another capture; the plan cached for the previous one is dropped.
    pub fn set_capture(&mut self, capture: VariantValue) {
        self.capture = capture;
        self.plan = None;
    }
}

/// How a replayed capture's flow relates to the requested flow; the
/// [`ProfileEmulateLayer`](crate::layer::emulate::ProfileEmulateLayer) docs
/// describe how the closest capture is chosen and replayed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub enum FlowMatch {
    /// The capture was recorded for the requested flow.
    #[default]
    Exact,
    /// No capture of the profile covers the requested flow: the closest one of the
    /// same protocol replays, with the caller's own request context fields.
    Nearest {
        /// The capture was recorded for another Fetch mode or destination.
        other_destination: bool,
        /// The capture was recorded for another request method.
        other_method: bool,
    },
}

/// Request-owned values cannot show whether a single captured cookie field
/// contained one pair or several. Multiple cookie fields prove split support;
/// a single field alone supplies no evidence for joining future pairs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub enum CookieLayoutEvidence {
    #[default]
    Unknown,
    Split,
}

#[derive(Debug, Clone, Serialize, Extension)]
#[extension(tags(ua))]
/// Deterministic request draw bound to a selected connection variant.
pub struct RequestSelection {
    pub profile: ValueId,
    pub connection_variant: ValueId,
    pub variant: ValueId,
    pub draw: DrawKey,
    pub analysis_revision: u16,
    pub effective: PreparedRequestProfile,
}

#[derive(Debug, Clone)]
/// Pool reuse policy binding a connection to its profile admission scope.
pub struct ProfileConnectionReuse {
    profile: ValueId,
    connection_pin: Option<ValueId>,
    caller_kept: CallerKept,
    negotiated: Version,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ProfileReuseKey {
    profile: ValueId,
    connection_pin: Option<ValueId>,
    caller_kept: CallerKept,
}

/// Connection layers the caller kept for itself instead of emulating them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CallerKept {
    http: bool,
    tls: bool,
}

impl CallerKept {
    // A connection opened with the caller's own HTTP or TLS must not serve a fully emulated request.
    fn of(extensions: &Extensions) -> Self {
        let agent = extensions.get_ref::<UserAgent>();
        Self {
            http: agent.and_then(UserAgent::http_agent) == Some(HttpAgent::Preserve),
            tls: agent.and_then(UserAgent::tls_agent) == Some(TlsAgent::Preserve),
        }
    }
}

#[derive(Debug, Clone)]
/// Failure to select or validate a captured profile variant.
pub enum SelectionError {
    Data(ProfileDataError),
    Draw(ProfileDrawError),
    MissingProfile,
    MissingFlow,
    MissingCapabilities(CapabilitySet),
    IncompatibleConnectionContext,
    IncompatibleRequestShape,
    IncompatibleNegotiatedProtocol(Version),
    IncompatiblePin(ValueId),
    UnsupportedAlpn(Box<[u8]>),
    MissingHttpAlpn,
    IncompatibleTransport,
}

impl fmt::Display for SelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data(error) => error.fmt(f),
            Self::Draw(error) => error.fmt(f),
            Self::MissingProfile => f.write_str("no profile matches the selector and flow"),
            Self::MissingFlow => f.write_str("no selected profile covers the requested flow"),
            Self::MissingCapabilities(required) => {
                write!(f, "no profile has the required capabilities: {required:?}")
            }
            Self::IncompatibleConnectionContext => {
                f.write_str("profile has no connection variant for the observed context")
            }
            Self::IncompatibleRequestShape => {
                f.write_str("profile has no request variant for the request-owned header shape")
            }
            Self::IncompatibleNegotiatedProtocol(version) => {
                write!(
                    f,
                    "profile is incompatible with negotiated protocol {version:?}"
                )
            }
            Self::IncompatiblePin(pin) => {
                write!(f, "profile does not contain pinned variant {pin:?}")
            }
            Self::UnsupportedAlpn(protocol) => {
                write!(f, "unsupported profile ALPN {protocol:?}")
            }
            Self::MissingHttpAlpn => f.write_str("profile selection requires an HTTP ALPN"),
            Self::IncompatibleTransport => {
                f.write_str("HTTP ALPN set is incompatible with the selected transport")
            }
        }
    }
}

impl Error for SelectionError {}

impl From<ProfileDataError> for SelectionError {
    fn from(value: ProfileDataError) -> Self {
        Self::Data(value)
    }
}

impl From<ProfileDrawError> for SelectionError {
    fn from(value: ProfileDrawError) -> Self {
        Self::Draw(value)
    }
}

impl UserAgentDatabase {
    pub fn select(
        &self,
        request: &SelectionRequest,
        seed: ProfileSeed,
        key: DrawKey,
    ) -> Result<SelectedProfile, SelectionError> {
        let protocol = flow_protocol(&request.flow)?;
        if !protocol_supported(request.required, protocol) {
            return Err(SelectionError::IncompatibleNegotiatedProtocol(protocol));
        }
        let flow = request.flow.canonical(MAXIMUM_IDENTITY_BYTES)?;
        let selection_flow = selection_flow(&request.flow)?;
        let candidates = self.candidates(ProfileCandidateFilter {
            user_agent: request.client.user_agent.as_deref(),
            client: request.client.client.as_deref(),
            platform: request.client.platform,
            device: request.client.device,
            latest_versions: request.client.latest_versions,
            capabilities: ProfileCapabilities::default(),
        })?;
        // The candidate draw weight is computed once, when the candidates are listed.
        let captured = candidates
            .iter()
            .filter_map(|candidate| {
                candidate
                    .profile
                    .captured
                    .as_ref()
                    .map(|analysis| (candidate.profile, analysis, candidate.weight))
            })
            .collect::<Vec<_>>();
        if captured.is_empty() {
            return Err(SelectionError::MissingProfile);
        }
        // The request's version is known only once the connection negotiates one: a profile
        // without the flow under the request's version may hold it under the other.
        let mut other = None;
        let mut matching = Vec::with_capacity(captured.len());
        for (profile, analysis, weight) in captured {
            let mut distance = closest_flow(analysis, &request.flow, flow.id, protocol);
            if distance.is_none() {
                if other.is_none() {
                    other = Some(other_negotiable_flow(
                        &request.flow,
                        request.required,
                        protocol,
                    )?);
                }
                distance = other.as_ref().and_then(Option::as_ref).and_then(
                    |(version, flow, canonical)| closest_flow(analysis, flow, *canonical, *version),
                );
            }
            if let Some(distance) = distance {
                matching.push((profile, analysis, (distance, weight)));
            }
        }
        if matching.is_empty() {
            return Err(SelectionError::MissingFlow);
        }
        matching.retain(|(profile, _analysis, _distance)| {
            CapabilitySet::from(profile.capabilities()).supports(request.required)
        });
        if matching.is_empty() {
            return Err(SelectionError::MissingCapabilities(request.required));
        }
        // Profile capabilities can come from request scopes alone; the connection step
        // needs a captured connection for this transport and context. Endpoint ECH
        // readiness is known only at connect, so matched pairs count here too.
        if request.pins.connection.is_none() {
            let context = flow_connection_context(&request.flow);
            matching.retain(|(profile, analysis, _distance)| {
                self.request_shape_cache(profile).is_some_and(|shapes| {
                    !connection_candidates(
                        analysis,
                        &shapes,
                        &context,
                        request.required,
                        true,
                        ConnectionOffers::WithEch,
                    )
                    .is_empty()
                })
            });
            if matching.is_empty() {
                return Err(SelectionError::IncompatibleConnectionContext);
            }
        }
        for (pin, connection) in [
            (request.pins.connection, true),
            (request.pins.request, false),
        ] {
            let Some(pin) = pin else { continue };
            let context = flow_connection_context(&request.flow);
            matching.retain(|(profile, analysis, _)| {
                if connection {
                    self.request_shape_cache(profile).is_some_and(|shapes| {
                        connection_candidates(
                            analysis,
                            &shapes,
                            &context,
                            request.required,
                            false,
                            ConnectionOffers::WithEch,
                        )
                        .iter()
                        .any(|(_, scope)| {
                            scope
                                .observations
                                .variants
                                .iter()
                                .any(|variant| variant.value.id() == pin)
                        })
                    })
                } else {
                    analysis.scopes.iter().enumerate().any(|(index, scope)| {
                        request_scope_usable(analysis, index, protocol)
                            && scope_flow_distance(scope, &request.flow, flow.id).is_some()
                            && scope
                                .observations
                                .variants
                                .iter()
                                .any(|variant| variant.value.id() == pin)
                    })
                }
            });
            if matching.is_empty() {
                return Err(SelectionError::IncompatiblePin(pin));
            }
        }
        if let Some(pin) = request.pins.request {
            let context = flow_connection_context(&request.flow);
            matching.retain(|(profile, analysis, _)| {
                self.request_shape_cache(profile).is_some_and(|shapes| {
                    connection_candidates(
                        analysis,
                        &shapes,
                        &context,
                        request.required,
                        false,
                        ConnectionOffers::WithEch,
                    )
                    .iter()
                    .any(|(_, scope)| {
                        scope_serves_request_pin(
                            analysis,
                            scope,
                            &request.flow,
                            pin,
                            request.required,
                        ) && request.pins.connection.is_none_or(|connection| {
                            scope
                                .observations
                                .variants
                                .iter()
                                .any(|variant| variant.value.id() == connection)
                        })
                    })
                })
            });
            if matching.is_empty() {
                return Err(SelectionError::IncompatiblePin(pin));
            }
        }
        // Profiles that captured the flow itself win over those that only come close.
        if let Some(closest) = matching
            .iter()
            .map(|(_profile, _analysis, (distance, _weight))| *distance)
            .min()
        {
            matching.retain(|(_profile, _analysis, (distance, _weight))| *distance == closest);
        }
        matching.sort_unstable_by_key(|(_profile, analysis, _distance)| analysis.id);
        let scope = selection_scope(
            matching
                .iter()
                .map(|(_profile, analysis, _distance)| analysis.id),
            selection_flow.id,
            request.required,
        );
        let mut draw = ProfileDraw::new(
            seed,
            ProfileDrawContext {
                profile: scope,
                analysis_revision: matching
                    .iter()
                    .map(|(_profile, analysis, _distance)| analysis.classifier_revision)
                    .max()
                    .unwrap_or_default(),
                scope,
                key,
                domain: DrawDomain::Connection,
                slot: 0,
            },
        );
        let exact_ech = request.client.ech_ready.map(|ech| {
            let context = flow_connection_context(&request.flow);
            matching
                .iter()
                .map(|(profile, analysis, _)| {
                    self.request_shape_cache(profile).is_some_and(|shapes| {
                        connection_candidates(
                            analysis,
                            &shapes,
                            &context,
                            request.required,
                            true,
                            ConnectionOffers::WithEch,
                        )
                        .iter()
                        .any(|(index, scope)| {
                            if request.pins.request.is_some_and(|pin| {
                                !scope_serves_request_pin(
                                    analysis,
                                    scope,
                                    &request.flow,
                                    pin,
                                    request.required,
                                )
                            }) || request.pins.connection.is_some_and(|pin| {
                                !scope
                                    .observations
                                    .variants
                                    .iter()
                                    .any(|variant| variant.value.id() == pin)
                            }) {
                                return false;
                            }
                            if ech {
                                shapes.ech_connection(analysis, *index)
                            } else {
                                shapes.ordinary_connection(analysis, *index)
                            }
                        })
                    })
                })
                .collect::<Vec<_>>()
        });
        let mut weights = matching
            .iter()
            .map(|(_profile, _analysis, (_distance, weight))| analyzed_observation_weight(*weight))
            .collect::<Vec<_>>();
        if let Some(exact) = exact_ech {
            prefer_exact_weights(&mut weights, &exact);
        }
        let selected = draw.weighted_index(&weights)?;
        let (profile, analysis, _distance) = matching
            .get(selected)
            .copied()
            .ok_or(SelectionError::MissingProfile)?;
        Ok(SelectedProfile {
            id: analysis.id,
            profile: Arc::new(profile.clone()),
            request_shapes: self
                .request_shape_cache(profile)
                .ok_or(SelectionError::MissingProfile)?,
            #[cfg(feature = "tls")]
            derived_database: Arc::clone(&self.derived_evidence),
            required: request.required,
            flow: request.flow.clone(),
            pins: request.pins,
        })
    }
}

impl SelectedProfile {
    #[must_use]
    /// Borrow the selected profile.
    pub fn profile(&self) -> &UserAgentProfile {
        &self.profile
    }

    #[must_use]
    /// Return the selected profile identity.
    pub fn profile_id(&self) -> ValueId {
        self.id
    }

    /// Capabilities the selected connection must provide.
    #[must_use]
    pub fn required(&self) -> CapabilitySet {
        self.required
    }

    #[must_use]
    /// Return the requested variant pins.
    pub fn pins(&self) -> VariantPins {
        self.pins
    }

    #[must_use]
    /// Borrow the selected request flow.
    pub fn flow(&self) -> &FlowKey {
        &self.flow
    }

    /// This selection widened to a TLS connection that reached `version` outside the
    /// pre-connect requirement, when the profile holds that version's data.
    pub(crate) fn for_negotiated(&self, version: Version) -> Option<Self> {
        let secure = self.required.tls_tcp || self.required.tls_quic;
        if !secure || protocol_supported(self.required, version) {
            return None;
        }
        let required = match version {
            Version::HTTP_3 => CapabilitySet {
                h3: true,
                tls_quic: true,
                quic: true,
                ..CapabilitySet::default()
            },
            Version::HTTP_2 => CapabilitySet {
                h2: true,
                tls_tcp: true,
                ..CapabilitySet::default()
            },
            Version::HTTP_11 => CapabilitySet {
                h1: true,
                tls_tcp: true,
                ..CapabilitySet::default()
            },
            _ => return None,
        };
        (CapabilitySet::from(self.profile.capabilities()).supports(required)
            && self
                .flow_versions()
                .is_none_or(|versions| protocol_supported(versions, version)))
        .then(|| Self {
            required,
            ..self.clone()
        })
    }

    /// This selection narrowed to the one TCP HTTP version under which the profile holds a
    /// flow for this request, when its offer would let the peer pick the other.
    pub(crate) fn for_flow_version(&self) -> Option<(Version, Self)> {
        if !(self.required.tls_tcp && self.required.h1 && self.required.h2) {
            return None;
        }
        let versions = self.flow_versions()?;
        let (version, required) = match (versions.h1, versions.h2) {
            (true, false) => (
                Version::HTTP_11,
                CapabilitySet {
                    h2: false,
                    ..self.required
                },
            ),
            (false, true) => (
                Version::HTTP_2,
                CapabilitySet {
                    h1: false,
                    ..self.required
                },
            ),
            _ => return None,
        };
        let mut flow = self.flow.clone();
        if let FlowKey::Http {
            version: flow_version,
            ..
        } = &mut flow
        {
            *flow_version = version;
        }
        Some((
            version,
            Self {
                required,
                flow,
                ..self.clone()
            },
        ))
    }

    /// The HTTP versions under which the profile holds a flow of this request's kind.
    fn flow_versions(&self) -> Option<CapabilitySet> {
        let analysis = self.profile.captured.as_ref()?;
        self.request_shapes
            .flow_versions(analysis)
            .of_flow(&self.flow)
    }

    /// Check that the profile supports the negotiated protocol.
    pub fn validate_negotiated_protocol(&self, version: Version) -> Result<(), SelectionError> {
        if protocol_supported(self.required, version) {
            Ok(())
        } else {
            Err(SelectionError::IncompatibleNegotiatedProtocol(version))
        }
    }

    #[must_use]
    /// Bind this selected profile to the supplied deterministic draw keys.
    pub fn emulation_context(
        self: Arc<Self>,
        seed: ProfileSeed,
        connection_key: DrawKey,
        request_key: DrawKey,
    ) -> EmulationContext {
        let pins = self.pins;
        EmulationContext {
            selected: self,
            seed,
            connection_key,
            request_key,
            pins,
        }
    }

    /// Draw a connection offer without endpoint ECH readiness.
    pub fn connection(
        &self,
        context: &ConnectionContext,
        seed: ProfileSeed,
        key: DrawKey,
    ) -> Result<ConnectionSelection, SelectionError> {
        self.connection_with_ech(context, seed, key, false)
    }

    /// Prefer matched ECH pairs only when the backend has a matching endpoint
    /// configuration and caller policy enables ECH. Otherwise draw the ordinary offer.
    pub fn connection_with_ech(
        &self,
        context: &ConnectionContext,
        seed: ProfileSeed,
        key: DrawKey,
        ech: bool,
    ) -> Result<ConnectionSelection, SelectionError> {
        self.connection_with_offer_mode(context, seed, key, ech)
            .map(|(selection, _)| selection)
    }

    /// Draw a connection and report whether its offer required derivation.
    pub fn connection_with_offer_mode(
        &self,
        context: &ConnectionContext,
        seed: ProfileSeed,
        key: DrawKey,
        ech: bool,
    ) -> Result<(ConnectionSelection, ConnectionOfferMode), SelectionError> {
        let analysis = self
            .profile
            .captured
            .as_ref()
            .ok_or(SelectionError::MissingProfile)?;
        // A GREASE offer replays only the variants whose outer the profile's ordinary offers show.
        let offered = |index, variant, offers| {
            offers != ConnectionOffers::GreaseFallback
                || self.request_shapes.grease_variant(analysis, index, variant)
        };
        let pinned = |offers| {
            let mut scopes = connection_candidates(
                analysis,
                &self.request_shapes,
                context,
                self.required,
                self.pins.connection.is_none(),
                offers,
            );
            if let Some(pin) = self.pins.request {
                scopes.retain(|(_, scope)| {
                    scope_serves_request_pin(analysis, scope, &self.flow, pin, self.required)
                });
            }
            if let Some(pin) = self.pins.connection {
                scopes.retain(|(index, scope)| {
                    scope.observations.variants.iter().enumerate().any(
                        |(variant_index, variant)| {
                            variant.value.id() == pin && offered(*index, variant_index, offers)
                        },
                    )
                });
            } else if !self.required.h2
                && self.required.tls_tcp
                && scopes
                    .iter()
                    .any(|(index, _)| self.request_shapes.connection_http1_only(analysis, *index))
            {
                // A captured http/1.1-only offer replays as is; narrowing another one changes
                // more than ALPN. A pinned variant is named by the caller and wins.
                scopes.retain(|(index, _)| {
                    self.request_shapes.connection_http1_only(analysis, *index)
                });
            }
            scopes
        };
        let mut offers = if ech {
            ConnectionOffers::WithEch
        } else {
            ConnectionOffers::Ordinary
        };
        let mut scopes = pinned(offers);
        if scopes.is_empty() && !ech {
            // A browser offers GREASE ECH where no ECH configuration is available.
            offers = ConnectionOffers::GreaseFallback;
            scopes = pinned(offers);
        }
        if scopes.is_empty() && !ech {
            offers = ConnectionOffers::Derived;
            scopes = pinned(offers);
        }
        if let Some(pin) = self.pins.connection {
            if scopes.is_empty() {
                return Err(SelectionError::IncompatiblePin(pin));
            }
        } else if scopes.is_empty() {
            return Err(SelectionError::IncompatibleConnectionContext);
        } else if ech
            && scopes
                .iter()
                .any(|(index, _)| self.request_shapes.ech_connection(analysis, *index))
        {
            scopes.retain(|(index, _)| self.request_shapes.ech_connection(analysis, *index));
        }
        scopes.sort_unstable_by_key(|(_index, scope)| scope.id);
        let mut scope_draw = ProfileDraw::new(
            seed,
            ProfileDrawContext {
                profile: analysis.id,
                analysis_revision: analysis.classifier_revision,
                scope: analysis.id,
                key,
                domain: DrawDomain::Connection,
                slot: 1,
            },
        );
        let weights = scopes
            .iter()
            .map(|(_index, scope)| scope.observations.counts.total)
            .collect::<Vec<_>>();
        let (scope_index, scope) = scopes
            .get(scope_draw.weighted_index(&weights)?)
            .copied()
            .ok_or(SelectionError::IncompatibleConnectionContext)?;
        if context.resumption == ResumptionContext::Fresh
            && scope.context.connection.resumption == ResumptionContext::Unknown
        {
            tracing::debug!(
                context_evidence = "unspecified-resumption",
                "using a captured connection as a fresh template"
            );
        }
        let variant = if let Some(pin) = self.pins.connection {
            scope
                .observations
                .variants
                .iter()
                .enumerate()
                .find(|(variant_index, variant)| {
                    variant.value.id() == pin && offered(scope_index, *variant_index, offers)
                })
                .map(|(_, variant)| variant)
        } else {
            let mut variant_draw = ProfileDraw::new(
                seed,
                ProfileDrawContext {
                    profile: analysis.id,
                    analysis_revision: analysis.classifier_revision,
                    scope: scope.id,
                    key,
                    domain: DrawDomain::Connection,
                    slot: 2,
                },
            );
            let weights = scope
                .observations
                .variants
                .iter()
                .enumerate()
                .map(|(variant_index, variant)| {
                    if offered(scope_index, variant_index, offers) {
                        analyzed_weight(&variant.weight)
                    } else {
                        Ok(0)
                    }
                })
                .collect::<Result<Vec<_>, _>>()?;
            scope
                .observations
                .variants
                .get(variant_draw.weighted_index(&weights)?)
        }
        .ok_or_else(|| {
            self.pins.connection.map_or(
                SelectionError::IncompatibleConnectionContext,
                SelectionError::IncompatiblePin,
            )
        })?;
        // Connection captures are never held compact, so this borrows.
        let capture = variant.value.canonical()?.into_owned();
        let variant = capture.id;
        // Decoded once: every per-connection draw below edits this one capture.
        let limits = JointCaptureLimits::default();
        let mut joint = JointCapture::from_canonical(&capture, limits)?;
        #[cfg(feature = "tls")]
        let derived_order = if offers == ConnectionOffers::Derived {
            derived::derive(
                &mut joint,
                self.request_shapes.ordinary_evidence(analysis),
                || self.derived_database.family_evidence(analysis.id),
            )?
        } else {
            None
        };
        let h3_settings_evidence = H3SettingsReplayEvidence::for_profile(analysis, scope, &joint)?;
        #[cfg(feature = "tls")]
        let mut drawn = match derived_order {
            Some(derived::DerivedExtensionOrder::Captured) => false,
            Some(derived::DerivedExtensionOrder::Shuffled(pinned)) => {
                let mut draw = ProfileDraw::new(
                    seed,
                    ProfileDrawContext {
                        profile: analysis.id,
                        analysis_revision: analysis.classifier_revision,
                        scope: scope.id,
                        key,
                        domain: DrawDomain::TlsExtensions,
                        slot: 0,
                    },
                );
                joint.map_wire_tls(TlsCaptureLimits::default(), |tls| {
                    tls.extensions = extension_order::shuffle(&tls.extensions, &pinned, &mut draw);
                })?;
                true
            }
            None => extension_order::draw_extension_order(
                self.request_shapes.tls_order_scope(analysis, scope_index),
                &mut joint,
                &mut ProfileDraw::new(
                    seed,
                    ProfileDrawContext {
                        profile: analysis.id,
                        analysis_revision: analysis.classifier_revision,
                        scope: scope.id,
                        key,
                        domain: DrawDomain::TlsExtensions,
                        slot: 0,
                    },
                ),
            )?,
        };
        #[cfg(not(feature = "tls"))]
        let mut drawn = false;
        // Only QUIC connections carry reserved identifiers a client draws afresh.
        if contains(analysis.components.quic.as_deref(), scope_index)
            || contains(analysis.components.h3.as_deref(), scope_index)
        {
            drawn |= reserved_draw::draw_reserved(
                &mut joint,
                ReservedDraws {
                    seed,
                    context: ProfileDrawContext {
                        profile: analysis.id,
                        analysis_revision: analysis.classifier_revision,
                        scope: scope.id,
                        key,
                        domain: DrawDomain::ReservedIdentifiers,
                        slot: 0,
                    },
                },
            )?;
        }
        let capture = if drawn || offers == ConnectionOffers::Derived {
            joint.canonical(limits)?
        } else {
            capture
        };
        let mode = match offers {
            ConnectionOffers::WithEch
                if joint
                    .slots
                    .iter()
                    .any(|slot| slot.kind == CapturedSlotKind::TlsOuter) =>
            {
                ConnectionOfferMode::RealEch
            }
            ConnectionOffers::Ordinary | ConnectionOffers::WithEch => ConnectionOfferMode::Ordinary,
            ConnectionOffers::GreaseFallback => ConnectionOfferMode::Grease,
            ConnectionOffers::Derived => ConnectionOfferMode::Derived,
        };
        Ok((
            ConnectionSelection {
                profile: analysis.id,
                variant,
                draw: key,
                analysis_revision: analysis.classifier_revision,
                effective: PreparedConnectionProfile {
                    scope: scope.id,
                    capture,
                    context: scope.context.clone(),
                    h3_settings_evidence,
                },
                ech_ready: ech,
            },
            mode,
        ))
    }

    /// Draw a request variant for the selected connection and flow.
    pub fn request(
        &self,
        connection: &ConnectionSelection,
        flow: &FlowKey,
        headers: &HeaderMap,
        seed: ProfileSeed,
        key: DrawKey,
    ) -> Result<RequestSelection, SelectionError> {
        let analysis = self
            .profile
            .captured
            .as_ref()
            .ok_or(SelectionError::MissingProfile)?;
        if connection.profile != analysis.id {
            return Err(SelectionError::MissingProfile);
        }
        let protocol = flow_protocol(flow)?;
        if !protocol_supported(self.required, protocol) {
            return Err(SelectionError::IncompatibleNegotiatedProtocol(protocol));
        }
        let canonical = flow.canonical(MAXIMUM_IDENTITY_BYTES)?;
        let mut scopes = eligible_request_scopes(
            analysis,
            &connection.effective.context.connection,
            flow,
            canonical.id,
            protocol,
            self.required,
        )
        .collect::<Vec<_>>();
        if let Some(pin) = self.pins.request {
            scopes.retain(|(_index, scope, _distance)| {
                scope
                    .observations
                    .variants
                    .iter()
                    .any(|variant| variant.value.id() == pin)
            });
            if scopes.is_empty() {
                return Err(SelectionError::IncompatiblePin(pin));
            }
        } else if scopes.is_empty() {
            return Err(SelectionError::MissingFlow);
        }
        let closest = scopes
            .iter()
            .map(|(_index, _scope, distance)| *distance)
            .min()
            .unwrap_or_default();
        let flow_match = closest.flow_match();
        if flow_match != FlowMatch::Exact {
            tracing::debug!(
                ?flow_match,
                "no captured scope covers the requested flow; replaying the closest one"
            );
        }

        // Capture request-owned fields once; every candidate compares against
        // the same validated caller input.
        let requested = HeaderCapturePolicy::default().capture(
            ProfileCaptureCompleteness::Complete,
            protocol,
            headers,
            None,
        )?;
        let mut candidates = Vec::new();
        for (index, scope, _distance) in scopes
            .into_iter()
            .filter(|(_index, _scope, distance)| *distance == closest)
        {
            let available: Vec<_> = scope
                .observations
                .variants
                .iter()
                .enumerate()
                .filter(|(_, variant)| {
                    self.pins
                        .request
                        .is_none_or(|pin| variant.value.id() == pin)
                })
                .collect();
            let (variants, covered) = request_variants_for_headers(
                &available,
                protocol,
                &requested,
                analysis,
                index,
                &self.request_shapes,
            )?;
            if !variants.is_empty() {
                candidates.push((index, scope, variants, covered));
            }
        }
        // A scope whose variants fit the caller's request-owned headers wins over one that
        // would replay a different shape, as within a scope; among those, the scopes that
        // recorded the most caller fields, so none is appended outside a captured slot.
        if let Some(best) = candidates.iter().filter_map(|candidate| candidate.3).max() {
            candidates.retain(|candidate| candidate.3 == Some(best));
        } else {
            // Request replay reports the remaining shape differences.
            tracing::debug!(
                "no captured request variant matches the caller headers; replaying a different shape"
            );
        }
        if candidates.is_empty() {
            return Err(SelectionError::IncompatibleRequestShape);
        }
        candidates.sort_unstable_by_key(|(_index, scope, _variants, _covered)| scope.id);

        let mut scope_draw = ProfileDraw::new(
            seed,
            ProfileDrawContext {
                profile: analysis.id,
                analysis_revision: analysis.classifier_revision,
                scope: connection.effective.scope,
                key,
                domain: DrawDomain::Request,
                slot: 0,
            },
        );
        let weights = candidates
            .iter()
            .map(|(_index, _scope, variants, _fits)| variant_weight(variants))
            .collect::<Result<Vec<_>, _>>()?;
        let (index, scope, variants, _fits) = candidates
            .get(scope_draw.weighted_index(&weights)?)
            .ok_or(SelectionError::MissingFlow)?;

        let variant = if let Some(pin) = self.pins.request {
            variants
                .iter()
                .copied()
                .find(|variant| variant.value.id() == pin)
        } else {
            let mut variant_draw = ProfileDraw::new(
                seed,
                ProfileDrawContext {
                    profile: analysis.id,
                    analysis_revision: analysis.classifier_revision,
                    scope: scope.id,
                    key,
                    domain: DrawDomain::Request,
                    slot: 1,
                },
            );
            let weights = variants
                .iter()
                .map(|variant| analyzed_weight(&variant.weight))
                .collect::<Result<Vec<_>, _>>()?;
            variants
                .get(variant_draw.weighted_index(&weights)?)
                .copied()
        }
        .ok_or_else(|| {
            self.pins
                .request
                .map_or(SelectionError::MissingFlow, SelectionError::IncompatiblePin)
        })?;
        let plan = scope
            .observations
            .variants
            .iter()
            .position(|candidate| ptr::eq(candidate, variant))
            .and_then(|position| self.request_shapes.plan(analysis, *index, position));
        let hints = &scope.observations.network_hints;
        let network_hints = if hints.is_empty() {
            Box::default()
        } else {
            let weights = hints
                .iter()
                .map(|hint| analyzed_weight(&hint.weight))
                .collect::<Result<Vec<_>, _>>()?;
            let mut hint_draw = ProfileDraw::new(
                seed,
                ProfileDrawContext {
                    profile: analysis.id,
                    analysis_revision: analysis.classifier_revision,
                    scope: scope.id,
                    key,
                    domain: DrawDomain::NetworkHints,
                    slot: 0,
                },
            );
            hints
                .get(hint_draw.weighted_index(&weights)?)
                .map(|hint| hint.fields.clone())
                .unwrap_or_default()
        };
        Ok(RequestSelection {
            profile: analysis.id,
            connection_variant: connection.variant,
            variant: variant.value.id(),
            draw: key,
            analysis_revision: analysis.classifier_revision,
            effective: PreparedRequestProfile {
                scope: scope.id,
                capture: variant.value.clone(),
                flow: flow.clone(),
                flow_match,
                cookie_layout: self.request_shapes.cookie_layout(analysis, protocol),
                network_hints,
                plan,
            },
        })
    }
}

fn variant_weight(variants: &[&AnalyzedCaptureVariant]) -> Result<u64, SelectionError> {
    variants.iter().try_fold(0_u64, |total, variant| {
        total
            .checked_add(analyzed_weight(&variant.weight)?)
            .ok_or(SelectionError::Data(ProfileDataError::CounterOverflow))
    })
}

impl ProfileConnectionReuse {
    /// `input` holds the connection request's extensions.
    #[must_use]
    pub fn new(context: &EmulationContext, negotiated: Version, input: &Extensions) -> Self {
        Self {
            profile: context.selected.profile_id(),
            connection_pin: context.pins.connection,
            caller_kept: CallerKept::of(input),
            negotiated,
        }
    }

    pub fn publish(self, connection: &Extensions) {
        ConnectionReuse::new(self).publish(connection);
    }
}

impl ConnectionReusePolicy for ProfileConnectionReuse {
    fn classifier(&self) -> ReuseKey {
        ReuseKey::from_bits::<Self>(u128::from(protocol_reuse_class(self.negotiated)))
    }

    fn connection_key(&self) -> Option<ReuseKey> {
        Some(ReuseKey::new(ProfileReuseKey {
            profile: self.profile,
            connection_pin: self.connection_pin,
            caller_kept: self.caller_kept,
        }))
    }

    fn request_key(&self, input: &Extensions) -> Option<ReuseKey> {
        let context = EmulationContext::of(input)?;
        // A pool may use any policy instance with this protocol classifier
        // to derive a request key, including one established for another profile.
        if !protocol_supported(context.selected.required, self.negotiated) {
            return None;
        }

        Some(ReuseKey::new(ProfileReuseKey {
            profile: context.selected.profile_id(),
            connection_pin: context.pins.connection,
            caller_kept: CallerKept::of(input),
        }))
    }
}

fn protocol_reuse_class(version: Version) -> u8 {
    match version {
        Version::HTTP_09 => 0,
        Version::HTTP_10 => 1,
        Version::HTTP_11 => 2,
        Version::HTTP_2 => 3,
        Version::HTTP_3 => 4,
    }
}

/// Distance of the closest request scope of `analysis` that can replay `flow`.
/// The flow under the other HTTP version a connection for `required` may negotiate, if any.
fn other_negotiable_flow(
    flow: &FlowKey,
    required: CapabilitySet,
    protocol: Version,
) -> Result<Option<(Version, FlowKey, ValueId)>, ProfileDataError> {
    let version = match protocol {
        Version::HTTP_11 if required.h2 && required.tls_tcp => Version::HTTP_2,
        Version::HTTP_2 if required.h1 && required.tls_tcp => Version::HTTP_11,
        _ => return Ok(None),
    };
    let mut flow = flow.clone();
    if let FlowKey::Http {
        version: flow_version,
        ..
    } = &mut flow
    {
        *flow_version = version;
    }
    let canonical = flow.canonical(MAXIMUM_IDENTITY_BYTES)?.id;
    Ok(Some((version, flow, canonical)))
}

fn closest_flow(
    analysis: &AnalyzedProfile,
    flow: &FlowKey,
    canonical: ValueId,
    protocol: Version,
) -> Option<FlowDistance> {
    // The version's component list holds exactly its usable scopes, in order.
    protocol_scopes(analysis, protocol)
        .iter()
        .filter_map(|&index| analysis.scopes.get(index))
        .filter(|scope| scope.observations.domain == CanonicalDomain::Joint)
        .filter_map(|scope| scope_flow_distance(scope, flow, canonical))
        .min()
}

/// Indices of the scopes holding data for `version`, as `request_scope_supports` checks.
fn protocol_scopes(analysis: &AnalyzedProfile, version: Version) -> &[usize] {
    let scopes = if matches!(
        version,
        Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11
    ) {
        &analysis.components.h1
    } else if version == Version::HTTP_2 {
        &analysis.components.h2
    } else if version == Version::HTTP_3 {
        &analysis.components.h3
    } else {
        return &[];
    };
    scopes.as_deref().unwrap_or_default()
}

fn request_scope_usable(analysis: &AnalyzedProfile, index: usize, protocol: Version) -> bool {
    analysis
        .scopes
        .get(index)
        .is_some_and(|scope| scope.observations.domain == CanonicalDomain::Joint)
        && request_scope_supports(analysis, index, protocol)
}

/// Connection scopes of `analysis` that can open a connection for `required` in `context`.
/// The captured wire offers a connection draw may replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionOffers {
    Ordinary,
    WithEch,
    GreaseFallback,
    Derived,
}

fn connection_candidates<'a>(
    analysis: &'a AnalyzedProfile,
    shapes: &RequestShapeCache,
    context: &ConnectionContext,
    required: CapabilitySet,
    lower_h2: bool,
    offers: ConnectionOffers,
) -> Vec<(usize, &'a AnalyzedProfileScope)> {
    let offered = |index| match offers {
        ConnectionOffers::Ordinary => shapes.ordinary_connection(analysis, index),
        ConnectionOffers::WithEch => {
            shapes.ordinary_connection(analysis, index) || shapes.ech_connection(analysis, index)
        }
        ConnectionOffers::GreaseFallback => shapes.grease_connection(analysis, index),
        ConnectionOffers::Derived => shapes.ech_connection(analysis, index),
    };
    let candidates = |required| {
        analysis
            .scopes
            .iter()
            .enumerate()
            .filter(|(index, scope)| {
                scope.context.flow.is_none()
                    && offered(*index)
                    && connection_context_matches(&scope.context.connection, context)
                    && scope.observations.domain == CanonicalDomain::Joint
                    && connection_scope_supports(analysis, *index, required)
            })
            .collect::<Vec<_>>()
    };
    let scopes = candidates(required);
    if scopes.is_empty() && lower_h2 && required.h2 {
        // Connections recorded without HTTP/2 SETTINGS still replay their TLS offer;
        // preparation reports the native HTTP/2 settings as lowered.
        return candidates(CapabilitySet {
            h2: false,
            ..required
        });
    }
    scopes
}

fn flow_connection_context(flow: &FlowKey) -> ConnectionContext {
    match flow {
        FlowKey::Http { connection, .. } => connection.clone(),
        FlowKey::Other { .. } => ConnectionContext::default(),
    }
}

fn connection_scope_supports(
    analysis: &AnalyzedProfile,
    index: usize,
    required: CapabilitySet,
) -> bool {
    // A recorded TLS offer cannot be replayed on a cleartext connection.
    let cleartext = !required.tls_tcp && !required.tls_quic;
    (!cleartext
        || !(contains(analysis.components.tls_tcp.as_deref(), index)
            || contains(analysis.components.tls_quic.as_deref(), index)))
        && (!required.h2 || contains(analysis.components.h2.as_deref(), index))
        && (!required.tls_tcp || contains(analysis.components.tls_tcp.as_deref(), index))
        && (!required.tls_quic || contains(analysis.components.tls_quic.as_deref(), index))
        && (!required.quic || contains(analysis.components.quic.as_deref(), index))
        && (!required.h3 || contains(analysis.components.h3.as_deref(), index))
}

fn scope_serves_request_pin(
    analysis: &AnalyzedProfile,
    connection: &AnalyzedProfileScope,
    flow: &FlowKey,
    pin: ValueId,
    required: CapabilitySet,
) -> bool {
    let Ok(protocol) = flow_protocol(flow) else {
        return false;
    };
    let Ok(canonical) = flow.canonical(MAXIMUM_IDENTITY_BYTES) else {
        return false;
    };
    eligible_request_scopes(
        analysis,
        &connection.context.connection,
        flow,
        canonical.id,
        protocol,
        required,
    )
    .any(|(_index, scope, _distance)| {
        scope
            .observations
            .variants
            .iter()
            .any(|variant| variant.value.id() == pin)
    })
}

/// Request scopes a request draw on a connection captured in `connection` may use.
fn eligible_request_scopes<'a>(
    analysis: &'a AnalyzedProfile,
    connection: &'a ConnectionContext,
    flow: &'a FlowKey,
    canonical: ValueId,
    protocol: Version,
    required: CapabilitySet,
) -> impl Iterator<Item = (usize, &'a AnalyzedProfileScope, FlowDistance)> {
    let candidates = move || {
        protocol_scopes(analysis, protocol)
            .iter()
            .filter_map(move |&index| analysis.scopes.get(index).map(|scope| (index, scope)))
            .filter(move |(_index, scope)| {
                scope.observations.domain == CanonicalDomain::Joint
                    && connection_context_matches(&scope.context.connection, connection)
            })
            .filter_map(move |(index, scope)| {
                scope_flow_distance(scope, flow, canonical).map(|distance| (index, scope, distance))
            })
    };
    // Browsers send fetch metadata only in secure contexts. Over TLS, a request shape
    // captured without it (a plaintext page) is not one this browser would send there.
    let metadata_only = (required.tls_tcp || required.tls_quic)
        && candidates().any(|(_index, scope, _distance)| has_fetch_metadata(scope));
    candidates()
        .filter(move |(_index, scope, _distance)| !metadata_only || has_fetch_metadata(scope))
}

fn connection_context_matches(left: &ConnectionContext, right: &ConnectionContext) -> bool {
    let resumption = match right.resumption {
        ResumptionContext::Unknown | ResumptionContext::Fresh => {
            !matches!(left.resumption, ResumptionContext::Resumed)
        }
        ResumptionContext::Resumed => left.resumption == ResumptionContext::Resumed,
    };
    let early_data = match right.early_data {
        None => left.early_data != Some(true),
        requested => left.early_data == requested,
    };
    let token = right
        .token_present
        .is_none_or(|requested| left.token_present == Some(requested));

    resumption && early_data && token
}

/// How far a captured flow is from the requested one. Fields compare in the order
/// documented on `ProfileEmulateLayer`, so the derived order ranks candidates;
/// the default, nothing different, is an exact match.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
struct FlowDistance {
    mode: bool,
    destination: bool,
    method: bool,
    user_activation: bool,
    site: bool,
    initiator: bool,
}

impl FlowDistance {
    fn flow_match(self) -> FlowMatch {
        if self == Self::default() {
            FlowMatch::Exact
        } else {
            FlowMatch::Nearest {
                other_destination: self.mode || self.destination,
                other_method: self.method,
            }
        }
    }
}

/// `None` when the scope cannot replay the requested flow at all.
fn scope_flow_distance(
    scope: &AnalyzedProfileScope,
    requested: &FlowKey,
    canonical: ValueId,
) -> Option<FlowDistance> {
    match &scope.flow {
        Some(observed) => flow_distance(observed, requested),
        None => (scope.context.flow == Some(canonical)).then(FlowDistance::default),
    }
}

fn flow_distance(observed: &FlowKey, requested: &FlowKey) -> Option<FlowDistance> {
    match (observed, requested) {
        (
            FlowKey::Http {
                version: observed_version,
                method: observed_method,
                initiator: observed_initiator,
                fetch: observed_fetch,
                connection: observed_connection,
            },
            FlowKey::Http {
                version: requested_version,
                method: requested_method,
                initiator: requested_initiator,
                fetch: requested_fetch,
                connection: requested_connection,
            },
        ) => {
            let websocket = is_websocket(*observed_initiator, observed_fetch.as_ref());
            if observed_version != requested_version
                || !connection_context_matches(observed_connection, requested_connection)
                // A tunnel or WebSocket handshake never replays as an ordinary request.
                || websocket != is_websocket(*requested_initiator, requested_fetch.as_ref())
                // A WebSocket handshake is a GET over HTTP/1.1 and a CONNECT over HTTP/2 or 3.
                || (!websocket
                    && (*observed_method == Method::CONNECT)
                        != (*requested_method == Method::CONNECT))
            {
                return None;
            }
            // Without Fetch metadata the caller leaves the request context to the capture.
            let differs = |field: fn(&FetchContext) -> Option<&str>| {
                requested_fetch.as_ref().is_some_and(|requested| {
                    observed_fetch.as_ref().and_then(field) != field(requested)
                })
            };
            Some(FlowDistance {
                mode: differs(|fetch| fetch.mode.as_deref()),
                destination: differs(|fetch| fetch.destination.as_deref()),
                method: !websocket && observed_method != requested_method,
                user_activation: differs(|fetch| fetch.user_activation.as_deref()),
                site: differs(|fetch| fetch.site.as_deref()),
                initiator: !initiator_matches(
                    *observed_initiator,
                    observed_fetch.as_ref(),
                    *requested_initiator,
                    requested_fetch.is_some(),
                ),
            })
        }
        (
            FlowKey::Other {
                protocol: observed_protocol,
                operation: observed_operation,
            },
            FlowKey::Other {
                protocol: requested_protocol,
                operation: requested_operation,
            },
        ) => (observed_protocol == requested_protocol && observed_operation == requested_operation)
            .then(FlowDistance::default),
        _ => None,
    }
}

fn is_websocket(initiator: Option<RequestInitiator>, fetch: Option<&FetchContext>) -> bool {
    initiator == Some(RequestInitiator::Ws)
        || fetch.is_some_and(|fetch| fetch.mode.as_deref() == Some("websocket"))
}

/// What a request flow is for, as [`flow_distance`] tells them apart. A WebSocket
/// handshake changes form, not kind, with its HTTP version.
#[derive(Debug, Clone, Copy)]
enum FlowKind {
    Ordinary,
    Tunnel,
    WebSocket,
}

impl FlowKind {
    const ALL: [Self; 3] = [Self::Ordinary, Self::Tunnel, Self::WebSocket];

    fn of(
        method: &Method,
        initiator: Option<RequestInitiator>,
        fetch: Option<&FetchContext>,
    ) -> Self {
        if is_websocket(initiator, fetch) {
            Self::WebSocket
        } else if *method == Method::CONNECT {
            Self::Tunnel
        } else {
            Self::Ordinary
        }
    }
}

/// Per [`FlowKind`], the HTTP versions under which a profile holds a flow that a request
/// on a fresh connection can replay.
#[derive(Debug, Default)]
pub(super) struct FlowVersions([CapabilitySet; 3]);

impl FlowVersions {
    pub(super) fn of(analysis: &AnalyzedProfile) -> Self {
        let mut versions = Self::default();
        let fresh = ConnectionContext::default();
        for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            let mut mark = |kind: FlowKind| {
                let set = &mut versions.0[kind as usize];
                match version {
                    Version::HTTP_11 => set.h1 = true,
                    Version::HTTP_2 => set.h2 = true,
                    _ => set.h3 = true,
                }
            };
            for scope in protocol_scopes(analysis, version)
                .iter()
                .filter_map(|&index| analysis.scopes.get(index))
                .filter(|scope| scope.observations.domain == CanonicalDomain::Joint)
            {
                match &scope.flow {
                    Some(FlowKey::Http {
                        method,
                        initiator,
                        fetch,
                        connection,
                        ..
                    }) if connection_context_matches(connection, &fresh) => {
                        mark(FlowKind::of(method, *initiator, fetch.as_ref()));
                    }
                    // Matched by its exact flow identity alone, it may serve any kind.
                    None if scope.context.flow.is_some() => {
                        FlowKind::ALL.into_iter().for_each(&mut mark);
                    }
                    _ => {}
                }
            }
        }
        versions
    }

    /// The versions holding a flow that `flow` can replay; `None` for a flow that is not on
    /// a fresh connection, which these versions do not describe.
    fn of_flow(&self, flow: &FlowKey) -> Option<CapabilitySet> {
        let FlowKey::Http {
            method,
            initiator,
            fetch,
            connection,
            ..
        } = flow
        else {
            return None;
        };
        let fresh = connection.resumption != ResumptionContext::Resumed
            && connection.early_data.is_none()
            && connection.token_present.is_none();
        fresh.then(|| self.0[FlowKind::of(method, *initiator, fetch.as_ref()) as usize])
    }
}

/// A request without an initiator is described by its Fetch metadata, or else
/// assumed to be a top-level navigation.
fn initiator_matches(
    observed: Option<RequestInitiator>,
    observed_fetch: Option<&FetchContext>,
    requested: Option<RequestInitiator>,
    requested_fetch: bool,
) -> bool {
    match (requested, observed) {
        (Some(requested), observed) => observed == Some(requested),
        // Fetch metadata cannot tell a link from a GET form, nor fetch from XHR.
        (None, _) if requested_fetch => true,
        (None, observed) => {
            observed.is_none_or(|observed| observed == RequestInitiator::Navigate)
                && observed_fetch.is_none_or(|fetch| {
                    fetch.mode.as_deref() == Some("navigate")
                        && fetch.destination.as_deref() == Some("document")
                })
        }
    }
}

fn has_fetch_metadata(scope: &AnalyzedProfileScope) -> bool {
    matches!(scope.flow, Some(FlowKey::Http { fetch: Some(_), .. }))
}

fn selection_flow(flow: &FlowKey) -> Result<CanonicalValue, ProfileDataError> {
    let mut flow = flow.clone();
    if let FlowKey::Http { connection, .. } = &mut flow {
        connection.ip_family = None;
    }
    flow.canonical(MAXIMUM_IDENTITY_BYTES)
}

fn request_scope_supports(analysis: &AnalyzedProfile, index: usize, version: Version) -> bool {
    if matches!(
        version,
        Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11
    ) {
        contains(analysis.components.h1.as_deref(), index)
    } else if version == Version::HTTP_2 {
        contains(analysis.components.h2.as_deref(), index)
    } else if version == Version::HTTP_3 {
        contains(analysis.components.h3.as_deref(), index)
    } else {
        false
    }
}

fn flow_protocol(flow: &FlowKey) -> Result<Version, SelectionError> {
    match flow {
        FlowKey::Http { version, .. } => Ok(*version),
        FlowKey::Other { .. } => Err(SelectionError::MissingFlow),
    }
}

fn protocol_supported(required: CapabilitySet, version: Version) -> bool {
    if matches!(
        version,
        Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11
    ) {
        required.h1
    } else if version == Version::HTTP_2 {
        required.h2
    } else {
        version == Version::HTTP_3 && required.h3
    }
}

fn contains(scopes: Option<&[usize]>, index: usize) -> bool {
    scopes.is_some_and(|scopes| scopes.binary_search(&index).is_ok())
}

fn selection_scope(
    candidates: impl Iterator<Item = ValueId>,
    flow: ValueId,
    required: CapabilitySet,
) -> ValueId {
    let mut digest = Sha256::new();
    digest.update(SELECTION_PREFIX);
    digest.update(flow.0);
    digest.update(required.bytes());
    for candidate in candidates {
        digest.update(candidate.0);
    }
    ValueId(digest.finalize().into())
}

fn prefer_exact_weights(weights: &mut [u64], exact: &[bool]) {
    let total: u128 = weights
        .iter()
        .zip(exact)
        .map(|(weight, exact)| u128::from(*weight) * if *exact { 2 } else { 1 })
        .sum();
    let positive = weights.iter().filter(|weight| **weight != 0).count() as u128;
    let capacity = (u128::from(u64::MAX) - positive).max(1);
    let divisor = total.div_ceil(capacity).max(1);
    for (weight, exact) in weights.iter_mut().zip(exact) {
        if *weight != 0 {
            let preferred = u128::from(*weight) * if *exact { 2 } else { 1 };
            *weight = (preferred / divisor).max(1) as u64;
        }
    }
}

fn analyzed_weight(weight: &AnalyzedOrderWeight) -> Result<u64, SelectionError> {
    Ok(match weight {
        AnalyzedOrderWeight::Counted(weight) => analyzed_observation_weight(*weight),
        AnalyzedOrderWeight::Sample { observed, .. } => *observed as u64,
    })
}

fn analyzed_observation_weight(weight: ObservationWeight) -> u64 {
    match weight {
        ObservationWeight::Exact(observed)
        | ObservationWeight::UnknownHistory { observed, .. }
        | ObservationWeight::LowerBound { observed, .. } => observed,
    }
}

#[cfg(test)]
mod tests;
