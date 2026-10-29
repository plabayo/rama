//! Select correlated connection and request variants within a profile.

pub mod bootstrap;
pub(crate) mod shapes;

use std::{error::Error, fmt, ptr, sync::Arc};

use rama_core::{
    extensions::{Extension, Extensions},
    telemetry::tracing,
};
use rama_http::{HeaderMap, Version};
use rama_net::client::pool::{ConnectionReuse, ConnectionReusePolicy, PoolPartition, ReuseKey};
use rama_utils::octets::kib;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub(crate) use self::shapes::RequestPlanRef;
use self::shapes::{RequestShapeCache, request_variants_for_headers};
use crate::{
    DeviceKind, HttpAgent, PlatformKind, TlsAgent, UserAgent,
    profile::{
        analysis::{
            capture::{AnalyzedCaptureVariant, VariantValue},
            order::AnalyzedOrderWeight,
            profile::{AnalyzedProfile, AnalyzedProfileScope},
        },
        capture::{completeness::ProfileCaptureCompleteness, headers::HeaderCapturePolicy},
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

const SELECTION_PREFIX: &[u8] = b"rama-profile-selection\0";
const MAXIMUM_IDENTITY_BYTES: usize = kib(16);

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
/// Identity filters applied before a captured profile is drawn.
pub struct ProfileSelector {
    /// Exact User-Agent of the profiles to draw from, such as one auto-detected
    /// from the request. Emulation relaxes it to the browser family when no
    /// profile has this exact User-Agent.
    #[serde(default)]
    pub user_agent: Option<Box<str>>,
    pub client: Option<Box<str>>,
    pub platform: Option<PlatformKind>,
    pub device: Option<DeviceKind>,
    pub latest_versions: Option<usize>,
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

#[derive(Debug, Clone, Serialize, Extension)]
#[extension(tags(ua))]
/// Deterministic connection draw consumed by protocol connectors.
pub struct ConnectionSelection {
    pub profile: ValueId,
    pub variant: ValueId,
    pub draw: DrawKey,
    pub analysis_revision: u16,
    pub effective: PreparedConnectionProfile,
}

#[derive(Debug, Clone, Serialize, Extension)]
#[extension(tags(ua))]
/// Canonical request variant and the flow it must replay.
pub struct PreparedRequestProfile {
    pub scope: ValueId,
    /// Replaced only through [`Self::set_capture`], so a cached plan never outlives it.
    pub(crate) capture: VariantValue,
    pub flow: FlowKey,
    /// Cookie layout evidence from this profile for the negotiated HTTP version.
    pub cookie_layout: CookieLayoutEvidence,
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
        let mut matching = candidates
            .iter()
            .map(|candidate| candidate.profile)
            .filter_map(|profile| {
                profile
                    .captured
                    .as_ref()
                    .map(|analysis| (profile, analysis))
            })
            .collect::<Vec<_>>();
        if matching.is_empty() {
            return Err(SelectionError::MissingProfile);
        }
        matching.retain(|(_profile, analysis)| has_flow(analysis, &request.flow, flow.id));
        if matching.is_empty() {
            return Err(SelectionError::MissingFlow);
        }
        matching.retain(|(profile, _analysis)| {
            CapabilitySet::from(profile.capabilities()).supports(request.required)
        });
        if matching.is_empty() {
            return Err(SelectionError::MissingCapabilities(request.required));
        }
        // Profile capabilities can come from request scopes alone; the connection step
        // needs a captured connection for this transport and context.
        if request.pins.connection.is_none() {
            let context = flow_connection_context(&request.flow);
            matching.retain(|(_profile, analysis)| {
                !connection_candidates(analysis, &context, request.required, true).is_empty()
            });
            if matching.is_empty() {
                return Err(SelectionError::IncompatibleConnectionContext);
            }
        }
        matching.sort_unstable_by_key(|(_profile, analysis)| analysis.id);
        let scope = selection_scope(&matching, selection_flow.id, request.required);
        let mut draw = ProfileDraw::new(
            seed,
            ProfileDrawContext {
                profile: scope,
                analysis_revision: matching
                    .iter()
                    .map(|(_profile, analysis)| analysis.classifier_revision)
                    .max()
                    .unwrap_or_default(),
                scope,
                key,
                domain: DrawDomain::Connection,
                slot: 0,
            },
        );
        let weights = matching
            .iter()
            .map(|(profile, _analysis)| observation_weight(profile.observation_weight()))
            .collect::<Result<Vec<_>, _>>()?;
        let selected = draw.weighted_index(&weights)?;
        let (profile, analysis) = matching
            .get(selected)
            .copied()
            .ok_or(SelectionError::MissingProfile)?;
        Ok(SelectedProfile {
            id: analysis.id,
            profile: Arc::new(profile.clone()),
            request_shapes: self
                .request_shape_cache(profile)
                .ok_or(SelectionError::MissingProfile)?,
            required: request.required,
            flow: request.flow.clone(),
            pins: request.pins,
        })
    }
}

impl SelectedProfile {
    #[must_use]
    pub fn profile(&self) -> &UserAgentProfile {
        &self.profile
    }

    #[must_use]
    pub fn profile_id(&self) -> ValueId {
        self.id
    }

    /// Capabilities the selected connection must provide.
    #[must_use]
    pub fn required(&self) -> CapabilitySet {
        self.required
    }

    #[must_use]
    pub fn pins(&self) -> VariantPins {
        self.pins
    }

    #[must_use]
    pub fn flow(&self) -> &FlowKey {
        &self.flow
    }

    pub fn validate_negotiated_protocol(&self, version: Version) -> Result<(), SelectionError> {
        if protocol_supported(self.required, version) {
            Ok(())
        } else {
            Err(SelectionError::IncompatibleNegotiatedProtocol(version))
        }
    }

    #[must_use]
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

    pub fn connection(
        &self,
        context: &ConnectionContext,
        seed: ProfileSeed,
        key: DrawKey,
    ) -> Result<ConnectionSelection, SelectionError> {
        let analysis = self
            .profile
            .captured
            .as_ref()
            .ok_or(SelectionError::MissingProfile)?;
        let mut scopes = connection_candidates(
            analysis,
            context,
            self.required,
            self.pins.connection.is_none(),
        );
        if let Some(pin) = self.pins.connection {
            scopes.retain(|(_index, scope)| {
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
            return Err(SelectionError::IncompatibleConnectionContext);
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
        let scope = scopes
            .get(scope_draw.weighted_index(&weights)?)
            .map(|(_index, scope)| *scope)
            .ok_or(SelectionError::IncompatibleConnectionContext)?;
        let variant = if let Some(pin) = self.pins.connection {
            scope
                .observations
                .variants
                .iter()
                .find(|variant| variant.value.id() == pin)
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
                .map(|variant| analyzed_weight(&variant.weight))
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
        Ok(ConnectionSelection {
            profile: analysis.id,
            variant: capture.id,
            draw: key,
            analysis_revision: analysis.classifier_revision,
            effective: PreparedConnectionProfile {
                scope: scope.id,
                capture: capture.clone(),
                context: scope.context.clone(),
                h3_settings_evidence: H3SettingsReplayEvidence::for_profile(
                    analysis, scope, &capture,
                )?,
            },
        })
    }

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
        let mut scopes = analysis
            .scopes
            .iter()
            .enumerate()
            .filter(|(index, scope)| {
                scope_flow_matches(scope, flow, canonical.id)
                    && connection_context_matches(
                        &scope.context.connection,
                        &connection.effective.context.connection,
                    )
                    && scope.observations.domain == CanonicalDomain::Joint
                    && request_scope_supports(analysis, *index, protocol)
            })
            .collect::<Vec<_>>();
        // Browsers send fetch metadata only in secure contexts. Over TLS, a request shape
        // captured without it (a plaintext page) is not one this browser would send there.
        if (self.required.tls_tcp || self.required.tls_quic)
            && scopes
                .iter()
                .any(|(_index, scope)| has_fetch_metadata(scope))
        {
            scopes.retain(|(_index, scope)| has_fetch_metadata(scope));
        }
        if let Some(pin) = self.pins.request {
            scopes.retain(|(_index, scope)| {
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

        // Capture request-owned fields once; every candidate compares against
        // the same validated caller input.
        let requested = HeaderCapturePolicy::default().capture(
            ProfileCaptureCompleteness::Complete,
            protocol,
            headers,
            None,
        )?;
        let mut candidates = Vec::new();
        for (index, scope) in scopes {
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
            let (compatible, covered) = request_variants_for_headers(
                &available,
                protocol,
                &requested,
                analysis,
                index,
                &self.request_shapes,
            )?;
            let fits = !compatible.is_empty();
            let variants = if fits {
                compatible
            } else {
                available.into_iter().map(|(_, variant)| variant).collect()
            };
            if !variants.is_empty() {
                candidates.push((index, scope, variants, fits.then_some(covered)));
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
                "no captured request variant matches the caller headers; drawing from all"
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
                cookie_layout: self.request_shapes.cookie_layout(analysis, protocol),
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
        let policy = ConnectionReuse::new(self);
        let policy = match connection.get_ref::<ConnectionReuse>() {
            Some(inner) => inner.clone().and(policy),
            None => policy,
        };
        connection.insert(policy);
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

fn has_flow(analysis: &AnalyzedProfile, flow: &FlowKey, canonical: ValueId) -> bool {
    analysis
        .scopes
        .iter()
        .any(|scope| scope_flow_matches(scope, flow, canonical))
}

/// Connection scopes of `analysis` that can open a connection for `required` in `context`.
fn connection_candidates<'a>(
    analysis: &'a AnalyzedProfile,
    context: &ConnectionContext,
    required: CapabilitySet,
    lower_h2: bool,
) -> Vec<(usize, &'a AnalyzedProfileScope)> {
    let candidates = |required| {
        analysis
            .scopes
            .iter()
            .enumerate()
            .filter(|(index, scope)| {
                scope.context.flow.is_none()
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

fn connection_context_matches(left: &ConnectionContext, right: &ConnectionContext) -> bool {
    let resumption = match right.resumption {
        ResumptionContext::Unknown => !matches!(left.resumption, ResumptionContext::Resumed),
        requested => left.resumption == requested,
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

fn scope_flow_matches(
    scope: &AnalyzedProfileScope,
    requested: &FlowKey,
    canonical: ValueId,
) -> bool {
    scope.flow.as_ref().map_or_else(
        || scope.context.flow == Some(canonical),
        |observed| flow_matches(observed, requested),
    )
}

fn flow_matches(observed: &FlowKey, requested: &FlowKey) -> bool {
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
            observed_version == requested_version
                && observed_method == requested_method
                && initiator_matches(*observed_initiator, *requested_initiator)
                && fetch_context_matches(observed_fetch.as_ref(), requested_fetch.as_ref())
                && connection_context_matches(observed_connection, requested_connection)
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
        ) => observed_protocol == requested_protocol && observed_operation == requested_operation,
        _ => false,
    }
}

fn initiator_matches(
    observed: Option<RequestInitiator>,
    requested: Option<RequestInitiator>,
) -> bool {
    match requested {
        Some(requested) => observed == Some(requested),
        None => observed.is_none_or(|observed| observed == RequestInitiator::Navigate),
    }
}

fn has_fetch_metadata(scope: &AnalyzedProfileScope) -> bool {
    matches!(scope.flow, Some(FlowKey::Http { fetch: Some(_), .. }))
}

fn fetch_context_matches(
    observed: Option<&FetchContext>,
    requested: Option<&FetchContext>,
) -> bool {
    match (observed, requested) {
        (Some(observed), Some(requested)) => {
            observed.mode == requested.mode
                && observed.site == requested.site
                && observed.destination == requested.destination
                && observed.user_activation == requested.user_activation
        }
        (_, None) => true,
        (None, Some(_)) => false,
    }
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
    candidates: &[(&UserAgentProfile, &Arc<AnalyzedProfile>)],
    flow: ValueId,
    required: CapabilitySet,
) -> ValueId {
    let mut digest = Sha256::new();
    digest.update(SELECTION_PREFIX);
    digest.update(flow.0);
    digest.update(required.bytes());
    for (_profile, analysis) in candidates {
        digest.update(analysis.id.0);
    }
    ValueId(digest.finalize().into())
}

fn observation_weight(
    weight: Result<ObservationWeight, ProfileDataError>,
) -> Result<u64, SelectionError> {
    weight.map(analyzed_observation_weight).map_err(Into::into)
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
