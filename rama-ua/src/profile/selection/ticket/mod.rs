use std::{error::Error, fmt, sync::Arc};

use rama_core::extensions::{Extension, Extensions};
use rama_http::Version;
use rama_net::{
    client::pool::{ConnectionReuse, ConnectionReusePolicy},
    tls::{ApplicationProtocol, TlsAlpn},
};
use rama_utils::octets::kib;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{DrawDomain, DrawKey, ProfileDraw, ProfileDrawContext, ProfileDrawError, ProfileSeed};
use crate::profile::{
    AnalyzedOrderWeight, CanonicalDomain, CanonicalValue, ConnectionContext, FlowKey,
    ObservationWeight, ProfileCandidateFilter, ProfileCapabilities, ProfileDataError,
    ProfileObservationScope, UserAgentDatabase, UserAgentProfile, ValueId,
};
use crate::{DeviceKind, PlatformKind};

const SELECTION_PREFIX: &[u8] = b"rama-profile-selection\0";
const MAXIMUM_IDENTITY_BYTES: usize = kib(16);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelectionTransport {
    TcpPlain,
    TcpTls,
    Quic,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySet {
    pub h1: bool,
    pub h2: bool,
    pub h3: bool,
    pub tls_tcp: bool,
    pub tls_quic: bool,
    pub quic: bool,
}

impl CapabilitySet {
    pub fn for_alpn(alpn: &TlsAlpn, transport: SelectionTransport) -> Result<Self, SelectionError> {
        let mut required = Self::default();
        for protocol in &alpn.0 {
            match protocol {
                ApplicationProtocol::HTTP_09
                | ApplicationProtocol::HTTP_10
                | ApplicationProtocol::HTTP_11 => required.h1 = true,
                ApplicationProtocol::HTTP_2 | ApplicationProtocol::HTTP_2_TCP => {
                    required.h2 = true;
                }
                ApplicationProtocol::HTTP_3 => required.h3 = true,
                other => {
                    return Err(SelectionError::UnsupportedAlpn(
                        other.as_bytes().to_vec().into(),
                    ));
                }
            }
        }
        if !required.h1 && !required.h2 && !required.h3 {
            return Err(SelectionError::MissingHttpAlpn);
        }
        match transport {
            SelectionTransport::TcpPlain => {
                if required.h3 {
                    return Err(SelectionError::IncompatibleTransport);
                }
            }
            SelectionTransport::TcpTls => {
                if required.h3 {
                    return Err(SelectionError::IncompatibleTransport);
                }
                required.tls_tcp = true;
            }
            SelectionTransport::Quic => {
                if required.h1 || required.h2 || !required.h3 {
                    return Err(SelectionError::IncompatibleTransport);
                }
                required.tls_quic = true;
                required.quic = true;
            }
        }
        Ok(required)
    }

    fn supports(self, required: Self) -> bool {
        (!required.h1 || self.h1)
            && (!required.h2 || self.h2)
            && (!required.h3 || self.h3)
            && (!required.tls_tcp || self.tls_tcp)
            && (!required.tls_quic || self.tls_quic)
            && (!required.quic || self.quic)
    }

    fn bytes(self) -> [u8; 6] {
        [
            self.h1 as u8,
            self.h2 as u8,
            self.h3 as u8,
            self.tls_tcp as u8,
            self.tls_quic as u8,
            self.quic as u8,
        ]
    }
}

impl From<crate::profile::ProfileCapabilities> for CapabilitySet {
    fn from(value: crate::profile::ProfileCapabilities) -> Self {
        Self {
            h1: value.h1,
            h2: value.h2,
            h3: value.h3,
            tls_tcp: value.tls_tcp,
            tls_quic: value.tls_quic,
            quic: value.quic,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileSelector {
    pub client: Option<Box<str>>,
    pub platform: Option<PlatformKind>,
    pub device: Option<DeviceKind>,
    pub latest_versions: Option<usize>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariantPins {
    pub connection: Option<ValueId>,
    pub request: Option<ValueId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionRequest {
    pub client: ProfileSelector,
    pub required: CapabilitySet,
    pub flow: FlowKey,
    pub pins: VariantPins,
}

#[derive(Debug, Clone)]
pub struct SelectedProfile {
    id: ValueId,
    profile: Arc<UserAgentProfile>,
    required: CapabilitySet,
    flow: FlowKey,
    pins: VariantPins,
}

#[derive(Debug, Clone, Extension)]
#[extension(tags(ua))]
pub struct EmulationContext {
    pub selected: Arc<SelectedProfile>,
    pub seed: ProfileSeed,
    pub connection_key: DrawKey,
    pub request_key: DrawKey,
    pub pins: VariantPins,
}

#[derive(Debug, Clone, Serialize, Extension)]
#[extension(tags(ua))]
pub struct PreparedConnectionProfile {
    pub scope: ValueId,
    pub capture: CanonicalValue,
    pub context: ProfileObservationScope,
}

#[derive(Debug, Clone, Serialize, Extension)]
#[extension(tags(ua))]
pub struct ConnectionSelection {
    pub profile: ValueId,
    pub variant: ValueId,
    pub draw: DrawKey,
    pub analysis_revision: u16,
    pub effective: PreparedConnectionProfile,
}

#[derive(Debug, Clone, Serialize, Extension)]
#[extension(tags(ua))]
pub struct PreparedRequestProfile {
    pub scope: ValueId,
    pub capture: CanonicalValue,
    pub flow: FlowKey,
}

#[derive(Debug, Clone, Serialize, Extension)]
#[extension(tags(ua))]
pub struct RequestSelection {
    pub profile: ValueId,
    pub connection_variant: ValueId,
    pub variant: ValueId,
    pub draw: DrawKey,
    pub analysis_revision: u16,
    pub effective: PreparedRequestProfile,
}

#[derive(Debug, Clone)]
pub struct ProfileConnectionReuse {
    profile: ValueId,
    variant: ValueId,
    negotiated: Version,
}

#[derive(Debug, Clone)]
pub enum SelectionError {
    Data(ProfileDataError),
    Draw(ProfileDrawError),
    MissingProfile,
    MissingFlow,
    MissingCapabilities(CapabilitySet),
    IncompatibleConnectionContext,
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
        let mut scopes = analysis
            .scopes
            .iter()
            .enumerate()
            .filter(|(index, scope)| {
                scope.context.flow.is_none()
                    && connection_context_matches(&scope.context.connection, context)
                    && scope.observations.domain == CanonicalDomain::Joint
                    && connection_scope_supports(analysis, *index, self.required)
            })
            .collect::<Vec<_>>();
        if let Some(pin) = self.pins.connection {
            scopes.retain(|(_index, scope)| {
                scope
                    .observations
                    .variants
                    .iter()
                    .any(|variant| variant.value.id == pin)
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
                .find(|variant| variant.value.id == pin)
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
        Ok(ConnectionSelection {
            profile: analysis.id,
            variant: variant.value.id,
            draw: key,
            analysis_revision: analysis.classifier_revision,
            effective: PreparedConnectionProfile {
                scope: scope.id,
                capture: variant.value.clone(),
                context: scope.context.clone(),
            },
        })
    }

    pub fn request(
        &self,
        connection: &ConnectionSelection,
        flow: &FlowKey,
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
        if let Some(pin) = self.pins.request {
            scopes.retain(|(_index, scope)| {
                scope
                    .observations
                    .variants
                    .iter()
                    .any(|variant| variant.value.id == pin)
            });
            if scopes.is_empty() {
                return Err(SelectionError::IncompatiblePin(pin));
            }
        } else if scopes.is_empty() {
            return Err(SelectionError::MissingFlow);
        }
        scopes.sort_unstable_by_key(|(_index, scope)| scope.id);
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
        let weights = scopes
            .iter()
            .map(|(_index, scope)| scope.observations.counts.total)
            .collect::<Vec<_>>();
        let scope = scopes
            .get(scope_draw.weighted_index(&weights)?)
            .map(|(_index, scope)| *scope)
            .ok_or(SelectionError::MissingFlow)?;
        let variant = if let Some(pin) = self.pins.request {
            scope
                .observations
                .variants
                .iter()
                .find(|variant| variant.value.id == pin)
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
            self.pins
                .request
                .map_or(SelectionError::MissingFlow, SelectionError::IncompatiblePin)
        })?;
        Ok(RequestSelection {
            profile: analysis.id,
            connection_variant: connection.variant,
            variant: variant.value.id,
            draw: key,
            analysis_revision: analysis.classifier_revision,
            effective: PreparedRequestProfile {
                scope: scope.id,
                capture: variant.value.clone(),
                flow: flow.clone(),
            },
        })
    }
}

impl ProfileConnectionReuse {
    #[must_use]
    pub fn new(ticket: &ConnectionSelection, negotiated: Version) -> Self {
        Self {
            profile: ticket.profile,
            variant: ticket.variant,
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
    fn matches(&self, input: &Extensions) -> bool {
        input.get_ref::<EmulationContext>().is_some_and(|context| {
            context.selected.profile_id() == self.profile
                && protocol_supported(context.selected.required, self.negotiated)
                && context
                    .pins
                    .connection
                    .is_none_or(|pin| pin == self.variant)
        })
    }
}

fn has_flow(
    analysis: &crate::profile::AnalyzedProfile,
    flow: &FlowKey,
    canonical: ValueId,
) -> bool {
    analysis
        .scopes
        .iter()
        .any(|scope| scope_flow_matches(scope, flow, canonical))
}

fn connection_scope_supports(
    analysis: &crate::profile::AnalyzedProfile,
    index: usize,
    required: CapabilitySet,
) -> bool {
    (!required.h2 || contains(analysis.components.h2.as_deref(), index))
        && (!required.tls_tcp || contains(analysis.components.tls_tcp.as_deref(), index))
        && (!required.tls_quic || contains(analysis.components.tls_quic.as_deref(), index))
        && (!required.quic || contains(analysis.components.quic.as_deref(), index))
        && (!required.h3 || contains(analysis.components.h3.as_deref(), index))
}

fn connection_context_matches(left: &ConnectionContext, right: &ConnectionContext) -> bool {
    left.resumption == right.resumption
        && left.early_data == right.early_data
        && left.token_present == right.token_present
}

fn scope_flow_matches(
    scope: &crate::profile::AnalyzedProfileScope,
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
                && observed_initiator == requested_initiator
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

fn fetch_context_matches(
    observed: Option<&crate::profile::FetchContext>,
    requested: Option<&crate::profile::FetchContext>,
) -> bool {
    match (observed, requested) {
        (Some(observed), Some(requested)) => {
            observed.mode == requested.mode
                && observed.site == requested.site
                && observed.destination == requested.destination
                && observed.user_activation == requested.user_activation
        }
        (None, None) => true,
        _ => false,
    }
}

fn selection_flow(flow: &FlowKey) -> Result<CanonicalValue, ProfileDataError> {
    let mut flow = flow.clone();
    if let FlowKey::Http { connection, .. } = &mut flow {
        connection.ip_family = None;
    }
    flow.canonical(MAXIMUM_IDENTITY_BYTES)
}

fn request_scope_supports(
    analysis: &crate::profile::AnalyzedProfile,
    index: usize,
    version: Version,
) -> bool {
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
    candidates: &[(&UserAgentProfile, &Arc<crate::profile::AnalyzedProfile>)],
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
