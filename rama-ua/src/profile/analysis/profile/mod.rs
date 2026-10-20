//! Reanalysis from retained counts, without new traffic or mandatory components.

mod normalize;

use std::collections::BTreeSet;

pub use normalize::{NormalizedProfileEvidence, normalize_profile_evidence, normalized_scope_id};

use crate::profile::capture::joint::normalize_stored_structure;

use rama_http::Version;
use rama_utils::octets::{kib, mib};
use serde::Serialize;

use crate::profile::analysis::{
    capture::{CountedCaptureAnalysis, analyze_capture_bucket},
    order::OrderAnalysisConfig,
};
#[cfg(feature = "tls")]
use crate::profile::capture::tls::{TlsCapture, TlsCaptureLimits, TlsCaptureTransport};
use crate::profile::{
    capture::{
        completeness::ProfileCaptureCompleteness,
        joint::{CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits},
        observation::ProfileCapture,
        order::{OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture},
    },
    evidence::{
        ProfileEvidence,
        window::{ProfileWindowLimits, RetainedBucketWindow},
    },
    format::{
        canonical::{CanonicalDomain, CanonicalValue, ProfileDataError, ValueId},
        legacy::{LegacyField, LegacyFieldCapture, LegacyHttpProtocol},
    },
    model::{
        identity::{FlowKey, ProfileKey},
        scope::ProfileObservationScope,
    },
};

#[derive(Debug, Clone, Copy)]
pub struct ProfileAnalysisLimits {
    /// Scopes after normalization; stored scopes that normalize alike count once.
    pub scopes: usize,
    /// Stored scopes read for one profile before normalization.
    pub stored_scopes: usize,
    pub bytes: usize,
    pub metadata_bytes: usize,
    /// Retained evidence bytes plus normalized order-element visits.
    pub maximum_work: usize,
    pub window: ProfileWindowLimits,
    /// Per-day literal capacity; selection scales it by the requested horizon.
    pub order: OrderAnalysisConfig,
}

impl Default for ProfileAnalysisLimits {
    fn default() -> Self {
        Self {
            scopes: 256,
            stored_scopes: 8192,
            bytes: mib(64),
            metadata_bytes: kib(16),
            maximum_work: mib(128),
            window: ProfileWindowLimits::default(),
            order: OrderAnalysisConfig::default(),
        }
    }
}

/// Each optional component references scopes in the enclosing profile. Presence
/// describes retained observations; provider-specific replay validation is separate.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AnalyzedProfileComponents {
    pub h1: Option<Box<[usize]>>,
    pub h2: Option<Box<[usize]>>,
    pub h3: Option<Box<[usize]>>,
    pub tls_tcp: Option<Box<[usize]>>,
    pub tls_quic: Option<Box<[usize]>>,
    pub quic: Option<Box<[usize]>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalyzedProfileScope {
    pub id: ValueId,
    pub context: ProfileObservationScope,
    pub flow: Option<FlowKey>,
    pub structure: CanonicalValue,
    pub observations: CountedCaptureAnalysis,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalyzedProfile {
    pub work_units: usize,
    pub format_version: u16,
    pub classifier_revision: u16,
    pub id: ValueId,
    pub key: ProfileKey,
    pub current_day: u32,
    pub horizon: u32,
    pub components: AnalyzedProfileComponents,
    pub scopes: Box<[AnalyzedProfileScope]>,
}

fn slot(
    value: &CanonicalValue,
    domain: CanonicalDomain,
    maximum: usize,
) -> Result<CapturedSlotKind, ProfileDataError> {
    Ok(match domain {
        CanonicalDomain::LegacyField => CapturedSlotKind::LegacyField,
        CanonicalDomain::Headers => CapturedSlotKind::Headers,
        CanonicalDomain::PseudoHeaders => CapturedSlotKind::PseudoHeaders,
        CanonicalDomain::RuntimeMetadata => CapturedSlotKind::RuntimeMetadata,
        CanonicalDomain::H2 => CapturedSlotKind::Http2EarlyFrames,
        CanonicalDomain::QuicFlight => CapturedSlotKind::QuicFirstFlight,
        CanonicalDomain::H3Sequence => CapturedSlotKind::Http3Sequence,
        CanonicalDomain::H3Bootstrap => CapturedSlotKind::Http3Bootstrap,
        CanonicalDomain::Order => match OrderedProtocolCapture::from_canonical(
            value,
            OrderCaptureLimits {
                elements: maximum,
                bytes: maximum,
            },
        )?
        .namespace
        {
            OrderNamespace::QuicParameter => CapturedSlotKind::QuicParameters,
            OrderNamespace::Http3Setting => CapturedSlotKind::Http3Settings,
            OrderNamespace::QuicVersion => CapturedSlotKind::QuicVersions,
        },
        #[cfg(feature = "tls")]
        CanonicalDomain::Tls => match TlsCapture::from_canonical(
            value,
            TlsCaptureLimits {
                elements: maximum,
                bytes: maximum,
            },
        )?
        .transport
        {
            TlsCaptureTransport::Tcp => CapturedSlotKind::TcpTls,
            TlsCaptureTransport::Quic => CapturedSlotKind::QuicTls,
        },
        _ => {
            return Err(ProfileDataError::Invalid(
                "profile evidence component domain",
            ));
        }
    })
}

fn joint(
    value: &CanonicalValue,
    domain: CanonicalDomain,
    limits: JointCaptureLimits,
) -> Result<JointCapture, ProfileDataError> {
    if domain == CanonicalDomain::Joint {
        return JointCapture::from_canonical(value, limits);
    }
    let kind = slot(value, domain, limits.value_bytes)?;
    let level = match kind {
        CapturedSlotKind::LegacyField => CaptureLevel::Legacy,
        CapturedSlotKind::Headers
        | CapturedSlotKind::PseudoHeaders
        | CapturedSlotKind::RuntimeMetadata => CaptureLevel::Request,
        _ => CaptureLevel::Connection,
    };
    Ok(JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level,
        slots: vec![CapturedSlot {
            kind,
            value: value.clone(),
        }]
        .into(),
    })
}

/// Authorization is selected by the caller, independently of serialized scope
/// metadata. The seed must be the persisted sampler seed for that partition.
pub fn analyze_profile_evidence(
    input: &ProfileEvidence,
    authorized: bool,
    seed: [u8; 32],
    current_day: u32,
    horizon: u32,
    limits: ProfileAnalysisLimits,
) -> Result<AnalyzedProfile, ProfileDataError> {
    if input.format_version != 1 {
        return Err(ProfileDataError::Unsupported("profile evidence format"));
    }
    // Stored scopes that differ only by volatile literals are analyzed as one.
    let normalized = normalize_profile_evidence(input, authorized, seed, limits)?;
    if normalized.dropped_scopes > 0 {
        return Err(ProfileDataError::LimitExceeded("profile analysis scopes"));
    }
    let input = &normalized.evidence;
    limits.window.retention.first_day(current_day, horizon)?;
    let order = OrderAnalysisConfig {
        maximum_literals: limits
            .order
            .maximum_literals
            .checked_mul(horizon as usize)
            .ok_or(ProfileDataError::LimitExceeded("profile horizon literals"))?,
        ..limits.order
    };
    let mut remaining = limits.bytes;
    let mut charge = |bytes: usize| -> Result<(), ProfileDataError> {
        remaining = remaining
            .checked_sub(bytes)
            .ok_or(ProfileDataError::LimitExceeded("profile analysis bytes"))?;
        Ok(())
    };
    charge(input.profile.bytes.len())?;
    for evidence in &input.scopes {
        charge(evidence.scope.bytes.len())?;
        charge(evidence.structure.bytes.len())?;
        if let Some(flow) = &evidence.flow {
            charge(flow.bytes.len())?;
        }
        if evidence.window.buckets.len() > limits.window.retention.days as usize {
            return Err(ProfileDataError::LimitExceeded("profile analysis days"));
        }
        for day in &evidence.window.buckets {
            for value in &day.bucket.values {
                charge(value.bytes.len())?;
            }
        }
    }
    let mut remaining_work = limits
        .maximum_work
        .checked_sub(normalized.work_units)
        .and_then(|work| work.checked_sub(limits.bytes - remaining))
        .ok_or(ProfileDataError::LimitExceeded("profile analysis work"))?;
    let key = ProfileKey::from_canonical(&input.profile, limits.metadata_bytes)?;
    let capture_limits = JointCaptureLimits {
        value_bytes: limits.window.bucket.input_bytes,
        bytes: limits.window.bucket.input_bytes,
        ..JointCaptureLimits::default()
    };
    let mut scopes = Vec::new();
    let mut seen = BTreeSet::new();
    let mut components: [BTreeSet<usize>; 6] = std::array::from_fn(|_index| BTreeSet::new());
    for evidence in &input.scopes {
        if !seen.insert(evidence.scope.id) {
            return Err(ProfileDataError::Invalid("duplicate profile scope"));
        }
        let context =
            ProfileObservationScope::from_canonical(&evidence.scope, limits.metadata_bytes)?;
        if context.authorized != authorized
            || context.profile != input.profile.id
            || context.structure != evidence.structure.id
            || context.flow != evidence.flow.as_ref().map(|flow| flow.id)
        {
            return Err(ProfileDataError::Invalid("profile evidence ownership"));
        }
        let flow = evidence
            .flow
            .as_ref()
            .map(|value| FlowKey::from_canonical(value, limits.metadata_bytes))
            .transpose()?;
        // Scopes are normalized above; this also covers callers' own evidence.
        let normalized_structure =
            normalize_stored_structure(&evidence.structure, limits.metadata_bytes)?;
        let mut normalized_context = context.clone();
        normalized_context.structure = normalized_structure.id;
        let normalized_scope = normalized_context.canonical(limits.metadata_bytes)?;
        let window = RetainedBucketWindow::from_snapshot(
            &evidence.window,
            evidence.window.domain,
            evidence.scope.id,
            seed,
            limits.window,
        )?;
        let bucket = window.select(current_day, horizon)?;
        let retained = bucket.snapshot();
        if retained.counts.total == 0 {
            continue;
        }
        let index = scopes.len();
        for value in &retained.values {
            let joint = joint(value, retained.domain, capture_limits)?;
            let prepared = ProfileCapture {
                profile: key.clone(),
                flow: flow.clone(),
                connection: context.connection.clone(),
                joint: joint.clone(),
            }
            .prepare(authorized, capture_limits)?;
            if !prepared.buckets.iter().any(|bucket| {
                bucket.value.id == value.id
                    && bucket.scope.bytes == normalized_scope.bytes
                    && bucket.structure.bytes == normalized_structure.bytes
            }) {
                return Err(ProfileDataError::Invalid(
                    "profile evidence structural membership",
                ));
            }
            for slot in &joint.slots {
                match slot.kind {
                    CapturedSlotKind::TcpTls => {
                        components[3].insert(index);
                    }
                    CapturedSlotKind::QuicTls => {
                        components[4].insert(index);
                    }
                    CapturedSlotKind::QuicParameters
                    | CapturedSlotKind::QuicFirstFlight
                    | CapturedSlotKind::QuicVersions => {
                        components[5].insert(index);
                    }
                    CapturedSlotKind::Http3Settings
                    | CapturedSlotKind::Http3Sequence
                    | CapturedSlotKind::Http3Bootstrap => {
                        components[2].insert(index);
                    }
                    CapturedSlotKind::Http2EarlyFrames => {
                        components[1].insert(index);
                    }
                    CapturedSlotKind::Headers | CapturedSlotKind::PseudoHeaders => {
                        if let Some(FlowKey::Http { version, .. }) = &flow {
                            match *version {
                                Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => {
                                    components[0].insert(index);
                                }
                                Version::HTTP_2 => {
                                    components[1].insert(index);
                                }
                                Version::HTTP_3 => {
                                    components[2].insert(index);
                                }
                            }
                        }
                    }
                    CapturedSlotKind::LegacyField => {
                        let legacy =
                            LegacyFieldCapture::from_canonical(&slot.value, limits.metadata_bytes)?;
                        match legacy.field.protocol() {
                            Some(LegacyHttpProtocol::Http1) => {
                                components[0].insert(index);
                            }
                            Some(LegacyHttpProtocol::Http2) => {
                                components[1].insert(index);
                            }
                            None if legacy.field == LegacyField::TcpTls => {
                                components[3].insert(index);
                            }
                            None => (),
                        }
                    }
                    CapturedSlotKind::RuntimeMetadata => (),
                }
            }
        }
        let observations = analyze_capture_bucket(
            &bucket,
            OrderAnalysisConfig {
                maximum_work: order.maximum_work.min(remaining_work),
                ..order
            },
        )?;
        remaining_work = remaining_work
            .checked_sub(observations.order_work)
            .ok_or(ProfileDataError::LimitExceeded("profile analysis work"))?;
        scopes.push(AnalyzedProfileScope {
            id: evidence.scope.id,
            context,
            flow,
            structure: evidence.structure.clone(),
            observations,
        });
    }
    let [h1, h2, h3, tls_tcp, tls_quic, quic] = components.map(|scopes| {
        if scopes.is_empty() {
            None
        } else {
            Some(scopes.into_iter().collect())
        }
    });
    Ok(AnalyzedProfile {
        work_units: limits.maximum_work - remaining_work,
        format_version: 1,
        classifier_revision: 2,
        id: input.profile.id,
        key,
        current_day,
        horizon,
        components: AnalyzedProfileComponents {
            h1,
            h2,
            h3,
            tls_tcp,
            tls_quic,
            quic,
        },
        scopes: scopes.into(),
    })
}

#[cfg(test)]
mod tests;
