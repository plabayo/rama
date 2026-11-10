//! Analyzed profiles into the stored layout of a compiled set.

use ahash::{HashMap, HashSet};
use rama_core::error::BoxError;
use sha2::{Digest as _, Sha256};

use super::{
    compact::{HeaderInterner, compiled_capture, compiled_fields},
    load::load_order,
    wire::{
        ValueRole, WireCapture, WireMode, WireObservations, WireOrder, WireProfile, WireRule,
        WireScope, WireSet, WireValue, WireVariant, for_each_value,
    },
};
use crate::profile::{
    analysis::{
        capture::{CaptureOrderAnalysis, CaptureOrderPath},
        order::DerivedOrderRule,
        profile::{AnalyzedProfile, AnalyzedProfileScope, PROFILE_CLASSIFIER_REVISION},
    },
    capture::joint::joint_slot_values,
    format::canonical::{CanonicalDomain, CanonicalValue, ProfileDataError, ValueId},
    replay::request::{FieldTableBuilder, PendingCompact},
};

/// Order paths replay reads: TLS extension shuffling and HTTP/3 SETTINGS generation.
fn replayed(path: CaptureOrderPath) -> bool {
    matches!(
        path,
        CaptureOrderPath::TlsExtensions | CaptureOrderPath::Http3Settings
    )
}

/// `profile` with only what selection and replay read; the rest stays in archives.
pub(super) fn retained(profile: &AnalyzedProfile) -> AnalyzedProfile {
    let mut profile = profile.clone();
    profile.work_units = 0;
    for scope in profile.scopes.iter_mut() {
        let observations = &mut scope.observations;
        observations.order_work = 0;
        observations.retained_samples = 0;
        observations.counts.untracked = 0;
        observations.counts.values = Box::default();
        observations.counts.untracked_distinct = Default::default();
        // HTTP/3 SETTINGS replay derives its generators from these samples.
        if observations.domain != CanonicalDomain::Order {
            observations.sample_values = Box::default();
        }
        observations.numeric = Box::default();
        observations.orders = observations
            .orders
            .iter()
            .filter(|order| replayed(order.path))
            .map(|order| load_order(wire_order(order)))
            .collect();
    }
    profile
}

/// The stored layout of `profiles`, which must already be [`retained`].
pub(super) fn compile_set(profiles: &[AnalyzedProfile]) -> Result<WireSet, BoxError> {
    let mut fields = FieldTableBuilder::default();
    let mut headers = HeaderInterner::default();
    let profiles = profiles
        .iter()
        .map(|profile| {
            Ok(WireProfile {
                format_version: profile.format_version,
                classifier_revision: profile.classifier_revision,
                key: profile.key.clone(),
                current_day: profile.current_day,
                horizon: profile.horizon,
                components: profile.components.clone(),
                scopes: profile
                    .scopes
                    .iter()
                    .map(|scope| compile_scope(scope, &mut fields, &mut headers))
                    .collect::<Result<_, BoxError>>()?,
            })
        })
        .collect::<Result<_, BoxError>>()?;
    let mut set = WireSet {
        classifier_revision: PROFILE_CLASSIFIER_REVISION,
        fields: compiled_fields(&fields.finish()),
        headers: headers.finish(),
        profiles,
    };
    share_repeated_values(&mut set)?;
    Ok(set)
}

fn compile_scope(
    scope: &AnalyzedProfileScope,
    fields: &mut FieldTableBuilder,
    headers: &mut HeaderInterner,
) -> Result<WireScope, BoxError> {
    let observations = &scope.observations;
    let request = scope.flow.is_some() && observations.domain == CanonicalDomain::Joint;
    let compactable = request || observations.domain == CanonicalDomain::Headers;
    let mut positions = HashMap::default();
    let mut variants = Vec::with_capacity(observations.variants.len());
    for (index, variant) in observations.variants.iter().enumerate() {
        let original = variant.value.canonical()?;
        let position = u32::try_from(index)
            .map_err(|_error| ProfileDataError::LimitExceeded("compiled scope variants"))?;
        positions.entry(original.id).or_insert(position);
        let compacted = if !compactable {
            None
        } else if request {
            PendingCompact::request(&original, fields).ok()
        } else {
            PendingCompact::headers(&original, fields).ok()
        };
        // A capture that does not decode stays canonical; selection reports it.
        let value = match compacted {
            Some(compacted) => WireCapture::Compact {
                id: original.id,
                capture: compiled_capture(compacted.kind(), headers)?,
            },
            None => WireCapture::Canonical(WireValue::Bytes(original.bytes.clone())),
        };
        variants.push(WireVariant {
            value,
            weight: variant.weight.clone(),
        });
    }
    let sample_values = observations
        .sample_values
        .iter()
        .map(|id| {
            positions
                .get(id)
                .copied()
                .ok_or(ProfileDataError::Invalid("compiled profile sample value"))
        })
        .collect::<Result<_, _>>()?;
    Ok(WireScope {
        authorized: scope.context.authorized,
        connection: scope.context.connection.clone(),
        revision: scope.context.revision,
        flow: scope.flow.clone(),
        structure: WireValue::Bytes(scope.structure.bytes.clone()),
        observations: WireObservations {
            classifier_revision: observations.classifier_revision,
            domain: observations.domain,
            total: observations.counts.total,
            losses: observations.counts.losses,
            sample_values,
            variants,
            orders: observations
                .orders
                .iter()
                .filter(|order| replayed(order.path))
                .map(wire_order)
                .collect(),
            network_hints: observations.network_hints.clone(),
        },
    })
}

fn wire_order(order: &CaptureOrderAnalysis) -> WireOrder {
    WireOrder {
        path: order.path,
        derived: order.evidence.derived.as_ref().map(wire_rule),
        disposition: order.evidence.disposition,
    }
}

fn wire_rule(rule: &DerivedOrderRule) -> WireRule {
    match rule {
        DerivedOrderRule::Mixture { modes } => WireRule::Mixture {
            modes: modes
                .iter()
                .map(|mode| WireMode {
                    sample_indices: mode.sample_indices.clone(),
                    sample_size: mode.sample_size,
                    derived: mode.evidence.derived.as_ref().map(wire_rule),
                    disposition: mode.evidence.disposition,
                })
                .collect(),
        },
        DerivedOrderRule::Sorted { elements } => WireRule::Sorted {
            elements: elements.clone(),
        },
        DerivedOrderRule::Relative {
            literals,
            placements,
        } => WireRule::Relative {
            literals: literals.clone(),
            placements: placements.clone(),
        },
        DerivedOrderRule::Shuffled { elements, pinned } => WireRule::Shuffled {
            elements: elements.clone(),
            pinned: pinned.clone(),
        },
    }
}

/// Keep each distinct value's bytes once. A repeat names that copy, and a component
/// held by a stored joint capture names the joint's slot instead.
fn share_repeated_values(set: &mut WireSet) -> Result<(), BoxError> {
    let mut visited: Vec<(ValueRole, ValueId)> = Vec::new();
    let mut joints = HashSet::default();
    let mut slots: HashMap<ValueId, (ValueId, u32)> = HashMap::default();
    for_each_value(set, |role, value| {
        let WireValue::Bytes(bytes) = value else {
            return Err(ProfileDataError::Invalid("compiled value reference").into());
        };
        let id = ValueId(Sha256::digest(bytes.as_ref()).into());
        if role == ValueRole::Joint && joints.insert(id) {
            let joint = CanonicalValue {
                id,
                bytes: bytes.clone(),
            };
            for (index, slot) in joint_slot_values(&joint)
                .unwrap_or_default()
                .into_iter()
                .enumerate()
            {
                let index = u32::try_from(index)
                    .map_err(|_error| ProfileDataError::LimitExceeded("joint capture slots"))?;
                slots.entry(slot.id).or_insert((id, index));
            }
        }
        visited.push((role, id));
        Ok(())
    })?;
    let mut stored: HashMap<ValueId, u32> = HashMap::default();
    let mut keeps = Vec::with_capacity(visited.len());
    for (role, id) in &visited {
        let keep =
            !stored.contains_key(id) && (*role == ValueRole::Joint || !slots.contains_key(id));
        if keep {
            let index = u32::try_from(stored.len())
                .map_err(|_error| ProfileDataError::LimitExceeded("compiled stored values"))?;
            stored.insert(*id, index);
        }
        keeps.push(keep);
    }
    let mut position = 0;
    for_each_value(set, |_role, value| {
        let (Some((_role, id)), Some(keep)) = (visited.get(position), keeps.get(position)) else {
            return Err(ProfileDataError::Invalid("compiled value reference").into());
        };
        position += 1;
        if *keep {
            return Ok(());
        }
        *value = match (stored.get(id), slots.get(id)) {
            (Some(index), _) => WireValue::Stored(*index),
            (None, Some((joint, slot))) => WireValue::Slot {
                joint: stored
                    .get(joint)
                    .copied()
                    .ok_or(ProfileDataError::Invalid("compiled joint reference"))?,
                slot: *slot,
            },
            (None, None) => {
                return Err(ProfileDataError::Invalid("compiled value reference").into());
            }
        };
        Ok(())
    })
}
