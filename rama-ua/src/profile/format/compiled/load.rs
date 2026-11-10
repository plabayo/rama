//! The stored layout of a compiled set back into analyzed profiles. Every id that
//! is not stored is recomputed from the bytes it names, so it cannot disagree with them.

use std::{collections::hash_map::Entry, mem, sync::Arc};

use ahash::HashMap;
use rama_core::{bytes::Bytes, error::BoxError};
use sha2::{Digest as _, Sha256};

use super::{
    compact::{CompiledHeaders, ProfileFields, load_fields},
    wire::{
        WireCapture, WireMode, WireOrder, WireProfile, WireRule, WireSet, WireValue, for_each_value,
    },
};
use crate::profile::{
    analysis::{
        capture::{
            AnalyzedCaptureVariant, CaptureOrderAnalysis, CountedCaptureAnalysis, VariantValue,
        },
        order::{DerivedOrderRule, OrderAnalysisDisposition, OrderModeEvidence, OrderRuleEvidence},
        profile::{AnalyzedProfile, AnalyzedProfileScope, ProfileAnalysisLimits},
    },
    capture::joint::joint_slot_values,
    evidence::counts::CounterSnapshot,
    format::canonical::{CanonicalValue, ProfileDataError, ValueId},
    model::scope::ProfileObservationScope,
    replay::request::{FieldEntry, PendingCompact},
};

pub(super) fn load_set(mut set: WireSet) -> Result<Vec<AnalyzedProfile>, BoxError> {
    // Each stored value is hashed once; every reference shares its bytes.
    let mut stored = Vec::new();
    for_each_value(&mut set, |_role, value| {
        if let WireValue::Bytes(bytes) = value {
            let index = u32::try_from(stored.len())
                .map_err(|_error| ProfileDataError::LimitExceeded("compiled stored values"))?;
            let bytes = mem::take(bytes);
            stored.push(CanonicalValue {
                id: ValueId(Sha256::digest(bytes.as_ref()).into()),
                bytes,
            });
            *value = WireValue::Stored(index);
        }
        Ok(())
    })?;
    let mut values = Values {
        stored,
        slots: HashMap::default(),
    };
    let fields = load_fields(&set.fields)?;
    set.profiles
        .into_iter()
        .map(|profile| load_profile(profile, &mut values, &fields, &set.headers))
        .collect()
}

/// The stored values of a set and the slots split from the joints that are referenced.
struct Values {
    stored: Vec<CanonicalValue>,
    slots: HashMap<u32, Vec<CanonicalValue>>,
}

impl Values {
    fn resolve(&mut self, value: &WireValue) -> Result<CanonicalValue, BoxError> {
        let reference = || ProfileDataError::Invalid("compiled profile set value reference");
        match value {
            WireValue::Bytes(_) => Err(reference().into()),
            WireValue::Stored(index) => Ok(self
                .stored
                .get(*index as usize)
                .cloned()
                .ok_or_else(reference)?),
            WireValue::Slot { joint, slot } => {
                let slots = match self.slots.entry(*joint) {
                    Entry::Occupied(entry) => entry.into_mut(),
                    Entry::Vacant(entry) => {
                        let joint = self.stored.get(*joint as usize).ok_or_else(reference)?;
                        entry.insert(joint_slot_values(joint).map_err(|_error| reference())?)
                    }
                };
                Ok(slots.get(*slot as usize).cloned().ok_or_else(reference)?)
            }
        }
    }
}

fn load_profile(
    profile: WireProfile,
    values: &mut Values,
    fields: &[FieldEntry],
    headers: &[CompiledHeaders],
) -> Result<AnalyzedProfile, BoxError> {
    let metadata = ProfileAnalysisLimits::default().metadata_bytes;
    let id = profile.key.canonical(metadata)?.id;
    let mut table = ProfileFields::new(fields, headers);
    let mut compact = Vec::new();
    let mut scopes = Vec::with_capacity(profile.scopes.len());
    for (scope_index, scope) in profile.scopes.into_iter().enumerate() {
        let structure = values.resolve(&scope.structure)?;
        let flow = scope
            .flow
            .as_ref()
            .map(|flow| flow.canonical(metadata).map(|value| value.id))
            .transpose()?;
        let context = ProfileObservationScope {
            authorized: scope.authorized,
            profile: id,
            flow,
            connection: scope.connection,
            structure: structure.id,
            revision: scope.revision,
        };
        let scope_id = context.canonical(metadata)?.id;
        let observations = scope.observations;
        let mut variants = Vec::with_capacity(observations.variants.len());
        for (variant_index, variant) in observations.variants.into_iter().enumerate() {
            let value = match variant.value {
                WireCapture::Canonical(value) => VariantValue::Canonical(values.resolve(&value)?),
                WireCapture::Compact { id, capture } => {
                    let kind = table.capture(&capture, |value| values.resolve(value))?;
                    compact.push((
                        scope_index,
                        variant_index,
                        PendingCompact::from_parts(id, kind),
                    ));
                    // Replaced below, once the profile's field table is complete.
                    VariantValue::Canonical(CanonicalValue {
                        id,
                        bytes: Bytes::new(),
                    })
                }
            };
            variants.push(AnalyzedCaptureVariant {
                value,
                weight: variant.weight,
            });
        }
        let sample_values = observations
            .sample_values
            .iter()
            .map(|index| {
                variants
                    .get(*index as usize)
                    .map(|variant| variant.value.id())
                    .ok_or(ProfileDataError::Invalid("compiled profile sample value"))
            })
            .collect::<Result<_, _>>()?;
        scopes.push(AnalyzedProfileScope {
            id: scope_id,
            context,
            flow: scope.flow,
            structure,
            observations: CountedCaptureAnalysis {
                classifier_revision: observations.classifier_revision,
                order_work: 0,
                domain: observations.domain,
                scope: scope_id,
                counts: CounterSnapshot {
                    total: observations.total,
                    untracked: 0,
                    values: Box::default(),
                    losses: observations.losses,
                    untracked_distinct: Default::default(),
                },
                retained_samples: 0,
                sample_values,
                variants: variants.into(),
                orders: observations.orders.into_iter().map(load_order).collect(),
                numeric: Box::default(),
                network_hints: observations.network_hints,
            },
        });
    }
    let table = table.finish();
    for (scope, variant, pending) in compact {
        let variant = scopes
            .get_mut(scope)
            .and_then(|scope| scope.observations.variants.get_mut(variant))
            .ok_or(ProfileDataError::Invalid("compact capture position"))?;
        variant.value = VariantValue::Compact(Arc::new(pending.finish(Arc::clone(&table))));
    }
    Ok(AnalyzedProfile {
        work_units: 0,
        format_version: profile.format_version,
        classifier_revision: profile.classifier_revision,
        id,
        key: profile.key,
        current_day: profile.current_day,
        horizon: profile.horizon,
        components: profile.components,
        scopes: scopes.into(),
    })
}

/// Order evidence holding only its rule; the unstored evidence loads empty.
pub(super) fn load_order(order: WireOrder) -> CaptureOrderAnalysis {
    CaptureOrderAnalysis {
        path: order.path,
        dictionary: Box::default(),
        variants: Box::default(),
        missing_samples: Box::default(),
        evidence: load_evidence(order.derived, order.disposition),
    }
}

fn load_evidence(
    derived: Option<WireRule>,
    disposition: OrderAnalysisDisposition,
) -> OrderRuleEvidence {
    OrderRuleEvidence {
        normalized_distinct_orders: 0,
        positions: Box::default(),
        derived: derived.map(load_rule),
        disposition,
    }
}

fn load_rule(rule: WireRule) -> DerivedOrderRule {
    match rule {
        WireRule::Mixture { modes } => DerivedOrderRule::Mixture {
            modes: modes.into_iter().map(load_mode).collect(),
        },
        WireRule::Sorted { elements } => DerivedOrderRule::Sorted { elements },
        WireRule::Relative {
            literals,
            placements,
        } => DerivedOrderRule::Relative {
            literals,
            placements,
        },
        WireRule::Shuffled { elements, pinned } => DerivedOrderRule::Shuffled { elements, pinned },
    }
}

fn load_mode(mode: WireMode) -> OrderModeEvidence {
    OrderModeEvidence {
        elements: Box::default(),
        sample_indices: mode.sample_indices,
        sample_count: 0,
        sample_size: mode.sample_size,
        evidence: Box::new(load_evidence(mode.derived, mode.disposition)),
    }
}
