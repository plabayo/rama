//! Merge analyzed variants that read the same once rewritten.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    AnalyzedCaptureVariant, CaptureOrderAnalysis, CaptureOrderVariant, CountedCaptureAnalysis,
    sequences,
};
use crate::profile::{
    analysis::order::{AnalyzedOrderWeight, OrderAnalysisConfig},
    evidence::counts::{LiteralCount, ObservationWeight},
    format::canonical::{CanonicalValue, ProfileDataError, ValueId},
};

fn sum(a: u64, b: u64) -> Result<u64, ProfileDataError> {
    a.checked_add(b)
        .ok_or(ProfileDataError::LimitExceeded("merged variant weight"))
}

/// The weight of two variants that read the same.
pub(super) fn merge_weights(
    a: &AnalyzedOrderWeight,
    b: &AnalyzedOrderWeight,
) -> Result<AnalyzedOrderWeight, ProfileDataError> {
    Ok(match (a, b) {
        (
            AnalyzedOrderWeight::Counted(ObservationWeight::Exact(a)),
            AnalyzedOrderWeight::Counted(ObservationWeight::Exact(b)),
        ) => AnalyzedOrderWeight::Counted(ObservationWeight::Exact(sum(*a, *b)?)),
        (
            AnalyzedOrderWeight::Counted(ObservationWeight::UnknownHistory {
                observed: a,
                unassigned,
            }),
            AnalyzedOrderWeight::Counted(ObservationWeight::UnknownHistory { observed: b, .. }),
        ) => AnalyzedOrderWeight::Counted(ObservationWeight::UnknownHistory {
            observed: sum(*a, *b)?,
            unassigned: *unassigned,
        }),
        (
            AnalyzedOrderWeight::Counted(ObservationWeight::LowerBound {
                observed: a,
                unassigned,
            }),
            AnalyzedOrderWeight::Counted(ObservationWeight::LowerBound { observed: b, .. }),
        ) => AnalyzedOrderWeight::Counted(ObservationWeight::LowerBound {
            observed: sum(*a, *b)?,
            unassigned: *unassigned,
        }),
        (
            AnalyzedOrderWeight::Sample {
                observed: a,
                sample_size,
                population,
                history_known,
            },
            AnalyzedOrderWeight::Sample { observed: b, .. },
        ) => AnalyzedOrderWeight::Sample {
            observed: a
                .checked_add(*b)
                .ok_or(ProfileDataError::LimitExceeded("merged variant weight"))?,
            sample_size: *sample_size,
            population: *population,
            history_known: *history_known,
        },
        _ => return Err(ProfileDataError::Invalid("mixed variant weight kinds")),
    })
}

/// Rewrite and merge variants; preserved ones stay exact because other scopes name them.
pub(super) fn merge_rewritten(
    analysis: &mut CountedCaptureAnalysis,
    config: OrderAnalysisConfig,
    preserved: &BTreeSet<ValueId>,
    rewrite: impl Fn(&CanonicalValue) -> Result<CanonicalValue, ProfileDataError>,
) -> Result<(), ProfileDataError> {
    let mut renamed = BTreeMap::new();
    let mut merged: Vec<AnalyzedCaptureVariant> = Vec::with_capacity(analysis.variants.len());
    let mut positions = BTreeMap::<ValueId, usize>::new();
    for variant in &analysis.variants {
        let value = variant.value.canonical()?;
        let read = if preserved.contains(&value.id) {
            value.into_owned()
        } else {
            rewrite(&value)?
        };
        renamed.insert(variant.value.id(), read.id);
        if let Some(&position) = positions.get(&read.id) {
            let existing = merged
                .get_mut(position)
                .ok_or(ProfileDataError::Invalid("unanalyzed capture variant"))?;
            existing.weight = merge_weights(&existing.weight, &variant.weight)?;
        } else {
            positions.insert(read.id, merged.len());
            merged.push(AnalyzedCaptureVariant {
                value: read.into(),
                weight: variant.weight.clone(),
            });
        }
    }
    let rename = |id: &ValueId| {
        renamed
            .get(id)
            .copied()
            .ok_or(ProfileDataError::Invalid("unanalyzed capture variant"))
    };

    let mut orders: Vec<CaptureOrderAnalysis> = analysis.orders.to_vec();
    for order in &mut orders {
        let mut kept = BTreeMap::new();
        for variant in &order.variants {
            let value = rename(&variant.value)?;
            if kept.contains_key(&value) {
                continue;
            }
            let read = positions
                .get(&value)
                .and_then(|position| merged.get(*position))
                .ok_or(ProfileDataError::Invalid("unanalyzed capture variant"))?;
            let elements = sequences(&*read.value.canonical()?, analysis.domain, config)?
                .remove(&order.path)
                .ok_or(ProfileDataError::Invalid("merged variant order path"))?
                .iter()
                .map(|element| {
                    order
                        .dictionary
                        .binary_search(element)
                        .map(|index| index as u16)
                        .map_err(|_error| ProfileDataError::Invalid("missing capture element"))
                })
                .collect::<Result<_, _>>()?;
            kept.insert(value, CaptureOrderVariant { value, elements });
        }
        order.variants = kept.into_values().collect();
    }

    analysis.sample_values = analysis
        .sample_values
        .iter()
        .map(rename)
        .collect::<Result<_, _>>()?;
    let mut literals = BTreeMap::<ValueId, u64>::new();
    for literal in &analysis.counts.values {
        // Literals outside the analyzed variants keep their identity.
        let value = renamed
            .get(&literal.value)
            .copied()
            .unwrap_or(literal.value);
        let count = literals.entry(value).or_default();
        *count = sum(*count, literal.count)?;
    }
    analysis.counts.values = literals
        .into_iter()
        .map(|(value, count)| LiteralCount { value, count })
        .collect();
    analysis.variants = merged.into();
    analysis.orders = orders.into();
    Ok(())
}
