//! Merge stored scopes that share today's structural normalization.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::profile::{
    analysis::profile::ProfileAnalysisLimits,
    capture::joint::normalize_stored_structure,
    evidence::{ProfileEvidence, ProfileScopeEvidence, window::RetainedBucketWindow},
    format::canonical::{CanonicalValue, ProfileDataError, ValueId},
    model::scope::ProfileObservationScope,
};

/// Evidence with one scope per normalized structure, plus what was left out.
#[derive(Debug, Clone, Serialize)]
pub struct NormalizedProfileEvidence {
    pub evidence: ProfileEvidence,
    /// Stored scopes in the input.
    pub stored_scopes: usize,
    /// Normalized scopes left out because the scope limit was reached.
    pub dropped_scopes: usize,
    /// Stored scopes that belonged to the dropped normalized scopes.
    pub dropped_stored_scopes: usize,
    /// Work spent normalizing, charged against `ProfileAnalysisLimits::maximum_work`.
    pub work_units: usize,
}

struct MergedScope {
    scope: CanonicalValue,
    flow: Option<CanonicalValue>,
    structure: CanonicalValue,
    window: RetainedBucketWindow,
}

/// Group stored scopes by today's normalization and merge their retained days.
///
/// Older stores split one client shape into many scopes when header values changed per
/// request. Input order decides which normalized scopes are kept once `limits.scopes`
/// is reached, so callers list the scopes to keep first. Ownership is checked
/// for every stored scope, including the dropped ones.
pub fn normalize_profile_evidence(
    input: &ProfileEvidence,
    authorized: bool,
    seed: [u8; 32],
    limits: ProfileAnalysisLimits,
) -> Result<NormalizedProfileEvidence, ProfileDataError> {
    if input.format_version != 1 {
        return Err(ProfileDataError::Unsupported("profile evidence format"));
    }
    if input.scopes.len() > limits.stored_scopes {
        return Err(ProfileDataError::LimitExceeded(
            "profile analysis stored scopes",
        ));
    }
    let mut merged: Vec<MergedScope> = Vec::new();
    let mut index = BTreeMap::<ValueId, usize>::new();
    let mut dropped = BTreeMap::<ValueId, usize>::new();
    let mut seen = BTreeSet::new();
    let mut remaining_work = limits.maximum_work;
    let mut charge = |units: usize| -> Result<(), ProfileDataError> {
        remaining_work = remaining_work
            .checked_sub(units)
            .ok_or(ProfileDataError::LimitExceeded("profile analysis work"))?;
        Ok(())
    };
    for evidence in &input.scopes {
        if !seen.insert(evidence.scope.id) {
            return Err(ProfileDataError::Invalid("duplicate profile scope"));
        }
        charge(evidence.scope.bytes.len() + evidence.structure.bytes.len())?;
        let context = owned_context(input, evidence, authorized, limits.metadata_bytes)?;
        let structure = normalize_stored_structure(&evidence.structure, limits.metadata_bytes)?;
        let mut normalized = context;
        normalized.structure = structure.id;
        let scope = normalized.canonical(limits.metadata_bytes)?;
        if let Some(count) = dropped.get_mut(&scope.id) {
            *count += 1;
            continue;
        }
        let position = index.get(&scope.id).copied();
        if position.is_none() && merged.len() >= limits.scopes {
            dropped.insert(scope.id, 1);
            continue;
        }
        for day in &evidence.window.buckets {
            for value in &day.bucket.values {
                charge(value.bytes.len())?;
            }
        }
        let mut window = RetainedBucketWindow::from_snapshot(
            &evidence.window,
            evidence.window.domain,
            evidence.scope.id,
            seed,
            limits.window,
        )?;
        if scope.id != evidence.scope.id {
            window = window.rescoped(scope.id)?;
        }
        if let Some(position) = position {
            let entry = &mut merged[position];
            entry.window = entry.window.merge_scope(&window)?;
        } else {
            index.insert(scope.id, merged.len());
            merged.push(MergedScope {
                scope,
                flow: evidence.flow.clone(),
                structure,
                window,
            });
        }
    }
    // Input order only ranks which scopes fit; archives require ascending scope IDs.
    merged.sort_unstable_by_key(|entry| entry.scope.id);
    Ok(NormalizedProfileEvidence {
        evidence: ProfileEvidence {
            format_version: input.format_version,
            profile: input.profile.clone(),
            scopes: merged
                .into_iter()
                .map(|entry| ProfileScopeEvidence {
                    scope: entry.scope,
                    flow: entry.flow,
                    structure: entry.structure,
                    window: entry.window.snapshot(),
                })
                .collect(),
        },
        stored_scopes: input.scopes.len(),
        dropped_scopes: dropped.len(),
        dropped_stored_scopes: dropped.values().sum(),
        work_units: limits.maximum_work - remaining_work,
    })
}

/// Normalized identity of one stored scope.
pub fn normalized_scope_id(
    scope: &CanonicalValue,
    structure: &CanonicalValue,
    maximum_bytes: usize,
) -> Result<ValueId, ProfileDataError> {
    let mut context = ProfileObservationScope::from_canonical(scope, maximum_bytes)?;
    if context.structure != structure.id {
        return Err(ProfileDataError::Invalid("profile evidence ownership"));
    }
    context.structure = normalize_stored_structure(structure, maximum_bytes)?.id;
    Ok(context.canonical(maximum_bytes)?.id)
}

fn owned_context(
    input: &ProfileEvidence,
    evidence: &ProfileScopeEvidence,
    authorized: bool,
    maximum_bytes: usize,
) -> Result<ProfileObservationScope, ProfileDataError> {
    let context = ProfileObservationScope::from_canonical(&evidence.scope, maximum_bytes)?;
    if context.authorized != authorized
        || context.profile != input.profile.id
        || context.structure != evidence.structure.id
        || context.flow != evidence.flow.as_ref().map(|flow| flow.id)
    {
        return Err(ProfileDataError::Invalid("profile evidence ownership"));
    }
    Ok(context)
}
