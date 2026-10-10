//! Bounded offline collection for the same analyzer used by database exports.

use std::collections::BTreeMap;

use super::{
    CanonicalValue, CaptureRunId, JointCaptureLimits, ObservationId, ProfileAnalysisLimits,
    ProfileCapture, ProfileDataError, ProfileEvidence, ProfileKey, ProfileScopeEvidence,
    RetainedBucketWindow, ValueId,
};

#[derive(Debug, Clone)]
struct Scope {
    canonical: CanonicalValue,
    flow: Option<CanonicalValue>,
    structure: CanonicalValue,
    window: RetainedBucketWindow,
}

impl Scope {
    fn bytes(&self) -> Result<usize, ProfileDataError> {
        [
            self.canonical.bytes.len(),
            self.flow.as_ref().map_or(0, |flow| flow.bytes.len()),
            self.structure.bytes.len(),
            self.window.retained_bytes(),
        ]
        .into_iter()
        .try_fold(0usize, |total, size| {
            total
                .checked_add(size)
                .ok_or(ProfileDataError::LimitExceeded("profile evidence bytes"))
        })
    }
}

/// Collect one profile from a pinned capture selection. Callers submit each
/// connection once and each request once. Rejected tuples leave every scope and
/// the sequence unchanged; connection and request tuples remain independent.
#[derive(Debug)]
pub struct ProfileEvidenceCollector {
    profile: CanonicalValue,
    authorized: bool,
    run: CaptureRunId,
    sequence: u64,
    seed: [u8; 32],
    current_day: u32,
    limits: ProfileAnalysisLimits,
    scopes: BTreeMap<ValueId, Scope>,
}

impl ProfileEvidenceCollector {
    pub fn new(
        profile: &ProfileKey,
        authorized: bool,
        run: CaptureRunId,
        seed: [u8; 32],
        current_day: u32,
        limits: ProfileAnalysisLimits,
    ) -> Result<Self, ProfileDataError> {
        limits.window.bucket.validate()?;
        limits
            .window
            .retention
            .validate_observation(current_day, run.created_day())?;
        let profile = profile.canonical(limits.metadata_bytes)?;
        if profile.bytes.len() > limits.bytes {
            return Err(ProfileDataError::LimitExceeded("profile evidence bytes"));
        }
        Ok(Self {
            profile,
            authorized,
            run,
            sequence: 0,
            seed,
            current_day,
            limits,
            scopes: BTreeMap::new(),
        })
    }

    pub fn observe(
        &mut self,
        observation_day: u32,
        capture: &ProfileCapture,
    ) -> Result<(), ProfileDataError> {
        self.limits
            .window
            .retention
            .validate_observation(self.current_day, observation_day)?;
        let prepared = capture.prepare(
            self.authorized,
            JointCaptureLimits {
                bytes: self.limits.window.bucket.input_bytes,
                value_bytes: self.limits.metadata_bytes,
                ..JointCaptureLimits::default()
            },
        )?;
        if prepared.profile.bytes != self.profile.bytes {
            return Err(ProfileDataError::Invalid("profile evidence owner"));
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(ProfileDataError::CounterOverflow)?;
        let observation = ObservationId {
            run: self.run.0,
            sequence,
        };
        let mut count = self.scopes.len();
        let mut pending = BTreeMap::new();
        for input in prepared.buckets {
            let mut scope = if let Some(previous) = self.scopes.get(&input.scope.id) {
                if previous.canonical.bytes != input.scope.bytes
                    || previous.structure.bytes != input.structure.bytes
                    || previous.flow.as_ref().map(|flow| &flow.bytes)
                        != prepared.flow.as_ref().map(|flow| &flow.bytes)
                {
                    return Err(ProfileDataError::IdentityMismatch);
                }
                previous.clone()
            } else {
                count = count
                    .checked_add(1)
                    .ok_or(ProfileDataError::LimitExceeded("profile evidence scopes"))?;
                if count > self.limits.scopes {
                    return Err(ProfileDataError::LimitExceeded("profile evidence scopes"));
                }
                let domain = input
                    .value
                    .validated_domain(self.limits.window.bucket.input_bytes)?;
                Scope {
                    window: RetainedBucketWindow::new(
                        domain,
                        input.scope.id,
                        self.seed,
                        self.limits.window,
                    )?,
                    canonical: input.scope,
                    flow: prepared.flow.clone(),
                    structure: input.structure,
                }
            };
            scope
                .window
                .observe(self.current_day, observation_day, observation, &input.value)?;
            pending.insert(scope.canonical.id, scope);
        }
        let mut remaining = self.limits.bytes - self.profile.bytes.len();
        for scope in self
            .scopes
            .iter()
            .filter(|(id, _scope)| !pending.contains_key(id))
            .map(|(_id, scope)| scope)
            .chain(pending.values())
        {
            remaining = remaining
                .checked_sub(scope.bytes()?)
                .ok_or(ProfileDataError::LimitExceeded("profile evidence bytes"))?;
        }
        self.scopes.extend(pending);
        self.sequence = sequence;
        Ok(())
    }

    pub fn finish(self) -> ProfileEvidence {
        ProfileEvidence {
            format_version: 1,
            profile: self.profile,
            scopes: self
                .scopes
                .into_values()
                .map(|scope| ProfileScopeEvidence {
                    scope: scope.canonical,
                    flow: scope.flow,
                    structure: scope.structure,
                    window: scope.window.snapshot(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests;
