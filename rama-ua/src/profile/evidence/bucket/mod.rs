//! A bounded counting bucket with one copy of each retained canonical value.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use rama_utils::octets::{kib, mib};
use serde::{Deserialize, Serialize};

use crate::profile::{
    evidence::{
        counts::{CounterSnapshot, LiteralCounters, ObservationLoss},
        ingestion::ObservationId,
        reservoir::{ObservationReservoir, ReservoirEntry},
    },
    format::canonical::{CanonicalDomain, CanonicalValue, ProfileDataError, ValueId},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileBucketLimits {
    pub literal_values: usize,
    pub samples: usize,
    pub value_bytes: usize,
    /// Maximum validated input; larger retained values are counted as oversize losses.
    pub input_bytes: usize,
    /// Retained canonical payload bytes; entry counts bound collection overhead separately.
    pub retained_bytes: usize,
}

impl Default for ProfileBucketLimits {
    fn default() -> Self {
        Self {
            literal_values: 16,
            samples: 256,
            value_bytes: kib(16),
            input_bytes: kib(64),
            retained_bytes: mib(8),
        }
    }
}

impl ProfileBucketLimits {
    pub fn validate(self) -> Result<(), ProfileDataError> {
        if self.input_bytes < self.value_bytes {
            return Err(ProfileDataError::Invalid(
                "bucket input and retained value limits",
            ));
        }
        self.literal_values
            .checked_add(self.samples)
            .ok_or(ProfileDataError::LimitExceeded("interned value count"))?;
        Ok(())
    }
}

/// Values are sorted by content ID, referenced by counters and complete samples.
/// No database surrogate or raw observation row is required to decode this snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountedBucketSnapshot {
    pub format_version: u16,
    pub domain: CanonicalDomain,
    pub scope: ValueId,
    pub counts: CounterSnapshot,
    pub samples: Box<[ReservoirEntry]>,
    pub values: Box<[CanonicalValue]>,
}

#[derive(Debug, Clone)]
pub struct CountedObservationBucket {
    domain: CanonicalDomain,
    scope: ValueId,
    seed: [u8; 32],
    limits: ProfileBucketLimits,
    counts: LiteralCounters,
    samples: ObservationReservoir,
    values: BTreeMap<ValueId, Arc<CanonicalValue>>,
    retained_bytes: usize,
}

fn references(counts: &LiteralCounters, samples: &ObservationReservoir) -> BTreeSet<ValueId> {
    counts
        .value_ids()
        .chain(samples.entries().iter().map(|entry| entry.value))
        .collect()
}

impl CountedObservationBucket {
    pub fn new(
        domain: CanonicalDomain,
        scope: ValueId,
        seed: [u8; 32],
        limits: ProfileBucketLimits,
    ) -> Result<Self, ProfileDataError> {
        limits.validate()?;
        Ok(Self {
            domain,
            scope,
            seed,
            limits,
            counts: if domain == CanonicalDomain::LegacyField {
                LiteralCounters::unknown_history(limits.literal_values)
            } else {
                LiteralCounters::new(limits.literal_values)
            },
            samples: ObservationReservoir::new(limits.samples, seed, scope),
            values: BTreeMap::new(),
            retained_bytes: 0,
        })
    }

    /// The enclosing transaction first admits the observation ID once for all its slots.
    /// Invalid input and overflow leave every field unchanged; retention losses still count.
    pub fn observe(
        &mut self,
        observation: ObservationId,
        value: &CanonicalValue,
    ) -> Result<(), ProfileDataError> {
        self.observe_with_retained_limit(observation, value, self.limits.retained_bytes)
    }

    pub(in crate::profile) fn observe_with_retained_limit(
        &mut self,
        observation: ObservationId,
        value: &CanonicalValue,
        maximum_retained_bytes: usize,
    ) -> Result<(), ProfileDataError> {
        value.validate_content(self.domain, self.limits.input_bytes)?;
        if observation.sequence == 0 {
            return Err(ProfileDataError::Invalid("zero ingestion sequence"));
        }
        let budget = self.limits.retained_bytes.min(maximum_retained_bytes);
        if self.retained_bytes > budget {
            return Err(ProfileDataError::LimitExceeded(
                "existing retained canonical bytes",
            ));
        }
        if value.bytes.len() > self.limits.value_bytes {
            return self
                .counts
                .observe_unretained(value.id, ObservationLoss::Oversize);
        }
        if let Some(previous) = self.values.get(&value.id)
            && previous.bytes != value.bytes
        {
            return Err(ProfileDataError::Invalid("canonical hash collision"));
        }
        let mut counts = self.counts.clone();
        let mut samples = self.samples.clone();
        counts.observe(value.id)?;
        samples.observe(observation, value.id)?;
        let retained = references(&counts, &samples);
        let mut remaining = budget;
        for id in &retained {
            let bytes = if *id == value.id {
                value.bytes.len()
            } else {
                self.values
                    .get(id)
                    .ok_or(ProfileDataError::Invalid("missing interned value"))?
                    .bytes
                    .len()
            };
            let Some(next) = remaining.checked_sub(bytes) else {
                return self
                    .counts
                    .observe_unretained(value.id, ObservationLoss::Retention);
            };
            remaining = next;
        }
        let added = if retained.contains(&value.id) && !self.values.contains_key(&value.id) {
            Some(Arc::new(value.clone()))
        } else {
            None
        };
        self.values.retain(|id, _value| retained.contains(id));
        if let Some(value) = added {
            self.values.insert(value.id, value);
        }
        self.counts = counts;
        self.samples = samples;
        self.retained_bytes = budget - remaining;
        Ok(())
    }

    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    #[must_use]
    pub fn counts(&self) -> &LiteralCounters {
        &self.counts
    }

    #[must_use]
    pub fn snapshot(&self) -> CountedBucketSnapshot {
        CountedBucketSnapshot {
            format_version: 1,
            domain: self.domain,
            scope: self.scope,
            counts: self.counts.snapshot(),
            samples: self.samples.entries().into(),
            values: self
                .values
                .values()
                .map(|value| value.as_ref().clone())
                .collect(),
        }
    }

    /// Validate a bounded dictionary and all its references before copying payloads.
    pub fn from_snapshot(
        snapshot: &CountedBucketSnapshot,
        expected_domain: CanonicalDomain,
        expected_scope: ValueId,
        seed: [u8; 32],
        limits: ProfileBucketLimits,
    ) -> Result<Self, ProfileDataError> {
        limits.validate()?;
        if snapshot.domain != expected_domain || snapshot.scope != expected_scope {
            return Err(ProfileDataError::Invalid(
                "restored profile domain or scope",
            ));
        }
        if snapshot.format_version != 1 {
            return Err(ProfileDataError::Unsupported(
                "counting bucket format version",
            ));
        }
        let maximum_values = limits
            .literal_values
            .checked_add(limits.samples)
            .ok_or(ProfileDataError::LimitExceeded("interned value count"))?;
        if snapshot.values.len() > maximum_values {
            return Err(ProfileDataError::LimitExceeded("interned value count"));
        }
        if expected_domain == CanonicalDomain::LegacyField
            && (snapshot.counts.losses.history_known
                || snapshot.counts.untracked_distinct.history_known)
        {
            return Err(ProfileDataError::Invalid("legacy historical counts"));
        }
        let counts = LiteralCounters::from_snapshot(&snapshot.counts, limits.literal_values)?;
        let samples = ObservationReservoir::from_entries(
            limits.samples,
            seed,
            snapshot.scope,
            &snapshot.samples,
        )?;
        let eligible = snapshot
            .counts
            .total
            .checked_sub(snapshot.counts.losses.oversize)
            .and_then(|total| total.checked_sub(snapshot.counts.losses.retention))
            .ok_or(ProfileDataError::Invalid("sample loss accounting"))?;
        let expected = eligible.min(limits.samples as u64);
        if snapshot.samples.len() as u64 > expected
            || (snapshot.counts.losses.history_known && snapshot.samples.len() as u64 != expected)
        {
            return Err(ProfileDataError::Invalid(
                "sample count does not match eligible observations",
            ));
        }
        let retained = references(&counts, &samples);
        if retained.len() != snapshot.values.len() {
            return Err(ProfileDataError::Invalid("interned value coverage"));
        }
        let mut remaining = limits.retained_bytes;
        let mut previous = None;
        for value in &snapshot.values {
            if !retained.contains(&value.id) || previous.is_some_and(|id| id >= value.id) {
                return Err(ProfileDataError::Invalid(
                    "interned value ordering or reference",
                ));
            }
            remaining = remaining
                .checked_sub(value.bytes.len())
                .ok_or(ProfileDataError::LimitExceeded("retained canonical bytes"))?;
            value.validate_content(snapshot.domain, limits.value_bytes)?;
            previous = Some(value.id);
        }
        Ok(Self {
            domain: snapshot.domain,
            scope: snapshot.scope,
            seed,
            limits,
            counts,
            samples,
            retained_bytes: limits.retained_bytes - remaining,
            values: snapshot
                .values
                .iter()
                .map(|value| (value.id, Arc::new(value.clone())))
                .collect(),
        })
    }

    /// Merge disjoint observations under the same retention budget.
    pub fn merge(&self, other: &Self) -> Result<Self, ProfileDataError> {
        if self.limits != other.limits {
            return Err(ProfileDataError::Invalid("incompatible counting buckets"));
        }
        self.combine(other, self.limits, self.counts.merge(&other.counts)?)
    }

    /// Re-draw samples under another scope identity, keeping counts and values.
    pub(in crate::profile) fn rescoped(&self, scope: ValueId) -> Result<Self, ProfileDataError> {
        let samples = self.samples.rescoped(scope)?;
        let retained = references(&self.counts, &samples);
        let values: BTreeMap<_, _> = self
            .values
            .iter()
            .filter(|(id, _value)| retained.contains(id))
            .map(|(id, value)| (*id, value.clone()))
            .collect();
        Ok(Self {
            domain: self.domain,
            scope,
            seed: self.seed,
            limits: self.limits,
            counts: self.counts.clone(),
            samples,
            retained_bytes: values.values().map(|value| value.bytes.len()).sum(),
            values,
        })
    }

    /// Merge disjoint observations of stored scopes that normalize to one scope.
    /// Each budget is the larger of both, so many small scopes cannot grow it.
    pub(in crate::profile) fn merge_scope(&self, other: &Self) -> Result<Self, ProfileDataError> {
        let limits = ProfileBucketLimits {
            literal_values: self.limits.literal_values.max(other.limits.literal_values),
            retained_bytes: self.limits.retained_bytes.max(other.limits.retained_bytes),
            ..self.limits
        };
        let counts = self
            .counts
            .merge_with_capacity(&other.counts, limits.literal_values)?;
        self.combine(other, limits, counts)
    }

    /// Drop the lowest-priority samples until retained values fit `maximum` bytes; counts stay exact.
    pub(in crate::profile) fn trim_samples(
        &self,
        maximum: usize,
    ) -> Result<Self, ProfileDataError> {
        let size = |id: &ValueId| {
            self.values
                .get(id)
                .map(|value| value.bytes.len())
                .ok_or(ProfileDataError::Invalid("missing interned value"))
        };
        let mut kept: BTreeSet<ValueId> = self.counts.value_ids().collect();
        let mut used = 0_usize;
        for id in &kept {
            used += size(id)?;
        }
        let mut length = 0;
        for entry in self.samples.entries() {
            if !kept.contains(&entry.value) {
                let bytes = size(&entry.value)?;
                if used + bytes > maximum {
                    break;
                }
                used += bytes;
                kept.insert(entry.value);
            }
            length += 1;
        }
        let mut samples = self.samples.clone();
        samples.truncate(length);
        Ok(Self {
            domain: self.domain,
            scope: self.scope,
            seed: self.seed,
            limits: self.limits,
            counts: self.counts.clone(),
            samples,
            values: self
                .values
                .iter()
                .filter(|(id, _value)| kept.contains(id))
                .map(|(id, value)| (*id, value.clone()))
                .collect(),
            retained_bytes: used,
        })
    }

    /// Sum exact retained counts from disjoint days, without reducing their union.
    pub fn coarsen(&self, other: &Self) -> Result<Self, ProfileDataError> {
        let limits = ProfileBucketLimits {
            literal_values: self
                .limits
                .literal_values
                .checked_add(other.limits.literal_values)
                .ok_or(ProfileDataError::LimitExceeded(
                    "coarsened literal capacity",
                ))?,
            retained_bytes: self
                .limits
                .retained_bytes
                .checked_add(other.limits.retained_bytes)
                .ok_or(ProfileDataError::LimitExceeded("coarsened retained bytes"))?,
            ..self.limits
        };
        self.combine(other, limits, self.counts.coarsen(&other.counts)?)
    }

    fn combine(
        &self,
        other: &Self,
        limits: ProfileBucketLimits,
        counts: LiteralCounters,
    ) -> Result<Self, ProfileDataError> {
        if self.domain != other.domain
            || self.scope != other.scope
            || self.seed != other.seed
            || self.limits.samples != other.limits.samples
            || self.limits.value_bytes != other.limits.value_bytes
            || self.limits.input_bytes != other.limits.input_bytes
        {
            return Err(ProfileDataError::Invalid("incompatible counting buckets"));
        }
        for (id, value) in &self.values {
            if let Some(other) = other.values.get(id)
                && value.bytes != other.bytes
            {
                return Err(ProfileDataError::Invalid("canonical hash collision"));
            }
        }
        let samples = self.samples.merge(&other.samples)?;
        let retained = references(&counts, &samples);
        let mut remaining = limits.retained_bytes;
        for id in &retained {
            let value = self
                .values
                .get(id)
                .or_else(|| other.values.get(id))
                .ok_or(ProfileDataError::Invalid("missing interned value"))?;
            remaining = remaining
                .checked_sub(value.bytes.len())
                .ok_or(ProfileDataError::LimitExceeded("retained canonical bytes"))?;
        }
        let values = retained
            .into_iter()
            .map(|id| {
                // Both maps are immutable and the preceding pass validated every reference.
                let value = self
                    .values
                    .get(&id)
                    .or_else(|| other.values.get(&id))
                    .ok_or(ProfileDataError::Invalid("missing interned value"))?;
                Ok((id, value.clone()))
            })
            .collect::<Result<_, ProfileDataError>>()?;
        Ok(Self {
            domain: self.domain,
            scope: self.scope,
            seed: self.seed,
            limits,
            counts,
            samples,
            values,
            retained_bytes: limits.retained_bytes - remaining,
        })
    }
}

#[cfg(test)]
mod tests;
