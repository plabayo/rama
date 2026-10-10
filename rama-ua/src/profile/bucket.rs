//! A bounded counting bucket with one copy of each retained canonical value.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use rama_utils::octets::{kib, mib};
use serde::{Deserialize, Serialize};

use super::{
    CanonicalDomain, CanonicalValue, CounterSnapshot, LiteralCounters, ObservationId,
    ObservationLoss, ObservationReservoir, ProfileDataError, ReservoirEntry, ValueId,
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
            counts: LiteralCounters::new(limits.literal_values),
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

    pub(super) fn observe_with_retained_limit(
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
        self.combine(other, self.limits, false)
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
        self.combine(other, limits, true)
    }

    fn combine(
        &self,
        other: &Self,
        limits: ProfileBucketLimits,
        coarsen: bool,
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
        let counts = if coarsen {
            self.counts.coarsen(&other.counts)?
        } else {
            self.counts.merge(&other.counts)?
        };
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
mod tests {
    use crate::profile::ProfileCaptureCompleteness;
    use rama_http::{HeaderMap, HeaderValue, Version};

    use super::*;
    use crate::profile::{
        ConnectionContext, HeaderCapturePolicy, LiteralCount, ObservationLosses, ObservationWeight,
        ProfileObservationScope, canonical::CanonicalWriter,
    };

    fn canonical(value: u64) -> CanonicalValue {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-value",
            HeaderValue::from_str(&value.to_string()).unwrap(),
        );
        let policy = HeaderCapturePolicy::default();
        policy
            .capture(
                ProfileCaptureCompleteness::Complete,
                Version::HTTP_11,
                &headers,
                None,
            )
            .unwrap()
            .canonical(&policy)
            .unwrap()
    }
    fn observation(sequence: u64) -> ObservationId {
        ObservationId {
            run: [1; 16],
            sequence,
        }
    }
    fn encoded(bucket: &CountedObservationBucket) -> Vec<u8> {
        serde_json::to_vec(&bucket.snapshot()).unwrap()
    }

    #[test]
    fn counting_bucket_bounds_random_values_and_reclaims_evictions() {
        let limits = ProfileBucketLimits {
            literal_values: 4,
            samples: 16,
            ..ProfileBucketLimits::default()
        };
        let mut bucket = CountedObservationBucket::new(
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            limits,
        )
        .unwrap();
        for sequence in 1..=10_000 {
            bucket
                .observe(observation(sequence), &canonical(sequence))
                .unwrap();
        }
        let snapshot = bucket.snapshot();
        assert_eq!(snapshot.counts.total, 10_000);
        assert_eq!(snapshot.counts.values.len(), 4);
        assert_eq!(snapshot.counts.untracked, 9996);
        assert_eq!(snapshot.samples.len(), 16);
        assert!(snapshot.values.len() <= 20);
        let ids = references(&bucket.counts, &bucket.samples);
        assert_eq!(ids.len(), snapshot.values.len());
        let restored = CountedObservationBucket::from_snapshot(
            &snapshot,
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            limits,
        )
        .unwrap();
        assert_eq!(encoded(&bucket), encoded(&restored));
    }

    #[test]
    fn counting_bucket_failure_does_not_update_counts_samples_or_dictionary() {
        let value = canonical(1);
        let limits = ProfileBucketLimits {
            retained_bytes: value.bytes.len(),
            ..ProfileBucketLimits::default()
        };
        let mut bucket = CountedObservationBucket::new(
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            limits,
        )
        .unwrap();
        bucket.observe(observation(1), &value).unwrap();
        let before = encoded(&bucket);

        bucket.observe(observation(0), &value).unwrap_err();
        let mut corrupt = value.clone();
        corrupt.id.0[0] ^= 1;
        bucket.observe(observation(2), &corrupt).unwrap_err();
        assert_eq!(before, encoded(&bucket));
        bucket.observe(observation(2), &value).unwrap();
        assert_eq!(bucket.snapshot().values.len(), 1);
        assert!(matches!(
            bucket.counts().weight(value.id),
            ObservationWeight::Exact(2)
        ));
        let mut snapshot = bucket.snapshot();
        snapshot.values[0].bytes[0] ^= 1;
        CountedObservationBucket::from_snapshot(
            &snapshot,
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            limits,
        )
        .unwrap_err();
        let mut snapshot = bucket.snapshot();
        snapshot.values = Box::default();
        CountedObservationBucket::from_snapshot(
            &snapshot,
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            limits,
        )
        .unwrap_err();
        let mut snapshot = bucket.snapshot();
        snapshot.format_version = 2;
        CountedObservationBucket::from_snapshot(
            &snapshot,
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            limits,
        )
        .unwrap_err();
        snapshot.format_version = 1;
        snapshot.domain = CanonicalDomain::Profile;
        CountedObservationBucket::from_snapshot(
            &snapshot,
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            limits,
        )
        .unwrap_err();
    }

    #[test]
    fn counting_bucket_merge_reuses_values_and_keeps_joint_sample_identity() {
        let limits = ProfileBucketLimits {
            literal_values: 2,
            samples: 16,
            ..ProfileBucketLimits::default()
        };
        let mut left = CountedObservationBucket::new(
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            limits,
        )
        .unwrap();
        let mut right = left.clone();
        let a = canonical(1);
        let b = canonical(2);
        for sequence in 1..=1000 {
            if sequence % 2 == 0 {
                left.observe(observation(sequence), &a).unwrap();
            } else {
                right.observe(observation(sequence), &b).unwrap();
            }
        }
        let merged = left.merge(&right).unwrap();
        assert_eq!(encoded(&merged), encoded(&right.merge(&left).unwrap()));
        assert_eq!(merged.snapshot().values.len(), 2);
        assert!(matches!(
            merged.counts().weight(a.id),
            ObservationWeight::Exact(500)
        ));
        assert!(matches!(
            merged.counts().weight(b.id),
            ObservationWeight::Exact(500)
        ));
        for sample in merged.samples.entries() {
            assert_eq!(
                sample.value,
                if sample.observation.sequence % 2 == 0 {
                    a.id
                } else {
                    b.id
                }
            );
        }
    }
    #[test]
    fn valid_digest_cannot_smuggle_request_values_into_retained_storage() {
        let limits = ProfileBucketLimits::default();
        let scope = ValueId([2; 32]);
        let mut writer =
            CanonicalWriter::new(CanonicalDomain::Headers, limits.value_bytes).unwrap();
        writer.u8(2).unwrap();
        writer.u8(1).unwrap();
        writer.u64(1).unwrap();
        writer.bytes(b"cookie").unwrap();
        writer.u32(0).unwrap();
        writer.u8(0).unwrap();
        writer.u8(0).unwrap();
        writer.u8(0).unwrap();
        writer.bytes(b"request-value-canary").unwrap();
        let forged = writer.finish();
        forged
            .verify(CanonicalDomain::Headers, limits.value_bytes)
            .unwrap();
        let mut bucket =
            CountedObservationBucket::new(CanonicalDomain::Headers, scope, [3; 32], limits)
                .unwrap();
        bucket.observe(observation(1), &forged).unwrap_err();
        assert_eq!(bucket.snapshot().counts.total, 0);
        assert_eq!(bucket.retained_bytes(), 0);
        let snapshot = CountedBucketSnapshot {
            format_version: 1,
            domain: CanonicalDomain::Headers,
            scope,
            counts: CounterSnapshot {
                untracked_distinct: Default::default(),
                losses: ObservationLosses {
                    history_known: true,
                    ..ObservationLosses::default()
                },
                total: 1,
                untracked: 0,
                values: vec![LiteralCount {
                    value: forged.id,
                    count: 1,
                }]
                .into(),
            },
            samples: Box::default(),
            values: vec![forged].into(),
        };
        CountedObservationBucket::from_snapshot(
            &snapshot,
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            limits,
        )
        .unwrap_err();
        CanonicalDomain::try_from(u16::MAX).unwrap_err();
        let mut unknown = CanonicalWriter::new(CanonicalDomain::Headers, limits.value_bytes)
            .unwrap()
            .finish();
        unknown.bytes[15..17].copy_from_slice(&u16::MAX.to_be_bytes());
        unknown.validated_domain(limits.value_bytes).unwrap_err();
    }
    #[test]
    fn valid_oversize_values_count_without_retention_or_secret_bypass() {
        let limits = ProfileBucketLimits::default();
        let policy = HeaderCapturePolicy::default();
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            HeaderValue::from_bytes(&vec![b'a'; kib(20)]).unwrap(),
        );
        let large = policy
            .capture(
                ProfileCaptureCompleteness::Complete,
                Version::HTTP_11,
                &headers,
                None,
            )
            .unwrap()
            .canonical(&policy)
            .unwrap();
        assert!(large.bytes.len() > limits.value_bytes && large.bytes.len() <= limits.input_bytes);
        let mut bucket = CountedObservationBucket::new(
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            limits,
        )
        .unwrap();
        bucket.observe(observation(1), &large).unwrap();
        let snapshot = bucket.snapshot();
        assert_eq!(snapshot.counts.total, 1);
        assert_eq!(snapshot.counts.untracked, 1);
        assert_eq!(snapshot.counts.losses.oversize, 1);
        assert!(snapshot.samples.is_empty() && snapshot.values.is_empty());
        assert_eq!(bucket.retained_bytes(), 0);
        CountedObservationBucket::from_snapshot(
            &snapshot,
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            limits,
        )
        .unwrap();
        let before = encoded(&bucket);
        let mut writer =
            CanonicalWriter::new(CanonicalDomain::Headers, limits.input_bytes).unwrap();
        writer.u8(2).unwrap();
        writer.u8(1).unwrap();
        writer.u64(1).unwrap();
        writer.bytes(b"cookie").unwrap();
        writer.u32(0).unwrap();
        writer.u8(0).unwrap();
        writer.u8(0).unwrap();
        writer.u8(0).unwrap();
        writer.bytes(&vec![b's'; kib(20)]).unwrap();
        let secret = writer.finish();
        secret
            .verify(CanonicalDomain::Headers, limits.input_bytes)
            .unwrap();
        bucket.observe(observation(2), &secret).unwrap_err();
        bucket.observe(observation(0), &large).unwrap_err();
        let mut forged = large;
        forged.id.0[0] ^= 1;
        bucket.observe(observation(2), &forged).unwrap_err();
        assert_eq!(before, encoded(&bucket));
        let invalid = ProfileBucketLimits {
            input_bytes: 1,
            ..limits
        };
        invalid.validate().unwrap_err();
        CountedObservationBucket::new(CanonicalDomain::Headers, ValueId([2; 32]), [3; 32], invalid)
            .unwrap_err();
    }

    #[test]
    fn retention_losses_preserve_payloads_and_restore_requires_full_eligible_samples() {
        let a = canonical(1);
        let limits = ProfileBucketLimits {
            retained_bytes: a.bytes.len(),
            ..ProfileBucketLimits::default()
        };
        let mut bucket = CountedObservationBucket::new(
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            limits,
        )
        .unwrap();
        bucket.observe(observation(1), &a).unwrap();
        bucket.observe(observation(2), &canonical(2)).unwrap();
        let snapshot = bucket.snapshot();
        assert_eq!(snapshot.counts.total, 2);
        assert_eq!(snapshot.counts.untracked, 1);
        assert_eq!(snapshot.counts.losses.retention, 1);
        assert_eq!(snapshot.samples.len(), 1);
        assert_eq!(snapshot.values.len(), 1);
        assert_eq!(snapshot.values[0].id, a.id);
        let mut restored = CountedObservationBucket::from_snapshot(
            &snapshot,
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            limits,
        )
        .unwrap();
        restored.observe(observation(3), &a).unwrap();
        assert_eq!(restored.snapshot().counts.total, 3);
        assert_eq!(restored.snapshot().samples.len(), 2);
        let mut incomplete = snapshot;
        incomplete.samples = Box::default();
        CountedObservationBucket::from_snapshot(
            &incomplete,
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            limits,
        )
        .unwrap_err();
        incomplete.counts.losses.history_known = false;
        let imported = CountedObservationBucket::from_snapshot(
            &incomplete,
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            limits,
        )
        .unwrap();
        assert!(matches!(
            imported.counts().weight(a.id),
            ObservationWeight::UnknownHistory { .. }
        ));
    }
    #[test]
    fn restored_bucket_requires_the_expected_domain_and_authorization_scope() {
        let limits = ProfileBucketLimits::default();
        let mut scope = ProfileObservationScope {
            authorized: false,
            profile: ValueId([1; 32]),
            flow: None,
            connection: ConnectionContext::default(),
            structure: ValueId([2; 32]),
        };
        let public = scope.canonical(limits.input_bytes).unwrap().id;
        scope.authorized = true;
        let authorized = scope.canonical(limits.input_bytes).unwrap().id;
        assert_ne!(public, authorized);
        let mut bucket =
            CountedObservationBucket::new(CanonicalDomain::Headers, public, [3; 32], limits)
                .unwrap();
        bucket.observe(observation(1), &canonical(1)).unwrap();
        let snapshot = bucket.snapshot();
        CountedObservationBucket::from_snapshot(
            &snapshot,
            CanonicalDomain::Headers,
            authorized,
            [3; 32],
            limits,
        )
        .unwrap_err();
        CountedObservationBucket::from_snapshot(
            &snapshot,
            CanonicalDomain::Order,
            public,
            [3; 32],
            limits,
        )
        .unwrap_err();
        let restored = CountedObservationBucket::from_snapshot(
            &snapshot,
            CanonicalDomain::Headers,
            public,
            [3; 32],
            limits,
        )
        .unwrap();
        assert_eq!(encoded(&restored), encoded(&bucket));
    }
}
