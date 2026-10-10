//! Freshness applies to counts and samples, with bounded retained UTC day buckets.

use std::collections::BTreeMap;

use rama_utils::octets::mib;
use serde::{Deserialize, Serialize};

use super::{
    CanonicalDomain, CanonicalValue, CountedBucketSnapshot, CountedObservationBucket,
    ObservationId, ProfileBucketLimits, ProfileDataError, RetentionWindow, ValueId,
};

#[derive(Debug, Clone, Copy)]
pub struct ProfileWindowLimits {
    pub retention: RetentionWindow,
    pub bucket: ProfileBucketLimits,
    pub retained_bytes: usize,
}

impl Default for ProfileWindowLimits {
    fn default() -> Self {
        Self {
            retention: RetentionWindow::default(),
            bucket: ProfileBucketLimits::default(),
            retained_bytes: mib(32),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DayBucketSnapshot {
    pub day: u32,
    pub bucket: CountedBucketSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetainedBucketsSnapshot {
    pub format_version: u16,
    pub domain: CanonicalDomain,
    pub scope: ValueId,
    pub last_day: u32,
    pub buckets: Box<[DayBucketSnapshot]>,
}

/// One authorization/profile/flow/structural scope, with no duplicate day coverage.
#[derive(Debug, Clone)]
pub struct RetainedBucketWindow {
    domain: CanonicalDomain,
    scope: ValueId,
    seed: [u8; 32],
    limits: ProfileWindowLimits,
    last_day: u32,
    buckets: BTreeMap<u32, CountedObservationBucket>,
}

impl RetainedBucketWindow {
    pub fn new(
        domain: CanonicalDomain,
        scope: ValueId,
        seed: [u8; 32],
        limits: ProfileWindowLimits,
    ) -> Result<Self, ProfileDataError> {
        limits.bucket.validate()?;
        limits.retention.first_day(0, limits.retention.days)?;
        Ok(Self {
            domain,
            scope,
            seed,
            limits,
            last_day: 0,
            buckets: BTreeMap::new(),
        })
    }

    fn validate_clock(&self, current_day: u32) -> Result<(), ProfileDataError> {
        if current_day < self.last_day {
            return Err(ProfileDataError::Unsupported(
                "time predates retained window watermark",
            ));
        }
        Ok(())
    }

    /// The enclosing transaction must admit this observation ID exactly once.
    /// Day and byte-budget checks complete before counts or retention change.
    pub fn observe(
        &mut self,
        current_day: u32,
        observation_day: u32,
        observation: ObservationId,
        value: &CanonicalValue,
    ) -> Result<(), ProfileDataError> {
        self.validate_clock(current_day)?;
        self.limits
            .retention
            .validate_observation(current_day, observation_day)?;
        let first = self
            .limits
            .retention
            .first_day(current_day, self.limits.retention.days)?;
        let mut remaining = self.limits.retained_bytes;
        for (&day, previous) in self.buckets.range(first..) {
            if day != observation_day {
                remaining = remaining
                    .checked_sub(previous.retained_bytes())
                    .ok_or(ProfileDataError::LimitExceeded("retained window bytes"))?;
            }
        }
        let mut bucket = match self.buckets.get(&observation_day) {
            Some(bucket) => bucket.clone(),
            None => CountedObservationBucket::new(
                self.domain,
                self.scope,
                self.seed,
                self.limits.bucket,
            )?,
        };
        bucket.observe_with_retained_limit(observation, value, remaining)?;
        self.buckets.retain(|day, _bucket| *day >= first);
        self.buckets.insert(observation_day, bucket);
        self.last_day = current_day;
        Ok(())
    }

    /// Remove expired state even when no new observations arrive.
    pub fn advance(&mut self, current_day: u32) -> Result<(), ProfileDataError> {
        self.validate_clock(current_day)?;
        let first = self
            .limits
            .retention
            .first_day(current_day, self.limits.retention.days)?;
        self.buckets.retain(|day, _bucket| *day >= first);
        self.last_day = current_day;
        Ok(())
    }

    /// The current partial UTC day counts toward the requested horizon.
    /// Expired counts and samples cannot influence the result.
    pub fn select(
        &self,
        current_day: u32,
        horizon: u32,
    ) -> Result<CountedObservationBucket, ProfileDataError> {
        self.validate_clock(current_day)?;
        let first = self.limits.retention.first_day(current_day, horizon)?;
        let mut selected: Option<CountedObservationBucket> = None;
        for (_day, bucket) in self.buckets.range(first..=current_day) {
            selected = Some(match selected {
                Some(previous) => previous.coarsen(bucket)?,
                None => bucket.clone(),
            });
        }
        match selected {
            Some(bucket) => Ok(bucket),
            None => CountedObservationBucket::new(
                self.domain,
                self.scope,
                self.seed,
                self.limits.bucket,
            ),
        }
    }

    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        // Every mutation checked the combined byte budget before publishing the state.
        self.buckets
            .values()
            .map(CountedObservationBucket::retained_bytes)
            .sum()
    }

    #[must_use]
    pub fn snapshot(&self) -> RetainedBucketsSnapshot {
        RetainedBucketsSnapshot {
            format_version: 1,
            domain: self.domain,
            scope: self.scope,
            last_day: self.last_day,
            buckets: self
                .buckets
                .iter()
                .map(|(&day, bucket)| DayBucketSnapshot {
                    day,
                    bucket: bucket.snapshot(),
                })
                .collect(),
        }
    }

    pub fn from_snapshot(
        snapshot: &RetainedBucketsSnapshot,
        expected_domain: CanonicalDomain,
        expected_scope: ValueId,
        seed: [u8; 32],
        limits: ProfileWindowLimits,
    ) -> Result<Self, ProfileDataError> {
        if snapshot.domain != expected_domain || snapshot.scope != expected_scope {
            return Err(ProfileDataError::Invalid(
                "restored profile domain or scope",
            ));
        }
        if snapshot.format_version != 1 {
            return Err(ProfileDataError::Unsupported(
                "retained window format version",
            ));
        }
        if snapshot.buckets.len() as u64 > u64::from(limits.retention.days) {
            return Err(ProfileDataError::LimitExceeded("retained days"));
        }
        let mut window = Self::new(snapshot.domain, snapshot.scope, seed, limits)?;
        let maximum_values = limits
            .bucket
            .literal_values
            .checked_add(limits.bucket.samples)
            .ok_or(ProfileDataError::LimitExceeded("interned value count"))?;
        let mut previous = None;
        let mut remaining = limits.retained_bytes;
        for day in &snapshot.buckets {
            limits
                .retention
                .validate_observation(snapshot.last_day, day.day)?;
            if previous.is_some_and(|value| value >= day.day)
                || day.bucket.domain != snapshot.domain
                || day.bucket.scope != snapshot.scope
            {
                return Err(ProfileDataError::Invalid("retained day ordering or scope"));
            }
            if day.bucket.values.len() > maximum_values {
                return Err(ProfileDataError::LimitExceeded("interned value count"));
            }
            for value in &day.bucket.values {
                remaining = remaining
                    .checked_sub(value.bytes.len())
                    .ok_or(ProfileDataError::LimitExceeded("retained window bytes"))?;
            }
            let bucket = CountedObservationBucket::from_snapshot(
                &day.bucket,
                expected_domain,
                expected_scope,
                seed,
                limits.bucket,
            )?;
            window.buckets.insert(day.day, bucket);
            previous = Some(day.day);
        }
        window.last_day = snapshot.last_day;
        Ok(window)
    }
}

#[cfg(test)]
mod tests {
    use rama_http::{HeaderMap, HeaderValue, Version};
    use rama_utils::octets::kib;

    use super::*;
    use crate::profile::{HeaderCapturePolicy, ObservationWeight};

    fn value(value: &'static str) -> CanonicalValue {
        let mut headers = HeaderMap::new();
        headers.insert("x-mode", HeaderValue::from_static(value));
        let policy = HeaderCapturePolicy::default();
        policy
            .capture(Version::HTTP_11, &headers, None)
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
    fn encoded(window: &RetainedBucketWindow) -> Vec<u8> {
        serde_json::to_vec(&window.snapshot()).unwrap()
    }

    #[test]
    fn fourteen_day_window_expires_weights_and_samples_together() {
        let limits = ProfileWindowLimits::default();
        let mut window =
            RetainedBucketWindow::new(CanonicalDomain::Headers, ValueId([2; 32]), [3; 32], limits)
                .unwrap();
        let a = value("A");
        let b = value("B");
        for sequence in 1..=1000 {
            window.observe(100, 100, observation(sequence), &a).unwrap();
        }
        for day in 101..=113 {
            window
                .observe(day, day, observation(1000 + u64::from(day)), &b)
                .unwrap();
        }
        let selected = window.select(113, 14).unwrap();
        assert!(matches!(
            selected.counts().weight(a.id),
            ObservationWeight::Exact(1000)
        ));
        assert!(matches!(
            selected.counts().weight(b.id),
            ObservationWeight::Exact(13)
        ));
        let selected = window.select(114, 14).unwrap();
        assert!(matches!(
            selected.counts().weight(a.id),
            ObservationWeight::Exact(0)
        ));
        assert!(matches!(
            selected.counts().weight(b.id),
            ObservationWeight::Exact(13)
        ));
        for sample in selected.snapshot().samples {
            assert_eq!(sample.value, b.id);
        }
        let restored = RetainedBucketWindow::from_snapshot(
            &window.snapshot(),
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            limits,
        )
        .unwrap();
        assert_eq!(encoded(&window), encoded(&restored));
        window.advance(114).unwrap();
        assert_eq!(window.snapshot().buckets.len(), 13);
        window.observe(114, 100, observation(2000), &a).unwrap_err();
        window.select(113, 14).unwrap_err();
        window.select(114, 15).unwrap_err();
        window.advance(127).unwrap();
        assert!(window.snapshot().buckets.is_empty());
        assert_eq!(window.retained_bytes(), 0);
    }

    #[test]
    fn selection_preserves_exact_literals_across_disjoint_days() {
        let limits = ProfileWindowLimits {
            bucket: ProfileBucketLimits {
                literal_values: 1,
                samples: 0,
                ..ProfileBucketLimits::default()
            },
            ..ProfileWindowLimits::default()
        };
        let mut window =
            RetainedBucketWindow::new(CanonicalDomain::Headers, ValueId([2; 32]), [3; 32], limits)
                .unwrap();
        let (mut a, mut b) = (value("A"), value("B"));
        if a.id < b.id {
            std::mem::swap(&mut a, &mut b);
        }
        for sequence in 1..=1000 {
            window.observe(100, 100, observation(sequence), &a).unwrap();
        }
        window.observe(101, 101, observation(1001), &b).unwrap();
        let selected = window.select(101, 14).unwrap();
        assert!(matches!(
            selected.counts().weight(a.id),
            ObservationWeight::Exact(1000)
        ));
        assert!(matches!(
            selected.counts().weight(b.id),
            ObservationWeight::Exact(1)
        ));
        assert_eq!(selected.snapshot().counts.untracked, 0);
        let mut all = CountedObservationBucket::new(
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            ProfileBucketLimits {
                literal_values: 2,
                ..limits.bucket
            },
        )
        .unwrap();
        for sequence in 1..=1000 {
            all.observe(observation(sequence), &a).unwrap();
        }
        all.observe(observation(1001), &b).unwrap();
        assert_eq!(
            serde_json::to_vec(&selected.snapshot()).unwrap(),
            serde_json::to_vec(&all.snapshot()).unwrap()
        );
    }

    #[test]
    fn window_byte_limit_counts_losses_and_expiration_frees_capacity() {
        let a = value("A");
        let limits = ProfileWindowLimits {
            retained_bytes: a.bytes.len(),
            ..ProfileWindowLimits::default()
        };
        let mut window =
            RetainedBucketWindow::new(CanonicalDomain::Headers, ValueId([2; 32]), [3; 32], limits)
                .unwrap();
        window.observe(100, 100, observation(1), &a).unwrap();
        window.observe(101, 101, observation(2), &a).unwrap();
        let counts = window.select(101, 14).unwrap().snapshot().counts;
        assert_eq!(counts.total, 2);
        assert_eq!(counts.untracked, 1);
        assert_eq!(counts.losses.retention, 1);
        assert_eq!(window.retained_bytes(), a.bytes.len());
        window.observe(114, 114, observation(3), &a).unwrap();
        assert_eq!(window.snapshot().buckets.len(), 2);
        let retained = window.select(114, 14).unwrap().snapshot();
        assert_eq!(retained.counts.total, 2);
        assert_eq!(retained.counts.losses.retention, 1);
        window.advance(115).unwrap();
        assert_eq!(window.snapshot().buckets.len(), 1);
        assert_eq!(window.retained_bytes(), a.bytes.len());
        assert!(matches!(
            window.select(115, 14).unwrap().counts().weight(a.id),
            ObservationWeight::Exact(1)
        ));
    }

    #[test]
    fn window_restore_rejects_scope_aliases_duplicate_days_and_future_data() {
        let limits = ProfileWindowLimits::default();
        let mut window =
            RetainedBucketWindow::new(CanonicalDomain::Headers, ValueId([2; 32]), [3; 32], limits)
                .unwrap();
        window
            .observe(100, 100, observation(1), &value("A"))
            .unwrap();
        let mut snapshot = window.snapshot();
        let mut other_scope = CountedObservationBucket::new(
            CanonicalDomain::Headers,
            ValueId([9; 32]),
            [3; 32],
            limits.bucket,
        )
        .unwrap();
        other_scope.observe(observation(1), &value("A")).unwrap();
        snapshot.buckets[0].bucket = other_scope.snapshot();
        RetainedBucketWindow::from_snapshot(
            &snapshot,
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            limits,
        )
        .unwrap_err();
        let mut snapshot = window.snapshot();
        snapshot.buckets = vec![snapshot.buckets[0].clone(); 2].into();
        RetainedBucketWindow::from_snapshot(
            &snapshot,
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            limits,
        )
        .unwrap_err();
        let mut snapshot = window.snapshot();
        snapshot.buckets[0].day = 101;
        RetainedBucketWindow::from_snapshot(
            &snapshot,
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            limits,
        )
        .unwrap_err();
        snapshot.buckets[0].day = 86;
        RetainedBucketWindow::from_snapshot(
            &snapshot,
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            limits,
        )
        .unwrap_err();
        let limits = ProfileWindowLimits {
            retained_bytes: 0,
            ..limits
        };
        RetainedBucketWindow::from_snapshot(
            &window.snapshot(),
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            limits,
        )
        .unwrap_err();
    }
    #[test]
    fn default_window_saturation_counts_the_next_observation_and_drop() {
        let limits = ProfileWindowLimits::default();
        let policy = HeaderCapturePolicy::default();
        let mut window =
            RetainedBucketWindow::new(CanonicalDomain::Headers, ValueId([2; 32]), [3; 32], limits)
                .unwrap();
        let mut sequence = 0u64;
        let mut last = None;
        for day in 100..=113 {
            for _ in 0..200 {
                sequence += 1;
                let mut bytes = vec![b'a'; kib(15)];
                bytes[..16].copy_from_slice(format!("{sequence:016x}").as_bytes());
                let mut headers = HeaderMap::new();
                headers.insert("accept", HeaderValue::from_bytes(&bytes).unwrap());
                let value = policy
                    .capture(Version::HTTP_11, &headers, None)
                    .unwrap()
                    .canonical(&policy)
                    .unwrap();
                window
                    .observe(day, day, observation(sequence), &value)
                    .unwrap();
                last = Some(value);
            }
        }
        let before = window.select(113, 14).unwrap().snapshot();
        assert_eq!(before.counts.total, sequence);
        assert!(before.counts.losses.retention > 0);
        window
            .observe(113, 113, observation(sequence + 1), &last.unwrap())
            .unwrap();
        let after = window.select(113, 14).unwrap().snapshot();
        assert_eq!(after.counts.total, sequence + 1);
        assert_eq!(
            after.counts.losses.retention,
            before.counts.losses.retention + 1
        );
        assert!(window.retained_bytes() <= limits.retained_bytes);
        let restored = RetainedBucketWindow::from_snapshot(
            &window.snapshot(),
            CanonicalDomain::Headers,
            ValueId([2; 32]),
            [3; 32],
            limits,
        )
        .unwrap();
        assert_eq!(encoded(&window), encoded(&restored));
    }
    #[test]
    fn window_restoration_requires_expected_identity_even_without_day_buckets() {
        let limits = ProfileWindowLimits::default();
        let scope = ValueId([2; 32]);
        let mut window =
            RetainedBucketWindow::new(CanonicalDomain::Headers, scope, [3; 32], limits).unwrap();
        for populated in [false, true] {
            if populated {
                window
                    .observe(100, 100, observation(1), &value("A"))
                    .unwrap();
            }
            let snapshot = window.snapshot();
            RetainedBucketWindow::from_snapshot(
                &snapshot,
                CanonicalDomain::Headers,
                ValueId([9; 32]),
                [3; 32],
                limits,
            )
            .unwrap_err();
            RetainedBucketWindow::from_snapshot(
                &snapshot,
                CanonicalDomain::Order,
                scope,
                [3; 32],
                limits,
            )
            .unwrap_err();
            let restored = RetainedBucketWindow::from_snapshot(
                &snapshot,
                CanonicalDomain::Headers,
                scope,
                [3; 32],
                limits,
            )
            .unwrap();
            assert_eq!(encoded(&restored), encoded(&window));
        }
    }
    #[test]
    fn version_one_snapshot_layouts_keep_numeric_domains_and_explicit_coverage() {
        let limits = ProfileWindowLimits::default();
        let scope = ValueId([2; 32]);
        let window =
            RetainedBucketWindow::new(CanonicalDomain::Headers, scope, [3; 32], limits).unwrap();
        let bucket =
            CountedObservationBucket::new(CanonicalDomain::Headers, scope, [3; 32], limits.bucket)
                .unwrap();
        let bucket_json = r#"{"format_version":1,"domain":1,"scope":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"counts":{"total":0,"untracked":0,"values":[],"losses":{"oversize":0,"retention":0,"history_known":true}},"samples":[],"values":[]}"#;
        let window_json = r#"{"format_version":1,"domain":1,"scope":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"last_day":0,"buckets":[]}"#;
        assert_eq!(
            serde_json::to_string(&bucket.snapshot()).unwrap(),
            bucket_json
        );
        assert_eq!(
            serde_json::to_string(&window.snapshot()).unwrap(),
            window_json
        );
        let restored = CountedObservationBucket::from_snapshot(
            &serde_json::from_str(bucket_json).unwrap(),
            CanonicalDomain::Headers,
            scope,
            [3; 32],
            limits.bucket,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_string(&restored.snapshot()).unwrap(),
            bucket_json
        );
        let restored = RetainedBucketWindow::from_snapshot(
            &serde_json::from_str(window_json).unwrap(),
            CanonicalDomain::Headers,
            scope,
            [3; 32],
            limits,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_string(&restored.snapshot()).unwrap(),
            window_json
        );
    }
}
