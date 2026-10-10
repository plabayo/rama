//! Freshness applies to counts and samples, with bounded retained UTC day buckets.

use std::collections::BTreeMap;

use rama_utils::octets::mib;
use serde::{Deserialize, Serialize};

use super::{
    CanonicalValue, CountedBucketSnapshot, CountedObservationBucket, ObservationId,
    ProfileBucketLimits, ProfileDataError, RetentionWindow, ValueId,
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
    pub domain: u16,
    pub scope: ValueId,
    pub last_day: u32,
    pub buckets: Box<[DayBucketSnapshot]>,
}

/// One authorization/profile/flow/structural scope, with no duplicate day coverage.
#[derive(Debug, Clone)]
pub struct RetainedBucketWindow {
    domain: u16,
    scope: ValueId,
    seed: [u8; 32],
    limits: ProfileWindowLimits,
    last_day: u32,
    buckets: BTreeMap<u32, CountedObservationBucket>,
}

impl RetainedBucketWindow {
    pub fn new(
        domain: u16,
        scope: ValueId,
        seed: [u8; 32],
        limits: ProfileWindowLimits,
    ) -> Result<Self, ProfileDataError> {
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
        let mut bucket = self
            .buckets
            .get(&observation_day)
            .cloned()
            .unwrap_or_else(|| {
                CountedObservationBucket::new(
                    self.domain,
                    self.scope,
                    self.seed,
                    self.limits.bucket,
                )
            });
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
        Ok(selected.unwrap_or_else(|| {
            CountedObservationBucket::new(self.domain, self.scope, self.seed, self.limits.bucket)
        }))
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
        seed: [u8; 32],
        limits: ProfileWindowLimits,
    ) -> Result<Self, ProfileDataError> {
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
            let bucket = CountedObservationBucket::from_snapshot(&day.bucket, seed, limits.bucket)?;
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
        let mut window = RetainedBucketWindow::new(1, ValueId([2; 32]), [3; 32], limits).unwrap();
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
        let restored =
            RetainedBucketWindow::from_snapshot(&window.snapshot(), [3; 32], limits).unwrap();
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
        let mut window = RetainedBucketWindow::new(1, ValueId([2; 32]), [3; 32], limits).unwrap();
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
            1,
            ValueId([2; 32]),
            [3; 32],
            ProfileBucketLimits {
                literal_values: 2,
                ..limits.bucket
            },
        );
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
    fn window_byte_limit_rejects_atomically_and_expiration_frees_capacity() {
        let a = value("A");
        let limits = ProfileWindowLimits {
            retained_bytes: a.bytes.len(),
            ..ProfileWindowLimits::default()
        };
        let mut window = RetainedBucketWindow::new(1, ValueId([2; 32]), [3; 32], limits).unwrap();
        window.observe(100, 100, observation(1), &a).unwrap();
        let before = encoded(&window);
        window.observe(101, 101, observation(2), &a).unwrap_err();
        assert_eq!(encoded(&window), before);
        window.observe(114, 114, observation(2), &a).unwrap();
        assert_eq!(window.snapshot().buckets.len(), 1);
        assert_eq!(window.retained_bytes(), a.bytes.len());
        assert!(matches!(
            window.select(114, 14).unwrap().counts().weight(a.id),
            ObservationWeight::Exact(1)
        ));
    }

    #[test]
    fn window_restore_rejects_scope_aliases_duplicate_days_and_future_data() {
        let limits = ProfileWindowLimits::default();
        let mut window = RetainedBucketWindow::new(1, ValueId([2; 32]), [3; 32], limits).unwrap();
        window
            .observe(100, 100, observation(1), &value("A"))
            .unwrap();
        let mut snapshot = window.snapshot();
        let mut other_scope =
            CountedObservationBucket::new(1, ValueId([9; 32]), [3; 32], limits.bucket);
        other_scope.observe(observation(1), &value("A")).unwrap();
        snapshot.buckets[0].bucket = other_scope.snapshot();
        RetainedBucketWindow::from_snapshot(&snapshot, [3; 32], limits).unwrap_err();
        let mut snapshot = window.snapshot();
        snapshot.buckets = vec![snapshot.buckets[0].clone(); 2].into();
        RetainedBucketWindow::from_snapshot(&snapshot, [3; 32], limits).unwrap_err();
        let mut snapshot = window.snapshot();
        snapshot.buckets[0].day = 101;
        RetainedBucketWindow::from_snapshot(&snapshot, [3; 32], limits).unwrap_err();
        snapshot.buckets[0].day = 86;
        RetainedBucketWindow::from_snapshot(&snapshot, [3; 32], limits).unwrap_err();
        let limits = ProfileWindowLimits {
            retained_bytes: 0,
            ..limits
        };
        RetainedBucketWindow::from_snapshot(&window.snapshot(), [3; 32], limits).unwrap_err();
    }
}
