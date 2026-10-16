//! Freshness applies to counts and samples, with bounded retained UTC day buckets.

use std::collections::BTreeMap;

use rama_utils::octets::mib;
use serde::{Deserialize, Serialize};

use crate::profile::{
    evidence::{
        bucket::{CountedBucketSnapshot, CountedObservationBucket, ProfileBucketLimits},
        ingestion::{ObservationId, RetentionWindow},
    },
    format::canonical::{CanonicalDomain, CanonicalValue, ProfileDataError, ValueId},
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
    /// The day comes from the receiver clock via `profile_utc_day`, never peer metadata.
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
        limits
            .retention
            .first_day(snapshot.last_day, limits.retention.days)?;
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
mod tests;
