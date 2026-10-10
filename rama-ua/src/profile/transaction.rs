//! Atomic admission of one observation and all of its counted components.

use std::{collections::BTreeSet, iter};

use rama_utils::octets::mib;
use serde::{Deserialize, Serialize};

use super::{
    CanonicalValue, CountedBucketSnapshot, CountedObservationBucket, IngestionCheckpoint,
    IngestionCursor, IngestionDisposition, IngestionLimits, ObservationId, ProfileBucketLimits,
    ProfileDataError, RetentionWindow,
};

/// The creation day is part of the identity, so deleting an expired checkpoint
/// cannot make its old IDs admissible again. Nonces come from the writer's RNG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureRunId(pub [u8; 16]);

impl CaptureRunId {
    #[must_use]
    pub fn new(created_day: u32, nonce: [u8; 12]) -> Self {
        let mut bytes = [0; 16];
        bytes[..4].copy_from_slice(&created_day.to_be_bytes());
        bytes[4..].copy_from_slice(&nonce);
        Self(bytes)
    }

    #[must_use]
    pub fn created_day(self) -> u32 {
        u32::from_be_bytes([self.0[0], self.0[1], self.0[2], self.0[3]])
    }
}

/// Loaded under the store's authorization and run-row locks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureRunCheckpoint {
    pub format_version: u16,
    pub run: CaptureRunId,
    pub authorized: bool,
    pub last_day: u32,
    pub sequences: IngestionCheckpoint,
}

impl CaptureRunCheckpoint {
    pub fn new(
        run: CaptureRunId,
        authorized: bool,
        current_day: u32,
        limits: IngestionBatchLimits,
    ) -> Result<Self, ProfileDataError> {
        limits.bucket.validate()?;
        limits
            .retention
            .validate_observation(current_day, run.created_day())?;
        Ok(Self {
            format_version: 1,
            run,
            authorized,
            last_day: current_day,
            sequences: IngestionCursor::new(limits.ingestion).checkpoint(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredObservationBucket {
    pub authorized: bool,
    pub day: u32,
    pub bucket: CountedBucketSnapshot,
}

/// Both the snapshot and the value remain borrowed until the entire batch passes
/// its count and payload preflight. A new bucket uses an empty validated snapshot.
#[derive(Debug, Clone, Copy)]
pub struct PendingBucketObservation<'a> {
    pub previous: &'a StoredObservationBucket,
    pub value: &'a CanonicalValue,
}

#[derive(Debug, Clone, Copy)]
pub struct IngestionBatchLimits {
    pub retention: RetentionWindow,
    pub ingestion: IngestionLimits,
    pub bucket: ProfileBucketLimits,
    pub buckets: usize,
    /// Combined incoming values and stored canonical payloads, before decoding.
    pub input_bytes: usize,
    pub retained_bytes: usize,
}

impl Default for IngestionBatchLimits {
    fn default() -> Self {
        Self {
            retention: RetentionWindow::default(),
            ingestion: IngestionLimits::default(),
            bucket: ProfileBucketLimits::default(),
            buckets: 16,
            input_bytes: mib(32),
            retained_bytes: mib(32),
        }
    }
}

/// Writer-assigned identity and observed day, independent of the retry's arrival day.
#[derive(Debug, Clone, Copy)]
pub struct IngestionAttempt {
    pub authorized: bool,
    pub observation_day: u32,
    pub observation: ObservationId,
}

#[derive(Debug)]
pub enum PreparedIngestion {
    /// No effects are returned for an already committed sequence, even when a
    /// retry arrives on another retained day or names another component.
    Duplicate,
    Commit {
        run: CaptureRunCheckpoint,
        buckets: Box<[StoredObservationBucket]>,
    },
}

impl CaptureRunCheckpoint {
    /// Prepare all effects without mutating loaded state. The store atomically
    /// commits the returned run checkpoint, buckets and global quota deltas.
    /// Its locks must span the read, this call, and commit. IDs are trusted writer
    /// identities: bounded checkpoints detect retries, not conflicting retry bodies.
    pub fn prepare(
        &self,
        current_day: u32,
        attempt: IngestionAttempt,
        pending: &[PendingBucketObservation<'_>],
        seed: [u8; 32],
        limits: IngestionBatchLimits,
    ) -> Result<PreparedIngestion, ProfileDataError> {
        limits.bucket.validate()?;
        let IngestionAttempt {
            authorized,
            observation_day,
            observation,
        } = attempt;
        if self.format_version != 1 {
            return Err(ProfileDataError::Unsupported(
                "capture run checkpoint format",
            ));
        }
        if self.authorized != authorized || self.run.0 != observation.run {
            return Err(ProfileDataError::Invalid("ingestion run ownership"));
        }
        if current_day < self.last_day || self.last_day < self.run.created_day() {
            return Err(ProfileDataError::Invalid("ingestion time watermark"));
        }
        limits
            .retention
            .validate_observation(current_day, self.run.created_day())?;
        limits
            .retention
            .validate_observation(current_day, observation_day)?;
        if observation_day < self.run.created_day() {
            return Err(ProfileDataError::Invalid(
                "observation predates capture run",
            ));
        }
        if pending.is_empty() || pending.len() > limits.buckets {
            return Err(ProfileDataError::LimitExceeded("ingestion batch buckets"));
        }
        let mut cursor = IngestionCursor::from_checkpoint(&self.sequences, limits.ingestion)?;
        if matches!(
            cursor.record(observation.sequence)?,
            IngestionDisposition::Duplicate
        ) {
            return Ok(PreparedIngestion::Duplicate);
        }
        let maximum_values = limits
            .bucket
            .literal_values
            .checked_add(limits.bucket.samples)
            .ok_or(ProfileDataError::LimitExceeded("interned value count"))?;
        let mut remaining_input = limits.input_bytes;
        let mut remaining_retained = limits.retained_bytes;
        let mut scopes = BTreeSet::new();
        for item in pending {
            let previous = item.previous;
            if previous.authorized != authorized || previous.day != observation_day {
                return Err(ProfileDataError::Invalid("ingestion bucket ownership"));
            }
            if !scopes.insert(previous.bucket.scope) {
                return Err(ProfileDataError::Invalid("duplicate ingestion bucket"));
            }
            if previous.bucket.values.len() > maximum_values
                || previous.bucket.samples.len() > limits.bucket.samples
                || previous.bucket.counts.values.len() > limits.bucket.literal_values
            {
                return Err(ProfileDataError::LimitExceeded("ingestion bucket entries"));
            }
            for value in previous.bucket.values.iter().chain(iter::once(item.value)) {
                if value.bytes.len() > limits.bucket.input_bytes {
                    return Err(ProfileDataError::LimitExceeded("ingestion value bytes"));
                }
                remaining_input = remaining_input.checked_sub(value.bytes.len()).ok_or(
                    ProfileDataError::LimitExceeded("ingestion batch input bytes"),
                )?;
            }
        }
        for item in pending {
            for value in &item.previous.bucket.values {
                remaining_retained = remaining_retained.checked_sub(value.bytes.len()).ok_or(
                    ProfileDataError::LimitExceeded("existing ingestion retained bytes"),
                )?;
            }
        }
        let mut buckets = Vec::new();
        for item in pending {
            let mut bucket = CountedObservationBucket::from_snapshot(
                &item.previous.bucket,
                seed,
                limits.bucket,
            )?;
            let available = remaining_retained
                .checked_add(bucket.retained_bytes())
                .ok_or(ProfileDataError::LimitExceeded(
                    "ingestion batch retained bytes",
                ))?;
            bucket.observe_with_retained_limit(observation, item.value, available)?;
            remaining_retained = available.checked_sub(bucket.retained_bytes()).ok_or(
                ProfileDataError::LimitExceeded("ingestion batch retained bytes"),
            )?;
            buckets.push(StoredObservationBucket {
                authorized,
                day: observation_day,
                bucket: bucket.snapshot(),
            });
        }
        Ok(PreparedIngestion::Commit {
            run: Self {
                format_version: 1,
                run: self.run,
                authorized,
                last_day: current_day,
                sequences: cursor.checkpoint(),
            },
            buckets: buckets.into(),
        })
    }
}

#[cfg(test)]
mod tests;
