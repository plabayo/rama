//! Bounded ingestion checkpoints for transaction retries and out-of-order delivery.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::ProfileDataError;

/// A writer assigns sequences only after reserving capacity in its bounded queue.
/// Retries keep the same run and sequence; a new run never reuses its identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObservationId {
    pub run: [u8; 16],
    pub sequence: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SequenceRange {
    pub first: u64,
    pub last: u64,
}

/// Completed sequences above the contiguous prefix, sorted and nonadjacent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestionCheckpoint {
    pub prefix: u64,
    pub completed: Box<[SequenceRange]>,
}

#[derive(Debug, Clone, Copy)]
pub struct IngestionLimits {
    pub pending_ranges: usize,
    pub forward_gap: u64,
}

impl Default for IngestionLimits {
    fn default() -> Self {
        Self {
            pending_ranges: 64,
            forward_gap: 4096,
        }
    }
}

/// The containing transaction also commits counts and reservoirs under its run-row lock.
/// The checkpoint alone is not evidence that those effects were committed.
#[derive(Debug, Clone)]
pub struct IngestionCursor {
    prefix: u64,
    completed: BTreeMap<u64, u64>,
    limits: IngestionLimits,
}

#[derive(Debug, Clone, Copy)]
pub enum IngestionDisposition {
    New,
    Duplicate,
}

impl IngestionCursor {
    #[must_use]
    pub fn new(limits: IngestionLimits) -> Self {
        Self {
            prefix: 0,
            completed: BTreeMap::new(),
            limits,
        }
    }

    pub fn from_checkpoint(
        checkpoint: &IngestionCheckpoint,
        limits: IngestionLimits,
    ) -> Result<Self, ProfileDataError> {
        if checkpoint.completed.len() > limits.pending_ranges {
            return Err(ProfileDataError::LimitExceeded("ingestion ranges"));
        }
        let mut previous = checkpoint.prefix;
        for range in &checkpoint.completed {
            if range.first == 0
                || range.first > range.last
                || range.first.saturating_sub(previous) <= 1
            {
                return Err(ProfileDataError::Invalid("ingestion range ordering"));
            }
            if range.last.saturating_sub(checkpoint.prefix) > limits.forward_gap {
                return Err(ProfileDataError::LimitExceeded("ingestion forward gap"));
            }
            previous = range.last;
        }
        Ok(Self {
            prefix: checkpoint.prefix,
            completed: checkpoint
                .completed
                .iter()
                .map(|range| (range.first, range.last))
                .collect(),
            limits,
        })
    }

    #[must_use]
    pub fn checkpoint(&self) -> IngestionCheckpoint {
        IngestionCheckpoint {
            prefix: self.prefix,
            completed: self
                .completed
                .iter()
                .map(|(&first, &last)| SequenceRange { first, last })
                .collect(),
        }
    }

    /// Record a sequence in the transaction's private cursor. Failed admission changes nothing.
    /// A gap is never treated as completed merely because a larger sequence arrived first.
    pub fn record(&mut self, sequence: u64) -> Result<IngestionDisposition, ProfileDataError> {
        if sequence == 0 {
            return Err(ProfileDataError::Invalid("zero ingestion sequence"));
        }
        if sequence <= self.prefix {
            return Ok(IngestionDisposition::Duplicate);
        }
        let previous = self
            .completed
            .range(..=sequence)
            .next_back()
            .map(|(&first, &last)| (first, last));
        if previous.is_some_and(|(_first, last)| sequence <= last) {
            return Ok(IngestionDisposition::Duplicate);
        }
        if sequence - self.prefix > self.limits.forward_gap {
            return Err(ProfileDataError::LimitExceeded("ingestion forward gap"));
        }
        if sequence - self.prefix == 1 {
            self.prefix = sequence;
            while let Some((&first, &last)) = self.completed.first_key_value() {
                if first - self.prefix != 1 {
                    break;
                }
                self.prefix = last;
                self.completed.pop_first();
            }
            return Ok(IngestionDisposition::New);
        }
        let next = self
            .completed
            .range(sequence..)
            .next()
            .map(|(&first, &last)| (first, last));
        let merge_previous = previous.filter(|(_first, last)| sequence - last == 1);
        let merge_next = next.filter(|(first, _last)| first - sequence == 1);
        if merge_previous.is_none()
            && merge_next.is_none()
            && self.completed.len() >= self.limits.pending_ranges
        {
            return Err(ProfileDataError::LimitExceeded("ingestion ranges"));
        }
        let first = merge_previous.map_or(sequence, |(first, _last)| first);
        let last = merge_next.map_or(sequence, |(_first, last)| last);
        if let Some((next_first, _last)) = merge_next {
            self.completed.remove(&next_first);
        }
        self.completed.insert(first, last);
        Ok(IngestionDisposition::New)
    }
}

/// Queries include the current partial UTC day and complete preceding buckets.
#[derive(Debug, Clone, Copy)]
pub struct RetentionWindow {
    pub days: u32,
}

impl Default for RetentionWindow {
    fn default() -> Self {
        Self { days: 14 }
    }
}

impl RetentionWindow {
    pub fn first_day(self, current_day: u32, horizon: u32) -> Result<u32, ProfileDataError> {
        if self.days == 0 || horizon == 0 || horizon > self.days {
            return Err(ProfileDataError::Unsupported("retention horizon"));
        }
        Ok(current_day.saturating_sub(horizon - 1))
    }

    pub fn validate_observation(
        self,
        current_day: u32,
        observation_day: u32,
    ) -> Result<(), ProfileDataError> {
        let first = self.first_day(current_day, self.days)?;
        if observation_day < first || observation_day > current_day {
            return Err(ProfileDataError::Invalid(
                "observation outside retention window",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn ingestion_out_of_order_never_commits_missing_sequences() {
        let mut cursor = IngestionCursor::new(IngestionLimits::default());
        assert!(matches!(
            cursor.record(3).unwrap(),
            IngestionDisposition::New
        ));
        assert_eq!(cursor.checkpoint().prefix, 0);
        assert!(matches!(
            cursor.record(3).unwrap(),
            IngestionDisposition::Duplicate
        ));
        assert!(matches!(
            cursor.record(1).unwrap(),
            IngestionDisposition::New
        ));
        assert_eq!(cursor.checkpoint().prefix, 1);
        let restored = cursor.checkpoint();
        let mut cursor =
            IngestionCursor::from_checkpoint(&restored, IngestionLimits::default()).unwrap();
        assert!(matches!(
            cursor.record(2).unwrap(),
            IngestionDisposition::New
        ));
        assert_eq!(cursor.checkpoint().prefix, 3);
        assert!(cursor.checkpoint().completed.is_empty());
        for sequence in 1..=3 {
            assert!(matches!(
                cursor.record(sequence).unwrap(),
                IngestionDisposition::Duplicate
            ));
        }
        cursor.record(0).unwrap_err();
    }

    #[test]
    fn ingestion_merges_ranges_at_capacity_and_rejects_without_changes() {
        let limits = IngestionLimits {
            pending_ranges: 2,
            forward_gap: 10,
        };
        let mut cursor = IngestionCursor::new(limits);
        cursor.record(11).unwrap_err();
        assert_eq!(cursor.checkpoint().prefix, 0);
        assert!(cursor.checkpoint().completed.is_empty());
        for sequence in [3, 5] {
            cursor.record(sequence).unwrap();
        }
        let before = serde_json::to_vec(&cursor.checkpoint()).unwrap();
        cursor.record(7).unwrap_err();
        cursor.record(11).unwrap_err();
        assert_eq!(before, serde_json::to_vec(&cursor.checkpoint()).unwrap());
        cursor.record(4).unwrap();
        assert_eq!(cursor.checkpoint().completed.len(), 1);
        cursor.record(6).unwrap();
        cursor.record(2).unwrap();
        cursor.record(1).unwrap();
        assert_eq!(cursor.checkpoint().prefix, 6);
        assert!(cursor.checkpoint().completed.is_empty());
        let mut serial = IngestionCursor::new(IngestionLimits {
            pending_ranges: 0,
            forward_gap: 1,
        });
        for sequence in 1..=10_000 {
            serial.record(sequence).unwrap();
        }
        assert_eq!(serial.checkpoint().prefix, 10_000);
        assert!(serial.checkpoint().completed.is_empty());
    }

    #[test]
    fn ingestion_checkpoint_rejects_noncanonical_ranges_and_integer_boundaries() {
        let limits = IngestionLimits {
            pending_ranges: 2,
            forward_gap: u64::MAX,
        };
        for completed in [
            vec![SequenceRange { first: 0, last: 2 }],
            vec![SequenceRange { first: 2, last: 1 }],
            vec![SequenceRange { first: 1, last: 2 }],
            vec![
                SequenceRange { first: 2, last: 3 },
                SequenceRange { first: 4, last: 5 },
            ],
            vec![
                SequenceRange { first: 3, last: 5 },
                SequenceRange { first: 4, last: 8 },
            ],
        ] {
            IngestionCursor::from_checkpoint(
                &IngestionCheckpoint {
                    prefix: 0,
                    completed: completed.into(),
                },
                limits,
            )
            .unwrap_err();
        }
        let checkpoint = IngestionCheckpoint {
            prefix: u64::MAX - 2,
            completed: vec![SequenceRange {
                first: u64::MAX,
                last: u64::MAX,
            }]
            .into(),
        };
        let mut cursor = IngestionCursor::from_checkpoint(&checkpoint, limits).unwrap();
        cursor.record(u64::MAX - 1).unwrap();
        assert_eq!(cursor.checkpoint().prefix, u64::MAX);
        assert!(matches!(
            cursor.record(u64::MAX).unwrap(),
            IngestionDisposition::Duplicate
        ));
        let limited = IngestionLimits {
            pending_ranges: 0,
            forward_gap: 1,
        };
        IngestionCursor::from_checkpoint(&checkpoint, limited).unwrap_err();
    }

    #[test]
    fn retention_rejects_expired_retry_future_day_and_unsupported_query() {
        let window = RetentionWindow::default();
        assert_eq!(window.first_day(100, 14).unwrap(), 87);
        for day in 87..=100 {
            window.validate_observation(100, day).unwrap();
        }
        window.validate_observation(100, 86).unwrap_err();
        window.validate_observation(100, 101).unwrap_err();
        window.validate_observation(101, 87).unwrap_err();
        window.first_day(100, 15).unwrap_err();
        window.first_day(100, 0).unwrap_err();
        RetentionWindow { days: 0 }
            .validate_observation(100, 100)
            .unwrap_err();
        assert_eq!(window.first_day(0, 14).unwrap(), 0);
    }

    #[test]
    fn ingestion_checkpoint_matches_delivered_ids_across_permutations() {
        for seed in 0..64_u64 {
            let mut state = seed + 1;
            let mut order: Vec<u64> = (1..=64).collect();
            for index in (1..order.len()).rev() {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                order.swap(index, (state % (index as u64 + 1)) as usize);
            }
            let limits = IngestionLimits {
                pending_ranges: 64,
                forward_gap: 64,
            };
            let mut cursor = IngestionCursor::new(limits);
            let mut delivered = BTreeSet::new();
            for sequence in order {
                assert!(matches!(
                    cursor.record(sequence).unwrap(),
                    IngestionDisposition::New
                ));
                delivered.insert(sequence);
                assert!(matches!(
                    cursor.record(sequence).unwrap(),
                    IngestionDisposition::Duplicate
                ));
                let checkpoint = cursor.checkpoint();
                let expected_prefix =
                    (1..=64).take_while(|id| delivered.contains(id)).count() as u64;
                assert_eq!(checkpoint.prefix, expected_prefix);
                for id in 1..=64 {
                    let represented = id <= checkpoint.prefix
                        || checkpoint
                            .completed
                            .iter()
                            .any(|range| range.first <= id && id <= range.last);
                    assert_eq!(represented, delivered.contains(&id));
                }
                cursor = IngestionCursor::from_checkpoint(&checkpoint, limits).unwrap();
            }
            assert_eq!(cursor.checkpoint().prefix, 64);
        }
    }
}
