//! Bounded distinct-value evidence for observations outside the literal counters.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{ProfileDataError, ValueId};

const DISTINCT_VALUES: usize = 32;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UntrackedDistinctSnapshot {
    pub values: Box<[ValueId]>,
    pub saturated: bool,
    /// False for observations recorded before distinct-value evidence was retained.
    pub history_known: bool,
}

/// A deterministic lower bound is reported after capacity, without an estimated
/// cardinality or statistical confidence claim. Repeated values count once.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum UntrackedDistinctCount {
    Exact(u64),
    AtLeast(u64),
    UnknownHistory { at_least: u64 },
}

#[derive(Debug, Clone)]
pub(super) struct UntrackedDistinct {
    values: BTreeSet<ValueId>,
    saturated: bool,
    history_known: bool,
}

impl UntrackedDistinct {
    pub(super) fn new() -> Self {
        Self {
            values: BTreeSet::new(),
            saturated: false,
            history_known: true,
        }
    }

    pub(super) fn from_snapshot(
        snapshot: &UntrackedDistinctSnapshot,
        observations: u64,
    ) -> Result<Self, ProfileDataError> {
        if snapshot.values.len() > DISTINCT_VALUES {
            return Err(ProfileDataError::LimitExceeded("untracked distinct values"));
        }
        if snapshot.saturated && snapshot.values.len() != DISTINCT_VALUES {
            return Err(ProfileDataError::Invalid("saturated distinct coverage"));
        }
        let lower_bound = snapshot.values.len() as u64 + u64::from(snapshot.saturated);
        if lower_bound > observations
            || (snapshot.history_known && observations != 0 && snapshot.values.is_empty())
        {
            return Err(ProfileDataError::Invalid("distinct observation coverage"));
        }
        if snapshot.values.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ProfileDataError::Invalid("distinct value ordering"));
        }
        Ok(Self {
            values: snapshot.values.iter().copied().collect(),
            saturated: snapshot.saturated,
            history_known: snapshot.history_known,
        })
    }

    pub(super) fn observe(&mut self, value: ValueId) {
        self.values.insert(value);
        if self.values.len() > DISTINCT_VALUES {
            self.saturated = true;
            self.values.pop_last();
        }
    }

    pub(super) fn merge(&self, other: &Self) -> Self {
        let mut result = self.clone();
        for value in &other.values {
            result.observe(*value);
        }
        result.saturated |= other.saturated;
        result.history_known &= other.history_known;
        result
    }

    pub(super) fn snapshot(&self) -> UntrackedDistinctSnapshot {
        UntrackedDistinctSnapshot {
            values: self.values.iter().copied().collect(),
            saturated: self.saturated,
            history_known: self.history_known,
        }
    }

    pub(super) fn count(&self) -> UntrackedDistinctCount {
        let lower_bound = self.values.len() as u64 + u64::from(self.saturated);
        if !self.history_known {
            UntrackedDistinctCount::UnknownHistory {
                at_least: lower_bound,
            }
        } else if self.saturated {
            UntrackedDistinctCount::AtLeast(lower_bound)
        } else {
            UntrackedDistinctCount::Exact(lower_bound)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_values_are_exact_until_capacity_then_a_bounded_lower_bound() {
        let mut distinct = UntrackedDistinct::new();
        for _ in 0..10_000 {
            distinct.observe(ValueId([1; 32]));
        }
        assert!(matches!(distinct.count(), UntrackedDistinctCount::Exact(1)));
        for index in 2..=32 {
            distinct.observe(ValueId([index; 32]));
        }
        assert!(matches!(
            distinct.count(),
            UntrackedDistinctCount::Exact(32)
        ));
        for index in 33..=255 {
            distinct.observe(ValueId([index; 32]));
        }
        assert!(matches!(
            distinct.count(),
            UntrackedDistinctCount::AtLeast(33)
        ));
        assert_eq!(distinct.snapshot().values.len(), DISTINCT_VALUES);
        assert!(matches!(
            UntrackedDistinct::from_snapshot(&distinct.snapshot(), 10_255)
                .unwrap()
                .count(),
            UntrackedDistinctCount::AtLeast(33)
        ));
    }

    #[test]
    fn distinct_merge_and_permutations_preserve_bottom_k_and_unknown_history() {
        let mut forward = UntrackedDistinct::new();
        let mut reverse = UntrackedDistinct::new();
        let mut left = UntrackedDistinct::new();
        let mut right = UntrackedDistinct::new();
        for index in 0..=255 {
            forward.observe(ValueId([index; 32]));
            reverse.observe(ValueId([255 - index; 32]));
            if index % 2 == 0 {
                left.observe(ValueId([index; 32]));
            } else {
                right.observe(ValueId([index; 32]));
            }
        }
        let expected = serde_json::to_vec(&forward.snapshot()).unwrap();
        assert_eq!(expected, serde_json::to_vec(&reverse.snapshot()).unwrap());
        assert_eq!(
            expected,
            serde_json::to_vec(&left.merge(&right).snapshot()).unwrap()
        );
        assert_eq!(
            expected,
            serde_json::to_vec(&right.merge(&left).snapshot()).unwrap()
        );
        let unknown =
            UntrackedDistinct::from_snapshot(&UntrackedDistinctSnapshot::default(), 10_000)
                .unwrap();
        assert!(matches!(
            forward.merge(&unknown).count(),
            UntrackedDistinctCount::UnknownHistory { at_least: 33 }
        ));
    }

    #[test]
    fn distinct_restore_rejects_impossible_or_unbounded_evidence() {
        for snapshot in [
            UntrackedDistinctSnapshot {
                values: vec![ValueId([1; 32]); 33].into(),
                saturated: true,
                history_known: true,
            },
            UntrackedDistinctSnapshot {
                values: vec![ValueId([1; 32]); 2].into(),
                saturated: false,
                history_known: true,
            },
            UntrackedDistinctSnapshot {
                values: vec![ValueId([2; 32]), ValueId([1; 32])].into(),
                saturated: false,
                history_known: true,
            },
            UntrackedDistinctSnapshot {
                values: Box::default(),
                saturated: true,
                history_known: false,
            },
            UntrackedDistinctSnapshot {
                values: Box::default(),
                saturated: false,
                history_known: true,
            },
        ] {
            UntrackedDistinct::from_snapshot(&snapshot, 100).unwrap_err();
        }
        let mut distinct = UntrackedDistinct::new();
        distinct.observe(ValueId([1; 32]));
        UntrackedDistinct::from_snapshot(&distinct.snapshot(), 0).unwrap_err();
        for index in 2..=33 {
            distinct.observe(ValueId([index; 32]));
        }
        UntrackedDistinct::from_snapshot(&distinct.snapshot(), 32).unwrap_err();
    }
}
