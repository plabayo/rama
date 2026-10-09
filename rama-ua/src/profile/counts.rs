//! Exact aggregate counts and bounded literal counters with explicit coverage.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{ProfileDataError, ValueId};

/// PostgreSQL BIGINT and the in-memory engine have the same overflow boundary.
const MAXIMUM_COUNT: u64 = i64::MAX as u64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiteralCount {
    pub value: ValueId,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterSnapshot {
    pub total: u64,
    /// Observations not assigned to one of the retained literal counters.
    /// This is not an exact count of distinct unretained values.
    pub untracked: u64,
    pub values: Box<[LiteralCount]>,
}

/// Partial literal coverage never masquerades as an exact full-history weight.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ObservationWeight {
    Exact(u64),
    LowerBound { observed: u64, unassigned: u64 },
}

#[derive(Debug, Clone)]
pub struct LiteralCounters {
    capacity: usize,
    total: u64,
    untracked: u64,
    values: BTreeMap<ValueId, u64>,
}

fn add_count(left: u64, right: u64) -> Result<u64, ProfileDataError> {
    left.checked_add(right)
        .filter(|value| *value <= MAXIMUM_COUNT)
        .ok_or(ProfileDataError::CounterOverflow)
}

impl LiteralCounters {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            total: 0,
            untracked: 0,
            values: BTreeMap::new(),
        }
    }

    /// Validate every count and the full accounting identity before retaining keys.
    pub fn from_snapshot(
        snapshot: &CounterSnapshot,
        capacity: usize,
    ) -> Result<Self, ProfileDataError> {
        if snapshot.values.len() > capacity {
            return Err(ProfileDataError::LimitExceeded("literal counters"));
        }
        let mut total = add_count(0, snapshot.untracked)?;
        let mut previous = None;
        for value in &snapshot.values {
            if value.count == 0 || previous.is_some_and(|id| id >= value.value) {
                return Err(ProfileDataError::Invalid(
                    "literal counter ordering or zero count",
                ));
            }
            total = add_count(total, value.count)?;
            previous = Some(value.value);
        }
        if total != snapshot.total {
            return Err(ProfileDataError::Invalid("literal counter total"));
        }
        Ok(Self {
            capacity,
            total,
            untracked: snapshot.untracked,
            values: snapshot
                .values
                .iter()
                .map(|value| (value.value, value.count))
                .collect(),
        })
    }

    #[must_use]
    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            total: self.total,
            untracked: self.untracked,
            values: self
                .values
                .iter()
                .map(|(&value, &count)| LiteralCount { value, count })
                .collect(),
        }
    }

    pub(super) fn value_ids(&self) -> impl Iterator<Item = ValueId> + '_ {
        self.values.keys().copied()
    }

    /// The ingestion transaction admits the ID and validates/interns the value first.
    /// Counter overflow leaves this accumulator unchanged.
    pub fn observe(&mut self, value: ValueId) -> Result<(), ProfileDataError> {
        let total = add_count(self.total, 1)?;
        let retain = self.values.len() < self.capacity;
        match self.values.get_mut(&value) {
            Some(count) => *count = add_count(*count, 1)?,
            None if retain => {
                self.values.insert(value, 1);
            }
            None => self.untracked = add_count(self.untracked, 1)?,
        }
        self.total = total;
        Ok(())
    }

    #[must_use]
    pub fn weight(&self, value: ValueId) -> ObservationWeight {
        let observed = self.values.get(&value).copied().unwrap_or(0);
        if self.untracked == 0 {
            ObservationWeight::Exact(observed)
        } else {
            ObservationWeight::LowerBound {
                observed,
                unassigned: self.untracked,
            }
        }
    }

    /// Coarsen disjoint buckets without inventing lost literal history.
    /// The lowest value IDs survive if their union exceeds the common capacity.
    /// Callers enforce disjoint day coverage and scope before summing counts.
    pub fn merge(&self, other: &Self) -> Result<Self, ProfileDataError> {
        if self.capacity != other.capacity {
            return Err(ProfileDataError::Invalid(
                "incompatible literal counter capacities",
            ));
        }
        let total = add_count(self.total, other.total)?;
        let mut merged = Self::new(self.capacity);
        let mut left = self.values.iter().peekable();
        let mut right = other.values.iter().peekable();
        let mut tracked = 0;
        loop {
            let next = match (left.peek(), right.peek()) {
                (Some(&(a, count_a)), Some(&(b, count_b))) if a == b => {
                    let count = add_count(*count_a, *count_b)?;
                    let value = *a;
                    left.next();
                    right.next();
                    Some((value, count))
                }
                (Some(&(a, _)), Some(&(b, _))) if a < b => {
                    left.next().map(|(&value, &count)| (value, count))
                }
                (_, Some(_)) => right.next().map(|(&value, &count)| (value, count)),
                (Some(_), None) => left.next().map(|(&value, &count)| (value, count)),
                (None, None) => break,
            };
            if let Some((value, count)) = next
                && merged.values.len() < merged.capacity
            {
                tracked = add_count(tracked, count)?;
                merged.values.insert(value, count);
            }
        }
        merged.total = total;
        merged.untracked = total
            .checked_sub(tracked)
            .ok_or(ProfileDataError::Invalid("literal counter accounting"))?;
        Ok(merged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(number: u8) -> ValueId {
        ValueId([number; 32])
    }
    fn encoded(counts: &LiteralCounters) -> Vec<u8> {
        serde_json::to_vec(&counts.snapshot()).unwrap()
    }

    #[test]
    fn literal_counters_keep_exact_totals_with_bounded_retention() {
        let mut counts = LiteralCounters::new(2);
        for index in 0..10_000 {
            counts.observe(value((index % 5) as u8)).unwrap();
        }
        let snapshot = counts.snapshot();
        assert_eq!(snapshot.total, 10_000);
        assert_eq!(snapshot.untracked, 6000);
        assert_eq!(snapshot.values.len(), 2);
        assert!(matches!(
            counts.weight(value(0)),
            ObservationWeight::LowerBound {
                observed: 2000,
                unassigned: 6000
            }
        ));
        assert!(matches!(
            counts.weight(value(9)),
            ObservationWeight::LowerBound {
                observed: 0,
                unassigned: 6000
            }
        ));
        let restored = LiteralCounters::from_snapshot(&snapshot, 2).unwrap();
        assert_eq!(encoded(&counts), encoded(&restored));
        let mut fixed = LiteralCounters::new(2);
        for _ in 0..10_000 {
            fixed.observe(value(1)).unwrap();
        }
        assert!(matches!(
            fixed.weight(value(1)),
            ObservationWeight::Exact(10_000)
        ));
        assert!(matches!(
            fixed.weight(value(2)),
            ObservationWeight::Exact(0)
        ));
        let mut disabled = LiteralCounters::new(0);
        disabled.observe(value(1)).unwrap();
        assert_eq!(disabled.snapshot().untracked, 1);
    }

    #[test]
    fn coarsening_sums_counts_without_claiming_unretained_history_is_exact() {
        let mut left = LiteralCounters::new(2);
        let mut right = LiteralCounters::new(2);
        for number in [1, 2, 1, 3] {
            left.observe(value(number)).unwrap();
        }
        for number in [3, 2, 1, 3] {
            right.observe(value(number)).unwrap();
        }
        let merged = left.merge(&right).unwrap();
        assert_eq!(encoded(&merged), encoded(&right.merge(&left).unwrap()));
        assert_eq!(merged.snapshot().total, 8);
        assert_eq!(merged.snapshot().untracked, 4);
        assert!(matches!(
            merged.weight(value(1)),
            ObservationWeight::LowerBound {
                observed: 2,
                unassigned: 4
            }
        ));
        assert!(matches!(
            merged.weight(value(2)),
            ObservationWeight::LowerBound {
                observed: 2,
                unassigned: 4
            }
        ));
        // The true count of value 1 is three; its second bucket did not retain it.
        let mut a = LiteralCounters::new(4);
        let mut b = LiteralCounters::new(4);
        for number in [1, 2, 1, 3] {
            a.observe(value(number)).unwrap();
        }
        for number in [3, 2, 1, 3] {
            b.observe(value(number)).unwrap();
        }
        let complete = a.merge(&b).unwrap();
        assert!(matches!(
            complete.weight(value(1)),
            ObservationWeight::Exact(3)
        ));
        assert!(matches!(
            complete.weight(value(2)),
            ObservationWeight::Exact(2)
        ));
        assert!(matches!(
            complete.weight(value(3)),
            ObservationWeight::Exact(3)
        ));
        a.merge(&left).unwrap_err();
    }

    #[test]
    fn counters_reject_corrupt_snapshots_and_bigint_overflow_without_mutation() {
        let snapshot = CounterSnapshot {
            total: MAXIMUM_COUNT,
            untracked: 0,
            values: vec![LiteralCount {
                value: value(1),
                count: MAXIMUM_COUNT,
            }]
            .into(),
        };
        let mut full = LiteralCounters::from_snapshot(&snapshot, 2).unwrap();
        let before = encoded(&full);
        full.observe(value(1)).unwrap_err();
        full.observe(value(2)).unwrap_err();
        assert_eq!(before, encoded(&full));
        full.merge(&full).unwrap_err();
        assert_eq!(before, encoded(&full));
        let mut invalid = snapshot;
        invalid.total -= 1;
        LiteralCounters::from_snapshot(&invalid, 2).unwrap_err();
        invalid.total = 0;
        invalid.values[0].count = 0;
        LiteralCounters::from_snapshot(&invalid, 2).unwrap_err();
        invalid.values[0].count = u64::MAX;
        invalid.total = u64::MAX;
        LiteralCounters::from_snapshot(&invalid, 2).unwrap_err();
        let mut duplicate = CounterSnapshot {
            total: 2,
            untracked: 0,
            values: vec![
                LiteralCount {
                    value: value(1),
                    count: 1
                };
                2
            ]
            .into(),
        };
        LiteralCounters::from_snapshot(&duplicate, 2).unwrap_err();
        duplicate.values[1].value = value(2);
        LiteralCounters::from_snapshot(&duplicate, 1).unwrap_err();
        duplicate.values.reverse();
        LiteralCounters::from_snapshot(&duplicate, 2).unwrap_err();
    }
}
