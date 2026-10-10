//! Exact aggregate counts and bounded literal counters with explicit coverage.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{
    ProfileDataError, UntrackedDistinctCount, UntrackedDistinctSnapshot, ValueId,
    distinct::UntrackedDistinct,
};

/// Persistent and in-memory counters share the signed 64-bit ceiling.
const MAXIMUM_COUNT: u64 = i64::MAX as u64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiteralCount {
    pub value: ValueId,
    pub count: u64,
}

/// Losses count admitted observations whose complete value could not be retained.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct ObservationLosses {
    pub oversize: u64,
    pub retention: u64,
    /// False for imports that predate explicit loss accounting.
    pub history_known: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum ObservationLoss {
    Oversize,
    Retention,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterSnapshot {
    pub total: u64,
    /// Observations not assigned to one of the retained literal counters.
    /// This is not an exact count of distinct unretained values.
    pub untracked: u64,
    pub values: Box<[LiteralCount]>,
    #[serde(default)]
    pub losses: ObservationLosses,
    #[serde(default)]
    pub untracked_distinct: UntrackedDistinctSnapshot,
}

/// Partial literal coverage never masquerades as an exact full-history weight.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ObservationWeight {
    Exact(u64),
    UnknownHistory { observed: u64, unassigned: u64 },
    LowerBound { observed: u64, unassigned: u64 },
}

#[derive(Debug, Clone)]
pub struct LiteralCounters {
    capacity: usize,
    total: u64,
    untracked: u64,
    values: BTreeMap<ValueId, u64>,
    losses: ObservationLosses,
    distinct: UntrackedDistinct,
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
            distinct: UntrackedDistinct::new(),
            losses: ObservationLosses {
                history_known: true,
                ..ObservationLosses::default()
            },
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
        if add_count(snapshot.losses.oversize, snapshot.losses.retention)? > snapshot.untracked {
            return Err(ProfileDataError::Invalid("observation loss accounting"));
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
            losses: snapshot.losses,
            distinct: UntrackedDistinct::from_snapshot(
                &snapshot.untracked_distinct,
                snapshot.untracked,
            )?,
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
            losses: self.losses,
            untracked_distinct: self.distinct.snapshot(),
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
            None => {
                if let Some((&largest, &evicted)) = self.values.last_key_value()
                    && value < largest
                {
                    let untracked = add_count(self.untracked, evicted)?;
                    self.values.pop_last();
                    self.values.insert(value, 1);
                    self.untracked = untracked;
                    self.distinct.observe(largest);
                } else {
                    self.untracked = add_count(self.untracked, 1)?;
                    self.distinct.observe(value);
                }
            }
        }
        self.total = total;
        Ok(())
    }

    /// Record a validated observation without retaining its literal or sample.
    pub fn observe_unretained(
        &mut self,
        value: ValueId,
        reason: ObservationLoss,
    ) -> Result<(), ProfileDataError> {
        let total = add_count(self.total, 1)?;
        let untracked = add_count(self.untracked, 1)?;
        let count = match reason {
            ObservationLoss::Oversize => &mut self.losses.oversize,
            ObservationLoss::Retention => &mut self.losses.retention,
        };
        *count = add_count(*count, 1)?;
        self.total = total;
        self.untracked = untracked;
        self.distinct.observe(value);
        Ok(())
    }

    #[must_use]
    pub fn untracked_distinct(&self) -> UntrackedDistinctCount {
        self.distinct.count()
    }

    #[must_use]
    pub fn weight(&self, value: ValueId) -> ObservationWeight {
        let observed = self.values.get(&value).copied().unwrap_or(0);
        if !self.losses.history_known {
            ObservationWeight::UnknownHistory {
                observed,
                unassigned: self.untracked,
            }
        } else if self.untracked == 0 {
            ObservationWeight::Exact(observed)
        } else {
            ObservationWeight::LowerBound {
                observed,
                unassigned: self.untracked,
            }
        }
    }

    /// Merge disjoint observations into the same bottom-k literal budget.
    pub fn merge(&self, other: &Self) -> Result<Self, ProfileDataError> {
        if self.capacity != other.capacity {
            return Err(ProfileDataError::Invalid(
                "incompatible literal counter capacities",
            ));
        }
        self.merge_with_capacity(other, self.capacity)
    }

    /// Coarsening retains every known per-value count from disjoint time buckets.
    pub fn coarsen(&self, other: &Self) -> Result<Self, ProfileDataError> {
        let capacity =
            self.capacity
                .checked_add(other.capacity)
                .ok_or(ProfileDataError::LimitExceeded(
                    "coarsened literal capacity",
                ))?;
        self.merge_with_capacity(other, capacity)
    }

    fn merge_with_capacity(&self, other: &Self, capacity: usize) -> Result<Self, ProfileDataError> {
        let total = add_count(self.total, other.total)?;
        let mut merged = Self::new(capacity);
        merged.distinct = self.distinct.merge(&other.distinct);
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
            if let Some((value, count)) = next {
                if merged.values.len() < merged.capacity {
                    tracked = add_count(tracked, count)?;
                    merged.values.insert(value, count);
                } else {
                    merged.distinct.observe(value);
                }
            }
        }
        merged.losses = ObservationLosses {
            oversize: add_count(self.losses.oversize, other.losses.oversize)?,
            retention: add_count(self.losses.retention, other.losses.retention)?,
            history_known: self.losses.history_known && other.losses.history_known,
        };
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
        assert_eq!(merged.snapshot().untracked, 3);
        assert!(matches!(
            merged.weight(value(1)),
            ObservationWeight::LowerBound {
                observed: 3,
                unassigned: 3
            }
        ));
        assert!(matches!(
            merged.weight(value(2)),
            ObservationWeight::LowerBound {
                observed: 2,
                unassigned: 3
            }
        ));
        // Untracked values remain explicitly separate from the retained counts.
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
    fn literal_bottom_k_is_independent_of_delivery_and_partitioning() {
        for capacity in [0, 1, 2, 3] {
            let mut expected = None;
            for order in [
                [1, 2, 3],
                [1, 3, 2],
                [2, 1, 3],
                [2, 3, 1],
                [3, 1, 2],
                [3, 2, 1],
            ] {
                let mut counts = LiteralCounters::new(capacity);
                for number in order {
                    for _ in 0..number {
                        counts.observe(value(number)).unwrap();
                    }
                }
                if let Some(expected) = &expected {
                    assert_eq!(&encoded(&counts), expected);
                } else {
                    expected = Some(encoded(&counts));
                }
            }
            let mut all = LiteralCounters::new(capacity);
            let mut left = LiteralCounters::new(capacity);
            let mut right = LiteralCounters::new(capacity);
            for (index, number) in [3, 1, 2, 1, 2, 3, 1, 2].into_iter().enumerate() {
                all.observe(value(number)).unwrap();
                if index < 4 {
                    left.observe(value(number)).unwrap();
                } else {
                    right.observe(value(number)).unwrap();
                }
            }
            assert_eq!(encoded(&left.merge(&right).unwrap()), encoded(&all));
        }
    }

    #[test]
    fn coarsening_preserves_exact_day_counts_and_is_associative() {
        let mut a = LiteralCounters::new(1);
        let mut b = LiteralCounters::new(1);
        let mut c = LiteralCounters::new(1);
        for _ in 0..1000 {
            a.observe(value(3)).unwrap();
        }
        b.observe(value(1)).unwrap();
        c.observe(value(2)).unwrap();
        let ab = a.coarsen(&b).unwrap();
        assert!(matches!(
            ab.weight(value(3)),
            ObservationWeight::Exact(1000)
        ));
        assert!(matches!(ab.weight(value(1)), ObservationWeight::Exact(1)));
        assert_eq!(
            encoded(&ab.coarsen(&c).unwrap()),
            encoded(&a.coarsen(&b.coarsen(&c).unwrap()).unwrap())
        );
        let mut all = LiteralCounters::new(3);
        for _ in 0..1000 {
            all.observe(value(3)).unwrap();
        }
        for number in [1, 2] {
            all.observe(value(number)).unwrap();
        }
        assert_eq!(encoded(&ab.coarsen(&c).unwrap()), encoded(&all));
    }

    #[test]
    fn counters_reject_corrupt_snapshots_and_bigint_overflow_without_mutation() {
        let snapshot = CounterSnapshot {
            untracked_distinct: UntrackedDistinctSnapshot::default(),
            losses: ObservationLosses {
                history_known: true,
                ..ObservationLosses::default()
            },
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
            untracked_distinct: UntrackedDistinctSnapshot::default(),
            losses: ObservationLosses {
                history_known: true,
                ..ObservationLosses::default()
            },
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
    #[test]
    fn loss_counts_validate_merge_and_preserve_unknown_import_history() {
        let mut a = LiteralCounters::new(1);
        a.observe(value(1)).unwrap();
        a.observe_unretained(value(2), ObservationLoss::Oversize)
            .unwrap();
        let mut b = LiteralCounters::new(1);
        b.observe_unretained(value(2), ObservationLoss::Retention)
            .unwrap();
        let merged = a.coarsen(&b).unwrap();
        let snapshot = merged.snapshot();
        assert_eq!(snapshot.total, 3);
        assert_eq!(snapshot.untracked, 2);
        assert_eq!(snapshot.losses.oversize, 1);
        assert_eq!(snapshot.losses.retention, 1);
        assert!(snapshot.losses.history_known);
        assert!(matches!(
            merged.weight(value(1)),
            ObservationWeight::LowerBound {
                observed: 1,
                unassigned: 2
            }
        ));
        let mut corrupt = snapshot.clone();
        corrupt.losses.retention = 2;
        LiteralCounters::from_snapshot(&corrupt, 2).unwrap_err();
        corrupt.losses.oversize = u64::MAX;
        LiteralCounters::from_snapshot(&corrupt, 2).unwrap_err();
        let mut old = serde_json::to_value(snapshot).unwrap();
        old.as_object_mut().unwrap().remove("losses");
        let imported =
            LiteralCounters::from_snapshot(&serde_json::from_value(old).unwrap(), 2).unwrap();
        assert!(matches!(
            imported.weight(value(1)),
            ObservationWeight::UnknownHistory {
                observed: 1,
                unassigned: 2
            }
        ));
        assert!(
            !imported
                .coarsen(&b)
                .unwrap()
                .snapshot()
                .losses
                .history_known
        );
        let full = CounterSnapshot {
            untracked_distinct: UntrackedDistinctSnapshot::default(),
            total: MAXIMUM_COUNT,
            untracked: MAXIMUM_COUNT,
            values: Box::default(),
            losses: ObservationLosses {
                retention: MAXIMUM_COUNT,
                history_known: true,
                ..ObservationLosses::default()
            },
        };
        let mut full = LiteralCounters::from_snapshot(&full, 1).unwrap();
        let before = encoded(&full);
        full.observe_unretained(value(2), ObservationLoss::Retention)
            .unwrap_err();
        full.observe_unretained(value(2), ObservationLoss::Oversize)
            .unwrap_err();
        assert_eq!(before, encoded(&full));
    }

    #[test]
    fn untracked_distinct_includes_evicted_values_and_losses_without_counting_repeats() {
        let mut counts = LiteralCounters::new(1);
        for _ in 0..10_000 {
            counts.observe(value(3)).unwrap();
        }
        assert_eq!(
            counts.untracked_distinct(),
            UntrackedDistinctCount::Exact(0)
        );
        counts.observe(value(1)).unwrap();
        assert_eq!(
            counts.untracked_distinct(),
            UntrackedDistinctCount::Exact(1)
        );
        counts.observe(value(3)).unwrap();
        assert_eq!(
            counts.untracked_distinct(),
            UntrackedDistinctCount::Exact(1)
        );
        counts
            .observe_unretained(value(2), ObservationLoss::Oversize)
            .unwrap();
        counts
            .observe_unretained(value(2), ObservationLoss::Retention)
            .unwrap();
        assert_eq!(
            counts.untracked_distinct(),
            UntrackedDistinctCount::Exact(2)
        );
        let mut lower = LiteralCounters::new(1);
        lower.observe(value(0)).unwrap();
        assert_eq!(
            counts.merge(&lower).unwrap().untracked_distinct(),
            UntrackedDistinctCount::Exact(3)
        );
        assert_eq!(
            counts.coarsen(&lower).unwrap().untracked_distinct(),
            UntrackedDistinctCount::Exact(2)
        );
        assert_eq!(
            LiteralCounters::from_snapshot(&counts.snapshot(), 1)
                .unwrap()
                .untracked_distinct(),
            counts.untracked_distinct()
        );
    }

    #[test]
    fn old_counter_snapshots_never_acquire_complete_distinct_history() {
        let mut counts = LiteralCounters::new(0);
        counts.observe(value(1)).unwrap();
        let mut json = serde_json::to_value(counts.snapshot()).unwrap();
        json.as_object_mut().unwrap().remove("untracked_distinct");
        let old =
            LiteralCounters::from_snapshot(&serde_json::from_value(json).unwrap(), 0).unwrap();
        assert_eq!(
            old.untracked_distinct(),
            UntrackedDistinctCount::UnknownHistory { at_least: 0 }
        );
        assert_eq!(
            old.merge(&counts).unwrap().untracked_distinct(),
            UntrackedDistinctCount::UnknownHistory { at_least: 1 }
        );
        let mut corrupt = counts.snapshot();
        corrupt.untracked_distinct.values = vec![value(1), value(2)].into();
        LiteralCounters::from_snapshot(&corrupt, 0).unwrap_err();
    }
}
