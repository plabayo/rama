//! Exact aggregate counts and bounded literal counters with explicit coverage.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::profile::{
    evidence::{UntrackedDistinctCount, UntrackedDistinctSnapshot, distinct::UntrackedDistinct},
    format::canonical::{ProfileDataError, ValueId},
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

    pub(in crate::profile) fn unknown_history(capacity: usize) -> Self {
        let mut value = Self::new(capacity);
        value.losses.history_known = false;
        value.distinct = UntrackedDistinct::unknown_history();
        value
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

    pub(in crate::profile) fn value_ids(&self) -> impl Iterator<Item = ValueId> + '_ {
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

    pub(in crate::profile) fn merge_with_capacity(
        &self,
        other: &Self,
        capacity: usize,
    ) -> Result<Self, ProfileDataError> {
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
mod tests;
