//! Deterministic bottom-k sampling independent of transport and emulation randomness.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::profile::{
    evidence::ingestion::ObservationId,
    format::canonical::{ProfileDataError, ValueId},
};

/// The referenced canonical value contains the whole slot or joint observation.
/// Joint values are never reconstructed from independently sampled slots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReservoirEntry {
    pub observation: ObservationId,
    pub priority: [u8; 32],
    pub value: ValueId,
}

impl ReservoirEntry {
    fn key(&self) -> ([u8; 32], ObservationId) {
        (self.priority, self.observation)
    }
}

/// Apply insertion/removal to the value interner in the same counting transaction.
#[derive(Debug)]
pub enum ReservoirUpdate {
    Unchanged,
    Inserted { removed: Option<ReservoirEntry> },
}

/// Capacity bounds entry count. The value interner independently bounds payload bytes.
/// Counting and duplicate admission belong to the enclosing ingestion transaction.
#[derive(Debug, Clone)]
pub struct ObservationReservoir {
    capacity: usize,
    seed: [u8; 32],
    scope: ValueId,
    entries: Vec<ReservoirEntry>,
}

impl ObservationReservoir {
    #[must_use]
    pub fn new(capacity: usize, seed: [u8; 32], scope: ValueId) -> Self {
        Self {
            capacity,
            seed,
            scope,
            entries: Vec::new(),
        }
    }

    /// A scope identifies the structural bucket and slot or complete joint tuple.
    /// The sampler seed and scope remain constant across its day buckets.
    fn priority(&self, observation: ObservationId) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"rama-profile-sample\0\0\x01");
        hash.update(self.scope.0);
        hash.update(self.seed);
        hash.update(observation.run);
        hash.update(observation.sequence.to_be_bytes());
        hash.finalize().into()
    }

    /// Validate persisted priorities and canonical ordering before retaining entries.
    pub fn from_entries(
        capacity: usize,
        seed: [u8; 32],
        scope: ValueId,
        entries: &[ReservoirEntry],
    ) -> Result<Self, ProfileDataError> {
        if entries.len() > capacity {
            return Err(ProfileDataError::LimitExceeded("reservoir entries"));
        }
        let mut value = Self::new(capacity, seed, scope);
        let mut previous = None;
        for entry in entries {
            if entry.observation.sequence == 0
                || value.priority(entry.observation) != entry.priority
            {
                return Err(ProfileDataError::Invalid("reservoir priority"));
            }
            if previous.is_some_and(|key| key >= entry.key()) {
                return Err(ProfileDataError::Invalid("reservoir entry ordering"));
            }
            previous = Some(entry.key());
        }
        value.entries.extend_from_slice(entries);
        Ok(value)
    }

    #[must_use]
    pub fn entries(&self) -> &[ReservoirEntry] {
        &self.entries
    }

    /// Admit through the run checkpoint before updating counts or sampling.
    /// Repeating an evicted ID cannot be detected by a bounded reservoir alone.
    pub fn observe(
        &mut self,
        observation: ObservationId,
        value: ValueId,
    ) -> Result<ReservoirUpdate, ProfileDataError> {
        if observation.sequence == 0 {
            return Err(ProfileDataError::Invalid("zero ingestion sequence"));
        }
        let entry = ReservoirEntry {
            observation,
            priority: self.priority(observation),
            value,
        };
        let index = match self
            .entries
            .binary_search_by_key(&entry.key(), ReservoirEntry::key)
        {
            Ok(index) => {
                if self.entries[index].value != value {
                    return Err(ProfileDataError::Invalid(
                        "observation identity reused for another value",
                    ));
                }
                return Ok(ReservoirUpdate::Unchanged);
            }
            Err(index) => index,
        };
        if index >= self.capacity {
            return Ok(ReservoirUpdate::Unchanged);
        }
        let removed = if self.entries.len() == self.capacity {
            self.entries.pop()
        } else {
            None
        };
        self.entries.insert(index, entry);
        Ok(ReservoirUpdate::Inserted { removed })
    }

    /// Retained entries under another scope's priorities, as if sampled there.
    pub(in crate::profile) fn rescoped(&self, scope: ValueId) -> Result<Self, ProfileDataError> {
        let mut rescoped = Self::new(self.capacity, self.seed, scope);
        for entry in &self.entries {
            rescoped.observe(entry.observation, entry.value)?;
        }
        Ok(rescoped)
    }

    /// Keep only the `len` highest-priority entries.
    pub(in crate::profile) fn truncate(&mut self, len: usize) {
        self.entries.truncate(len);
    }

    /// Merge disjoint retained day buckets by priority. Counts are merged separately.
    /// Equal IDs must reference the same complete observation in both inputs.
    pub fn merge(&self, other: &Self) -> Result<Self, ProfileDataError> {
        if self.capacity != other.capacity || self.seed != other.seed || self.scope != other.scope {
            return Err(ProfileDataError::Invalid("incompatible reservoirs"));
        }
        let mut merged = Self::new(self.capacity, self.seed, self.scope);
        let mut left = self.entries.iter().peekable();
        let mut right = other.entries.iter().peekable();
        loop {
            let next = match (left.peek(), right.peek()) {
                (Some(a), Some(b)) if a.key() == b.key() => {
                    if a.value != b.value {
                        return Err(ProfileDataError::Invalid(
                            "observation identity reused for another value",
                        ));
                    }
                    right.next();
                    left.next()
                }
                (Some(a), Some(b)) if a.key() < b.key() => left.next(),
                (_, Some(_)) => right.next(),
                (Some(_), None) => left.next(),
                (None, None) => break,
            };
            if let Some(entry) = next
                && merged.entries.len() < merged.capacity
            {
                merged.entries.push(entry.clone());
            }
        }
        Ok(merged)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn observation(sequence: u64) -> ObservationId {
        ObservationId {
            run: [3; 16],
            sequence,
        }
    }
    fn value(sequence: u64) -> ValueId {
        ValueId(Sha256::digest(sequence.to_be_bytes()).into())
    }
    fn encoded(reservoir: &ObservationReservoir) -> Vec<u8> {
        serde_json::to_vec(reservoir.entries()).unwrap()
    }

    #[test]
    fn reservoir_is_bounded_and_independent_of_delivery_order() {
        let scope = ValueId([2; 32]);
        let mut forward = ObservationReservoir::new(256, [1; 32], scope);
        let mut reverse = forward.clone();
        for sequence in 1..=10_000 {
            forward
                .observe(observation(sequence), value(sequence))
                .unwrap();
            reverse
                .observe(observation(10_001 - sequence), value(10_001 - sequence))
                .unwrap();
            assert!(forward.entries().len() <= 256);
            assert!(reverse.entries().len() <= 256);
        }
        assert_eq!(forward.entries().len(), 256);
        assert_eq!(encoded(&forward), encoded(&reverse));
        let ids: BTreeSet<_> = forward
            .entries()
            .iter()
            .map(|entry| entry.observation)
            .collect();
        assert_eq!(ids.len(), 256);
        let restored =
            ObservationReservoir::from_entries(256, [1; 32], scope, forward.entries()).unwrap();
        assert_eq!(encoded(&forward), encoded(&restored));
        let mut disabled = ObservationReservoir::new(0, [1; 32], scope);
        disabled.observe(observation(1), value(1)).unwrap();
        assert!(disabled.entries().is_empty());
    }

    #[test]
    fn reservoir_merge_matches_one_pass_and_preserves_complete_joint_values() {
        let scope = ValueId([2; 32]);
        let mut all = ObservationReservoir::new(32, [1; 32], scope);
        let mut a = all.clone();
        let mut b = all.clone();
        for sequence in 1..=10_000 {
            // One value ID addresses the complete (A,X) or (B,Y) tuple.
            let tuple = value(sequence % 2);
            all.observe(observation(sequence), tuple).unwrap();
            if sequence % 2 == 0 {
                a.observe(observation(sequence), tuple).unwrap();
            } else {
                b.observe(observation(sequence), tuple).unwrap();
            }
        }
        let merged = a.merge(&b).unwrap();
        assert_eq!(encoded(&all), encoded(&merged));
        assert_eq!(encoded(&all), encoded(&b.merge(&a).unwrap()));
        for entry in merged.entries() {
            assert_eq!(entry.value, value(entry.observation.sequence % 2));
        }
        assert_eq!(encoded(&all), encoded(&all.merge(&all).unwrap()));
    }

    #[test]
    fn reservoir_rejects_corrupt_snapshots_and_conflicting_ids_atomically() {
        let scope = ValueId([2; 32]);
        let mut reservoir = ObservationReservoir::new(2, [1; 32], scope);
        reservoir.observe(observation(1), value(1)).unwrap();
        reservoir.observe(observation(2), value(2)).unwrap();
        let before = encoded(&reservoir);
        reservoir.observe(observation(1), value(9)).unwrap_err();
        reservoir.observe(observation(0), value(0)).unwrap_err();
        assert_eq!(before, encoded(&reservoir));
        let mut single = vec![reservoir.entries()[0].clone()];
        single[0].priority[31] ^= 1;
        ObservationReservoir::from_entries(2, [1; 32], scope, &single).unwrap_err();
        let mut entries = reservoir.entries().to_vec();
        entries[0].priority[0] ^= 1;
        ObservationReservoir::from_entries(2, [1; 32], scope, &entries).unwrap_err();
        ObservationReservoir::from_entries(1, [1; 32], scope, reservoir.entries()).unwrap_err();
        entries = reservoir.entries().to_vec();
        entries.reverse();
        ObservationReservoir::from_entries(2, [1; 32], scope, &entries).unwrap_err();
        entries = vec![reservoir.entries()[0].clone(); 2];
        ObservationReservoir::from_entries(2, [1; 32], scope, &entries).unwrap_err();
        let mut other = reservoir.clone();
        other.entries[0].value = value(99);
        reservoir.merge(&other).unwrap_err();
        assert_eq!(before, encoded(&reservoir));
        for other in [
            ObservationReservoir::new(1, [1; 32], scope),
            ObservationReservoir::new(2, [9; 32], scope),
            ObservationReservoir::new(2, [1; 32], ValueId([9; 32])),
        ] {
            reservoir.merge(&other).unwrap_err();
        }
    }
    #[test]
    fn reservoir_priority_has_owned_encoding_and_scope_separation() {
        let scope = ValueId([2; 32]);
        let base = ObservationReservoir::new(8, [1; 32], scope);
        let priority = base.priority(observation(7));
        assert_eq!(
            priority,
            [
                166, 188, 215, 196, 164, 192, 225, 51, 138, 132, 131, 105, 242, 158, 174, 137, 239,
                36, 152, 243, 174, 31, 9, 235, 115, 55, 117, 253, 24, 173, 37, 64
            ]
        );
        assert_ne!(priority, base.priority(observation(8)));
        let mut another_run = observation(7);
        another_run.run[0] = 4;
        assert_ne!(priority, base.priority(another_run));
        assert_ne!(
            priority,
            ObservationReservoir::new(8, [9; 32], scope).priority(observation(7))
        );
        assert_ne!(
            priority,
            ObservationReservoir::new(8, [1; 32], ValueId([9; 32])).priority(observation(7))
        );
    }
}
