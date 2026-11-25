use core::{cmp::Ordering, ops::Range};

use rama_utils::collections::smallvec::SmallVec;

/// A set of u64 values optimized for long runs and random insert/delete/contains
///
/// `ArrayRangeSet` uses an array representation, where each array entry represents
/// a range.
///
/// The array-based RangeSet provides 2 benefits:
/// - There exists an inline representation, which avoids the need of heap
///   allocating ACK ranges for SentFrames for small ranges.
/// - Iterating over ranges should usually be faster since there is only
///   a single cache-friendly contiguous range.
///
/// `ArrayRangeSet` is especially useful for tracking ACK ranges where the amount
/// of ranges is usually very low (since ACK numbers are in consecutive fashion
/// unless reordering or packet loss occur).
#[derive(Debug, Default)]
pub struct ArrayRangeSet(SmallVec<[Range<u64>; ARRAY_RANGE_SET_INLINE_CAPACITY]>);

/// The capacity of elements directly stored in [`ArrayRangeSet`]
///
/// An inline capacity of 2 is chosen to keep `SentFrame` below 128 bytes.
const ARRAY_RANGE_SET_INLINE_CAPACITY: usize = 2;

impl Clone for ArrayRangeSet {
    fn clone(&self) -> Self {
        // Clones (e.g. for storage in `SentFrames`) are rarely mutated, so prefer the inline
        // representation whenever the current length fits, even if the original had spilled.
        Self(self.0.iter().cloned().collect())
    }
}

impl ArrayRangeSet {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = Range<u64>> + '_ {
        self.0.iter().cloned()
    }

    pub fn elts(&self) -> impl Iterator<Item = u64> + '_ {
        self.iter().flatten()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this set contains the given value.
    pub fn contains(&self, x: u64) -> bool {
        self.0
            .binary_search_by(|range| {
                if range.end <= x {
                    Ordering::Less
                } else if x < range.start {
                    Ordering::Greater
                } else {
                    Ordering::Equal
                }
            })
            .is_ok()
    }

    #[cfg(test)]
    pub fn subtract(&mut self, other: &Self) {
        // TODO: This can potentially be made more efficient, since the we know
        // individual ranges are not overlapping, and the next range must start
        // after the last one finished
        for range in &other.0 {
            self.remove(range.clone());
        }
    }

    pub fn insert_one(&mut self, x: u64) -> bool {
        self.insert(x..x + 1)
    }

    pub fn insert(&mut self, x: Range<u64>) -> bool {
        let mut result = false;

        if x.is_empty() {
            // Don't try to deal with ranges where x.end <= x.start
            return false;
        }

        // Strict comparison keeps a range ending exactly at `x.start` in view so it merges
        let idx = self.0.partition_point(|r| r.end < x.start);

        let Some(range) = self.0.get_mut(idx) else {
            self.0.push(x);
            return true;
        };

        if x.end < range.start {
            // The new range ends before this range and therefore cannot extend it
            self.0.insert(idx, x);
            return true;
        }
        if range.start > x.start {
            // The range before `idx` ends before `x.start`, so only this range extends left
            result = true;
            range.start = x.start;
        }

        if x.end <= range.end {
            // Fully contained
            return result;
        }

        // `partition_point` guarantees `x.start <= range.end`, so this range absorbs `x`
        range.end = x.end;

        // Absorb every following range that starts at or before the new end
        let merge_end = idx + 1 + self.0[idx + 1..].partition_point(|r| r.start <= x.end);
        if merge_end > idx + 1 {
            self.0[idx].end = x.end.max(self.0[merge_end - 1].end);
            self.0.drain(idx + 1..merge_end);
        }

        true
    }

    pub fn remove(&mut self, x: Range<u64>) -> bool {
        let mut result = false;

        if x.is_empty() {
            // Don't try to deal with ranges where x.end <= x.start
            return false;
        }

        // Inclusive comparison: a range ending at `x.start` is untouched by the removal
        let mut idx = self.0.partition_point(|r| r.end <= x.start);

        while idx != self.0.len() {
            let range = self.0[idx].clone();

            if x.end <= range.start {
                // The range is fully before this range
                return result;
            }

            // The range overlaps with this range
            result = true;

            let left = range.start..x.start;
            let right = x.end..range.end;
            if left.is_empty() && right.is_empty() {
                self.0.remove(idx);
            } else if left.is_empty() {
                self.0[idx] = right;
                idx += 1;
            } else if right.is_empty() {
                self.0[idx] = left;
                idx += 1;
            } else {
                self.0[idx] = right;
                self.0.insert(idx, left);
                idx += 2;
            }
        }

        result
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn pop_min(&mut self) -> Option<Range<u64>> {
        if !self.0.is_empty() {
            Some(self.0.remove(0))
        } else {
            None
        }
    }

    #[cfg(test)]
    pub fn min(&self) -> Option<u64> {
        self.iter().next().map(|x| x.start)
    }

    pub fn max(&self) -> Option<u64> {
        self.iter().next_back().map(|x| x.end - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_storage_and_clone() {
        let mut set = ArrayRangeSet::new();
        assert!(set.insert(0..1));
        assert!(set.insert(5..6));
        assert!(!set.0.spilled(), "two ranges fit inline");
        assert!(set.insert(10..11));
        assert!(set.0.spilled(), "a third range spills to the heap");
        assert!(set.remove(10..11));
        assert!(set.0.spilled(), "shrinking keeps the heap allocation");
        let clone = set.clone();
        assert!(
            !clone.0.spilled(),
            "clones use inline storage when the length fits"
        );
        assert_eq!(
            clone.iter().collect::<Vec<_>>(),
            set.iter().collect::<Vec<_>>()
        );
        let big = {
            let mut set = ArrayRangeSet::new();
            for i in 0..4u64 {
                set.insert(i * 3..i * 3 + 1);
            }
            set
        };
        let clone = big.clone();
        assert!(clone.0.spilled());
        assert_eq!(clone.len(), big.len());
    }

    #[test]
    fn stays_small_for_sent_frames() {
        // Two inline `Range<u64>` plus the length word: 48 bytes on 64-bit targets, which keeps
        // `SentFrames` compact (below 128 bytes)
        assert!(
            size_of::<ArrayRangeSet>() <= 2 * size_of::<Range<u64>>() + 2 * size_of::<usize>(),
            "{}",
            size_of::<ArrayRangeSet>()
        );
    }
}
