//! [PRNG] utilities for middleware.
//!
//! This module provides a generic [`Rng`] trait and a [`HasherRng`] that
//! implements the trait based on [`RandomState`] or any other [`Hasher`].
//!
//! [PRNG]: https://en.wikipedia.org/wiki/Pseudorandom_number_generator

use std::{
    collections::hash_map::RandomState,
    hash::{BuildHasher, Hasher},
    ops::Range,
};

/// A simple [PRNG] trait for use within middleware.
///
/// [PRNG]: https://en.wikipedia.org/wiki/Pseudorandom_number_generator
pub trait Rng: Send + Sync + 'static {
    /// Generate a random [`u64`].
    fn next_u64(&mut self) -> u64;

    /// Generate a random [`f64`] between `[0, 1)`.
    fn next_f64(&mut self) -> f64 {
        // Borrowed from:
        // https://github.com/rust-random/rand/blob/master/src/distributions/float.rs#L106
        let float_size = std::mem::size_of::<f64>() as u32 * 8;
        let precision = 52 + 1;
        let scale = 1.0 / ((1u64 << precision) as f64);

        let value = self.next_u64();
        let value = value >> (float_size - precision);

        scale * value as f64
    }

    /// Randomly pick a value within the range.
    ///
    /// # Panic
    ///
    /// - If start < end this will panic in debug mode.
    fn next_range(&mut self, range: Range<u64>) -> u64 {
        debug_assert!(
            range.start < range.end,
            "The range start must be smaller than the end"
        );
        let start = range.start;
        let end = range.end;

        let range = end - start;

        let n = self.next_u64();

        (n % range) + start
    }
}

impl<R: Rng + ?Sized> Rng for Box<R> {
    fn next_u64(&mut self) -> u64 {
        (**self).next_u64()
    }
}

/// A [`Rng`] implementation that uses a [`Hasher`] to generate the random
/// values. The implementation uses an internal counter to pass to the hasher
/// for each iteration of [`Rng::next_u64`].
///
/// # Default
///
/// This hasher has a default type of [`RandomState`] which just uses the
/// libstd method of getting a random u64.
#[derive(Clone, Debug)]
pub struct HasherRng<H = RandomState> {
    hasher: H,
    counter: u64,
}

impl HasherRng {
    /// Create a new default [`HasherRng`].
    pub fn new() -> Self {
        HasherRng::default()
    }
}

impl Default for HasherRng {
    fn default() -> Self {
        HasherRng::with_hasher(RandomState::default())
    }
}

impl<H> HasherRng<H> {
    /// Create a new [`HasherRng`] with the provided hasher.
    pub fn with_hasher(hasher: H) -> Self {
        HasherRng { hasher, counter: 0 }
    }
}

impl<H> Rng for HasherRng<H>
where
    H: BuildHasher + Send + Sync + 'static,
{
    fn next_u64(&mut self) -> u64 {
        let mut hasher = self.hasher.build_hasher();
        hasher.write_u64(self.counter);
        self.counter = self.counter.wrapping_add(1);
        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::*;

    quickcheck! {
        fn next_f64(counter: u64) -> TestResult {
            let mut rng = HasherRng {
                counter,
                ..HasherRng::default()
            };
            let n = rng.next_f64();

            TestResult::from_bool((0.0..1.0).contains(&n))
        }

        fn next_range(counter: u64, range: Range<u64>) -> TestResult {
            if  range.start >= range.end{
                return TestResult::discard();
            }

            let mut rng = HasherRng {
                counter,
                ..HasherRng::default()
            };

            let n = rng.next_range(range.clone());

            TestResult::from_bool(n >= range.start && (n < range.end || range.start == range.end))
        }
    }
}
