//! Deterministic, independently keyed draws for profile selection.

use std::{convert::Infallible, error::Error, fmt, num::NonZeroU64};

use chacha20::{
    ChaCha20Rng,
    rand_core::{SeedableRng as _, TryRng as _},
};
use rama_core::extensions::Extension;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::ValueId;

mod order;
pub use order::OrderDrawError;

mod replay;
pub use replay::*;

mod ticket;
pub use ticket::*;

const DRAW_PREFIX: &[u8] = b"rama-profile-draw\0";

/// Canonical encoding and ChaCha20 stream revision.
pub const PROFILE_DRAW_REVISION: u16 = 1;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Extension)]
#[extension(tags(ua))]
pub struct ProfileSeed(pub [u8; 32]);

impl fmt::Debug for ProfileSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProfileSeed(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Extension)]
#[extension(tags(ua))]
pub struct DrawKey(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum DrawDomain {
    Connection = 1,
    Request = 2,
    Layout = 3,
}

/// Every logical draw is independent of scheduling and other draw consumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProfileDrawContext {
    pub profile: ValueId,
    pub analysis_revision: u16,
    pub scope: ValueId,
    pub key: DrawKey,
    pub domain: DrawDomain,
    pub slot: u64,
}

#[derive(Debug)]
pub struct ProfileDraw {
    stream: ChaCha20Rng,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileDrawError {
    EmptyWeights,
    WeightOverflow,
}

impl fmt::Display for ProfileDrawError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyWeights => f.write_str("profile draw has no positive weight"),
            Self::WeightOverflow => f.write_str("profile draw weight sum overflowed"),
        }
    }
}

impl Error for ProfileDrawError {}

impl ProfileDraw {
    #[must_use]
    pub fn new(seed: ProfileSeed, context: ProfileDrawContext) -> Self {
        let mut digest = Sha256::new();
        digest.update(DRAW_PREFIX);
        digest.update(PROFILE_DRAW_REVISION.to_be_bytes());
        digest.update(seed.0);
        digest.update(context.profile.0);
        digest.update(context.analysis_revision.to_be_bytes());
        digest.update(context.scope.0);
        digest.update(context.key.0);
        digest.update([context.domain as u8]);
        digest.update(context.slot.to_be_bytes());
        Self {
            stream: ChaCha20Rng::from_seed(digest.finalize().into()),
        }
    }

    #[must_use]
    pub fn next_u64(&mut self) -> u64 {
        match self.stream.try_next_u64() {
            Ok(value) => value,
            Err(error) => infallible(error),
        }
    }

    #[must_use]
    pub fn index(&mut self, upper: NonZeroU64) -> u64 {
        sample_below_with(upper, || self.next_u64())
    }

    pub fn weighted_index(&mut self, weights: &[u64]) -> Result<usize, ProfileDrawError> {
        let mut total = 0_u64;
        for weight in weights {
            total = total
                .checked_add(*weight)
                .ok_or(ProfileDrawError::WeightOverflow)?;
        }
        let Some(total) = NonZeroU64::new(total) else {
            return Err(ProfileDrawError::EmptyWeights);
        };
        let selected = self.index(total);
        let mut boundary = 0_u64;
        for (index, weight) in weights.iter().enumerate() {
            boundary += *weight;
            if selected < boundary {
                return Ok(index);
            }
        }
        Err(ProfileDrawError::WeightOverflow)
    }

    pub fn shuffle<T>(&mut self, values: &mut [T]) {
        for index in (1..values.len()).rev() {
            let Some(upper) = NonZeroU64::new(index as u64 + 1) else {
                return;
            };
            let selected = self.index(upper) as usize;
            values.swap(index, selected);
        }
    }
}

fn infallible(error: Infallible) -> ! {
    match error {}
}

fn sample_below_with(upper: NonZeroU64, mut next: impl FnMut() -> u64) -> u64 {
    let upper = upper.get();
    let threshold = upper.wrapping_neg() % upper;
    loop {
        let value = next();
        if value >= threshold {
            return value % upper;
        }
    }
}

#[cfg(test)]
mod tests;
