//! Counts, samples and retention for observed client behaviour.
//!
//! [`ProfileEvidence`] is the retained input to analysis. Collection and storage
//! share bounded counting and sampling primitives; ingestion checkpoints make
//! transaction retries idempotent. Retention applies to both counts and samples.

use self::window::RetainedBucketsSnapshot;
use crate::profile::format::canonical::CanonicalValue;
use serde::{Deserialize, Serialize};

pub mod collector;

pub mod counts;

pub mod bucket;

pub mod reservoir;

mod distinct;
pub use distinct::{UntrackedDistinctCount, UntrackedDistinctSnapshot};

pub mod window;

pub mod ingestion;

pub mod transaction;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Retained counts and samples for one ownership scope.
pub struct ProfileScopeEvidence {
    pub scope: CanonicalValue,
    pub flow: Option<CanonicalValue>,
    pub structure: CanonicalValue,
    pub window: RetainedBucketsSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Versioned retained observations for one client profile.
pub struct ProfileEvidence {
    pub format_version: u16,
    pub profile: CanonicalValue,
    pub scopes: Box<[ProfileScopeEvidence]>,
}
