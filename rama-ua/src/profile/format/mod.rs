//! Stable canonical identities, versioned archives and legacy profile input.
//!
//! Canonical bytes preserve domain and version independently of Rust layout.
//! Archives retain the evidence needed to recompute analysis; serialized derived
//! results are not trusted when loading them. Only the compiled form, which Rama's
//! own export produces for embedding, carries analysis. Legacy input retains only
//! recorded facts.

pub mod canonical;

pub mod archive;

#[cfg(feature = "embed-profiles")]
#[cfg_attr(docsrs, doc(cfg(feature = "embed-profiles")))]
pub mod compressed;

#[cfg(feature = "embed-profiles")]
#[cfg_attr(docsrs, doc(cfg(feature = "embed-profiles")))]
pub mod compiled;

pub mod input;

pub mod legacy;

/// Typed decoding for inspection and comparison of retained captures.
pub mod decoded;
