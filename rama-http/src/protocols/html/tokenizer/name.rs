//! Compact, allocation-free hashing of element/tag names.
//!
//! HTML tag names are ASCII case-insensitive, so a name is hashed over its
//! ASCII-lowercased bytes. The hash lets the tokenizer and (later) the
//! tree-builder simulator dispatch on known tags (`script`, `style`, …)
//! with a single integer comparison instead of repeated byte matching.

/// A 64-bit hash of an ASCII-lowercased tag name.
///
/// `0` is reserved to mean "no / empty name". The hash is FNV-1a over the
/// lowercased bytes; the known-tag constants below are verified to be
/// collision-free by a test, which is all the dispatch paths rely on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct LocalNameHash(u64);

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

impl LocalNameHash {
    /// The reserved "no name" hash.
    pub const NONE: Self = Self(0);

    /// Hashes a tag name (ASCII-lowercasing as it goes). Returns
    /// [`Self::NONE`] for an empty name.
    #[must_use]
    pub fn of(name: &[u8]) -> Self {
        if name.is_empty() {
            return Self::NONE;
        }
        let mut hash = FNV_OFFSET;
        for &byte in name {
            hash ^= u64::from(byte.to_ascii_lowercase());
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        Self(hash)
    }

    /// `const` constructor for known-tag constants from a static lowercase
    /// byte string.
    #[must_use]
    pub const fn from_static(name: &'static [u8]) -> Self {
        let mut hash = FNV_OFFSET;
        let mut i = 0;
        while i < name.len() {
            hash ^= name[i] as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
            i += 1;
        }
        Self(hash)
    }

    /// Whether this is the reserved "no name" hash.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }
}
