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
            // The static must already be lowercase: `of` lowercases, this does
            // not, so an uppercase byte here would hash to a different value.
            debug_assert!(!name[i].is_ascii_uppercase());
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

#[cfg(test)]
mod tests {
    use ahash::HashMap;

    use super::LocalNameHash;

    #[test]
    fn case_insensitive_and_const_agreement() {
        assert_eq!(LocalNameHash::of(b"DIV"), LocalNameHash::of(b"div"));
        assert_eq!(LocalNameHash::of(b"ScRiPt"), LocalNameHash::of(b"script"));
        assert_eq!(
            LocalNameHash::of(b"script"),
            LocalNameHash::from_static(b"script")
        );
        assert!(LocalNameHash::of(b"").is_none());
        assert!(!LocalNameHash::of(b"div").is_none());
    }

    /// Hashing every distinct (lowercased) name across the full 1-3 ASCII-
    /// letter space plus longer real tags must be collision-free: dispatch and
    /// the rewriter's open-element matching compare names by hash alone.
    #[test]
    fn names_are_collision_free() {
        let mut seen: HashMap<u64, Vec<u8>> = HashMap::default();
        let mut check = |name: &[u8]| {
            let hash = LocalNameHash::of(name);
            if let Some(prev) = seen.insert(hash.0, name.to_vec())
                && !prev.eq_ignore_ascii_case(name)
            {
                panic!("collision: {prev:?} vs {name:?}");
            }
        };

        for a in b'a'..=b'z' {
            check(&[a]);
            for b in b'a'..=b'z' {
                check(&[a, b]);
                for c in b'a'..=b'z' {
                    check(&[a, b, c]);
                }
            }
        }
        for tag in [
            b"blockquote".as_slice(),
            b"figcaption",
            b"foreignobject",
            b"plaintext",
            b"textarea",
            b"template",
            b"noscript",
            b"optgroup",
        ] {
            check(tag);
        }
    }
}
