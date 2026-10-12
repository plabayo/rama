//! Compact, allocation-free identities of element/tag names.
//!
//! HTML tag names are ASCII case-insensitive, so a name is identified by its
//! ASCII-lowercased bytes. Almost every tag name is short ASCII, and those
//! are packed into the identity itself, so equal identities prove equal
//! names and the tokenizer, the tree builder and selectors compare names as
//! integers. Longer (or non-ASCII) names fall back to a 64-bit hash, whose
//! hits are confirmed on the name bytes, since a crafted name can share any
//! such hash.

/// The identity of an ASCII-lowercased tag name.
///
/// `0` is reserved to mean "no / empty name". A name of at most 8 bytes, all
/// ASCII and none NUL, is its own lowercased bytes packed little-endian
/// ([`is_exact`](Self::is_exact)): equal values prove equal names. Any other
/// name is an FNV-1a hash of its lowercased bytes with the top bit set, which
/// is not collision resistant: compare the names themselves before acting on
/// a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct LocalNameHash(u64);

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Marks a hashed (non-exact) identity; packed bytes never set it.
const HASHED: u64 = 1 << 63;

/// Longest name packed exactly.
const PACKED_LEN: usize = 8;

const LANES: u64 = 0x0101_0101_0101_0101;

/// ASCII-lowercases the bytes packed in `x` (each below `0x80`), all lanes at
/// once.
const fn lower_packed(x: u64) -> u64 {
    // A lane's top bit is set iff its byte is at least `A` / beyond `Z`; no
    // lane overflows into the next, as every byte is below `0x80`.
    let at_least_a = x.wrapping_add(LANES * (0x80 - b'A' as u64));
    let beyond_z = x.wrapping_add(LANES * (0x80 - b'Z' as u64 - 1));
    let upper = at_least_a & !beyond_z & (LANES * 0x80);
    x | (upper >> 2)
}

/// Whether `b` may be packed: ASCII and not NUL (NUL is the padding).
const fn packable(b: u8) -> bool {
    b.wrapping_sub(1) < 0x7f
}

impl LocalNameHash {
    /// The reserved "no name" identity.
    pub const NONE: Self = Self(0);

    /// The identity of a tag name (ASCII-lowercasing as it goes). Returns
    /// [`Self::NONE`] for an empty name.
    #[must_use]
    #[inline]
    pub fn of(name: &[u8]) -> Self {
        if name.len() <= PACKED_LEN {
            let mut packed = 0u64;
            let mut exact = true;
            for (i, &b) in name.iter().enumerate() {
                exact &= packable(b);
                packed |= u64::from(b) << (8 * i);
            }
            if exact {
                return Self(lower_packed(packed));
            }
        }
        Self::hashed(name)
    }

    #[cold]
    fn hashed(name: &[u8]) -> Self {
        let mut hash = FNV_OFFSET;
        for &byte in name {
            hash ^= u64::from(byte.to_ascii_lowercase());
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        Self(hash | HASHED)
    }

    /// `const` constructor for known-tag constants from a static lowercase
    /// byte string; agrees with [`Self::of`].
    #[must_use]
    pub const fn from_static(name: &'static [u8]) -> Self {
        let mut i = 0;
        let mut exact = name.len() <= PACKED_LEN;
        while i < name.len() {
            // The static must already be lowercase: `of` lowercases, this does
            // not, so an uppercase byte here would give a different identity.
            debug_assert!(!name[i].is_ascii_uppercase());
            exact = exact && packable(name[i]);
            i += 1;
        }
        let mut value = 0;
        i = 0;
        if exact {
            while i < name.len() {
                value |= (name[i] as u64) << (8 * i);
                i += 1;
            }
        } else {
            value = FNV_OFFSET;
            while i < name.len() {
                value ^= name[i] as u64;
                value = value.wrapping_mul(FNV_PRIME);
                i += 1;
            }
            value |= HASHED;
        }
        Self(value)
    }

    /// Whether this is the reserved "no name" identity.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == 0
    }

    /// Whether this identity is the (lowercased) name itself, so that equal
    /// identities prove equal names. Otherwise it is a hash of the name.
    #[must_use]
    #[inline]
    pub const fn is_exact(self) -> bool {
        self.0 != 0 && self.0 & HASHED == 0
    }

    /// The raw value, for matching against known-tag constants (a `u64`
    /// `match` lowers to a switch / binary search, unlike a struct compare).
    pub(crate) const fn as_u64(self) -> u64 {
        self.0
    }

    /// Whether the tag named `name` with this identity is the `known`
    /// (lowercase) name with identity `known_id`.
    #[inline]
    pub(crate) fn names(self, name: &[u8], known_id: Self, known: &[u8]) -> bool {
        self == known_id && (known_id.is_exact() || name.eq_ignore_ascii_case(known))
    }
}

/// A known tag name: its identity rejects other names cheaply, its bytes
/// confirm a hit on a hashed (long) identity.
#[derive(Debug, Clone, Copy)]
pub(crate) struct KnownName {
    hash: LocalNameHash,
    name: &'static [u8],
}

impl KnownName {
    /// `name` must be ASCII lowercase.
    pub(crate) const fn new(name: &'static [u8]) -> Self {
        Self {
            hash: LocalNameHash::from_static(name),
            name,
        }
    }

    /// Whether the tag named `name` (with identity `hash`) is this one.
    #[inline]
    pub(crate) fn is(self, hash: LocalNameHash, name: &[u8]) -> bool {
        hash.names(name, self.hash, self.name)
    }
}

/// A set of known tag names, kept as parallel lists so the identities
/// reject most names in one tight pass; a hashed hit is confirmed on the
/// bytes.
#[derive(Debug)]
pub(crate) struct KnownNames<const N: usize> {
    hashes: [LocalNameHash; N],
    names: [&'static [u8]; N],
}

impl<const N: usize> KnownNames<N> {
    /// The names must be ASCII lowercase.
    pub(crate) const fn new(names: [&'static [u8]; N]) -> Self {
        let mut hashes = [LocalNameHash::NONE; N];
        let mut i = 0;
        while i < N {
            hashes[i] = LocalNameHash::from_static(names[i]);
            i += 1;
        }
        Self { hashes, names }
    }

    /// Whether the tag named `name` (with identity `hash`) is in the set.
    #[inline]
    pub(crate) fn contains(&self, hash: LocalNameHash, name: &[u8]) -> bool {
        self.hashes
            .iter()
            .position(|&known| known == hash)
            .and_then(|i| self.names.get(i))
            .is_some_and(|known| hash.is_exact() || name.eq_ignore_ascii_case(known))
    }
}

#[cfg(test)]
mod tests {
    use ahash::HashMap;
    use quickcheck::{QuickCheck, TestResult};

    use super::{KnownName, KnownNames, LocalNameHash};

    #[test]
    fn case_insensitive_and_const_agreement() {
        assert_eq!(LocalNameHash::of(b"DIV"), LocalNameHash::of(b"div"));
        assert_eq!(LocalNameHash::of(b"ScRiPt"), LocalNameHash::of(b"script"));
        for name in [
            &b"script"[..],
            b"a",
            b"textarea",
            b"plaintext",
            b"annotation-xml",
            b"x-never-present",
            b"h1",
            b"\x7f",
        ] {
            assert_eq!(LocalNameHash::of(name), LocalNameHash::from_static(name));
        }
        assert!(LocalNameHash::of(b"").is_none());
        assert!(!LocalNameHash::of(b"div").is_none());
        assert!(!LocalNameHash::of(b"").is_exact());
    }

    /// Short ASCII names are exact; long, NUL-carrying or non-ASCII ones are
    /// hashed, and the two spaces never meet.
    #[test]
    fn exactness_follows_length_and_bytes() {
        for (name, exact) in [
            (&b"a"[..], true),
            (b"textarea", true),
            (b"TEXTAREA", true),
            (b"x-a-b-c-", true),
            (b"plaintext", false),
            (b"a\0", false),
            (b"\xc3\xa9", false),
            (b"\x7f", true),
        ] {
            assert_eq!(LocalNameHash::of(name).is_exact(), exact, "{name:?}");
        }
    }

    /// Equal exact identities are equal names; every identity is case
    /// insensitive; exactness depends on the name only.
    #[test]
    fn exact_identities_are_lossless() {
        #[expect(
            clippy::needless_pass_by_value,
            reason = "quickcheck generates owned inputs"
        )]
        fn prop(a: Vec<u8>, b: Vec<u8>) -> TestResult {
            let (ha, hb) = (LocalNameHash::of(&a), LocalNameHash::of(&b));
            let exact = a.len() <= 8 && a.iter().all(|&c| (1..0x80).contains(&c));
            if ha.is_exact() != (exact && !a.is_empty()) {
                return TestResult::failed();
            }
            if LocalNameHash::of(&a.to_ascii_uppercase()) != ha {
                return TestResult::failed();
            }
            if ha.is_exact() && ha == hb && !a.eq_ignore_ascii_case(&b) {
                return TestResult::failed();
            }
            if ha.is_exact() != hb.is_exact() && ha == hb {
                return TestResult::failed();
            }
            TestResult::passed()
        }
        QuickCheck::new()
            .tests(10_000)
            .quickcheck(prop as fn(Vec<u8>, Vec<u8>) -> TestResult);
        // Short names, so that equal identities actually come up.
        fn short(a: u32, b: u32) -> TestResult {
            let name = |n: u32| -> Vec<u8> {
                n.to_le_bytes()
                    .into_iter()
                    .take_while(|&c| c != 0)
                    .map(|c| b"aAbB\x7f-1"[usize::from(c % 7)])
                    .collect()
            };
            let (a, b) = (name(a), name(b));
            let same = LocalNameHash::of(&a) == LocalNameHash::of(&b);
            TestResult::from_bool(same == a.eq_ignore_ascii_case(&b))
        }
        QuickCheck::new()
            .tests(10_000)
            .quickcheck(short as fn(u32, u32) -> TestResult);
    }

    /// Hashing every distinct (lowercased) name across the full 1-3 ASCII-
    /// letter space plus longer real tags is collision-free, so the identity
    /// alone rejects nearly every name before a byte comparison.
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

    /// A hashed (long) name sharing a known tag's hash is told apart on the
    /// bytes; exact identities need no confirmation.
    #[test]
    fn known_name_confirms_hashed_hits() {
        let script = KnownName::new(b"script");
        assert!(script.is(LocalNameHash::of(b"SCRIPT"), b"SCRIPT"));
        assert!(!script.is(LocalNameHash::of(b"div"), b"script"));
        let plaintext = KnownName::new(b"plaintext");
        assert!(plaintext.is(LocalNameHash::of(b"PlainText"), b"PlainText"));
        // A crafted 64-bit FNV collision with a long known name.
        assert!(!plaintext.is(LocalNameHash::of(b"plaintext"), b"plaintexx"));
        let names = KnownNames::new([b"b", b"div", b"foreignobject"]);
        assert!(names.contains(LocalNameHash::of(b"DIV"), b"DIV"));
        assert!(names.contains(LocalNameHash::of(b"foreignObject"), b"foreignObject"));
        assert!(!names.contains(LocalNameHash::of(b"foreignobject"), b"foreignobjecx"));
        assert!(!names.contains(LocalNameHash::of(b"span"), b"span"));
    }
}
