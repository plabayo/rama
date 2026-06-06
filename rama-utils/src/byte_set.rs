//! `const` builders for `[bool; 256]` byte-set lookup tables.
//!
//! A lookup table turns a byte-class predicate into a single branchless
//! load, which beats a `match` / compare-chain on hot per-byte paths (URI
//! validation, HTML tokenizing, …) and is deterministic across compilers.
//! Build the table once at `const` time, then index it by `byte as usize`.
//!
//! Reach for a table only for *irregular* byte sets on a hot path: a simple
//! range such as `b < 0x80` is one compare and should stay a comparison.

/// Mark every byte in the half-open range `[lo, hi_exclusive)` as `true`.
#[must_use]
pub const fn set_range(mut table: [bool; 256], lo: u8, hi_exclusive: u8) -> [bool; 256] {
    let mut i = lo;
    while i < hi_exclusive {
        table[i as usize] = true;
        i += 1;
    }
    table
}

/// Mark every byte present in `bytes` as `true`.
#[must_use]
pub const fn set_each(mut table: [bool; 256], bytes: &[u8]) -> [bool; 256] {
    let mut i = 0;
    while i < bytes.len() {
        table[bytes[i] as usize] = true;
        i += 1;
    }
    table
}

/// Mark the ASCII alpha bytes (`A-Z`, `a-z`) as `true`.
#[must_use]
pub const fn set_ascii_alpha(table: [bool; 256]) -> [bool; 256] {
    let table = set_range(table, b'A', b'Z' + 1);
    set_range(table, b'a', b'z' + 1)
}

/// Mark the ASCII alphanumeric bytes (`0-9`, `A-Z`, `a-z`) as `true`.
#[must_use]
pub const fn set_ascii_alphanum(table: [bool; 256]) -> [bool; 256] {
    set_range(set_ascii_alpha(table), b'0', b'9' + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_and_members() {
        const T: [bool; 256] = set_each(set_range([false; 256], b'0', b'9' + 1), b"+-");
        assert!(T[b'0' as usize] && T[b'9' as usize]);
        assert!(T[b'+' as usize] && T[b'-' as usize]);
        assert!(!T[b'a' as usize] && !T[b'/' as usize]);
    }

    #[test]
    fn ascii_classes() {
        const ALPHA: [bool; 256] = set_ascii_alpha([false; 256]);
        const ALNUM: [bool; 256] = set_ascii_alphanum([false; 256]);
        assert!(ALPHA[b'A' as usize] && ALPHA[b'z' as usize] && !ALPHA[b'0' as usize]);
        assert!(ALNUM[b'0' as usize] && ALNUM[b'Z' as usize] && !ALNUM[b'_' as usize]);
    }
}
