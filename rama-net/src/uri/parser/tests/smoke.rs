//! Structured smoke tests — feed *targeted* byte patterns to the parser
//! and assert it never panics, never overflows, never UB.
//!
//! These are NOT fuzzing. Real fuzzing happens via the cargo-fuzz target
//! at [`fuzz/fuzz_targets/uri_parse.rs`] which runs coverage-guided
//! mutation in CI. This file is a deterministic regression net: every
//! pattern here is a category we want to be sure the parser handles —
//! when fuzzing finds a new crash class, the minimised case lands here.
//!
//! Each test must:
//! - never `panic!`, `unwrap` a `None`, or trigger UB
//! - parse the byte sequence (or return a typed [`ParseError`])

use super::{parse_graceful_bytes, parse_graceful_static, parse_strict_bytes, parse_strict_static};
use crate::uri::parser::MAX_URI_LEN;

/// Both modes must terminate cleanly on any input.
fn assert_no_panic(bytes: &[u8]) {
    drop(parse_graceful_bytes(bytes));
    drop(parse_strict_bytes(bytes));
}

/// Zero-copy variant for static literals.
fn assert_no_panic_static(bytes: &'static [u8]) {
    drop(parse_graceful_static(bytes));
    drop(parse_strict_static(bytes));
}

// ----------------------------------------------------------------------
// Uniform byte fills
// ----------------------------------------------------------------------

#[test]
fn all_zero_bytes_no_panic() {
    for len in [0, 1, 2, 16, 256, 4096] {
        assert_no_panic(&vec![0u8; len]);
    }
}

#[test]
fn all_high_bytes_no_panic() {
    for len in [0, 1, 2, 16, 256, 4096] {
        assert_no_panic(&vec![0xFFu8; len]);
    }
}

#[test]
fn all_single_byte_no_panic() {
    // Every byte value as a single-byte input. Exhaustive.
    for b in 0u8..=0xFFu8 {
        assert_no_panic(&[b]);
    }
}

#[test]
fn all_single_byte_long_no_panic() {
    // Every byte value, repeated to 128 bytes.
    for b in 0u8..=0xFFu8 {
        assert_no_panic(&[b; 128]);
    }
}

// ----------------------------------------------------------------------
// Delimiter-heavy patterns
// ----------------------------------------------------------------------

#[test]
fn delimiter_storms_no_panic() {
    for chunk in [
        b"////////".as_slice(),
        b"????????",
        b"########",
        b"@@@@@@@@",
        b"::::::::",
        b"%%%%%%%%",
        b"[[[[[[[[",
        b"]]]]]]]]",
        b"...........",
        b"+++++++",
        b"---",
    ] {
        for prefix in [b"".as_slice(), b"/", b"http://", b"http://example.com/"] {
            let mut buf = Vec::with_capacity(prefix.len() + chunk.len() * 4);
            buf.extend_from_slice(prefix);
            for _ in 0..4 {
                buf.extend_from_slice(chunk);
            }
            assert_no_panic(&buf);
        }
    }
}

#[test]
fn percent_encoded_garbage_no_panic() {
    // `%` followed by varied garbage. Exercises the percent-escape
    // validator's bounds checking. All inputs are static literals.
    for pattern in [
        b"/%".as_slice(),
        b"/%0",
        b"/%00",
        b"/%%%",
        b"/%aZ",
        b"/foo%bar",
        b"/%2",
        b"/%%2",
        b"/%%2F",
        b"/%2F%",
        b"http://example.com/%",
        b"http://example.com/%2",
        b"/p?%",
        b"/p#%",
    ] {
        assert_no_panic_static(pattern);
    }
}

// ----------------------------------------------------------------------
// Length boundary patterns
// ----------------------------------------------------------------------

#[test]
fn length_boundary_no_panic() {
    // Around 0, around MAX_URI_LEN, and a couple of intermediate sizes.
    for &len in &[
        0_usize,
        1,
        2,
        128,
        4096,
        MAX_URI_LEN - 1,
        MAX_URI_LEN,
        MAX_URI_LEN + 1,
        u16::MAX as usize,
        u16::MAX as usize + 1,
    ] {
        // Filled with `a` (valid path byte) so the parser walks the full
        // length when shorter than the cap.
        assert_no_panic(&vec![b'a'; len]);
        // With a `/` prefix to force the origin-form path.
        let mut buf = vec![b'/'];
        buf.extend(std::iter::repeat_n(b'a', len.saturating_sub(1)));
        assert_no_panic(&buf);
    }
}

// ----------------------------------------------------------------------
// Authority-shaped garbage
// ----------------------------------------------------------------------

#[test]
fn authority_garbage_no_panic() {
    for s in [
        b"http://".as_slice(),
        b"http://:",
        b"http://@",
        b"http://@:",
        b"http://[",
        b"http://[]",
        b"http://[]:",
        b"http://[]/",
        b"http://[]:80",
        b"http://[::",
        b"http://]/",
        b"http://:80/",
        b"http://x:99999999999999/",
        b"http://a@b@c@d/",
        b"http://a:b:c:d:e:f:g:h:i:j:k/",
    ] {
        assert_no_panic_static(s);
    }
}
