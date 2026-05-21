//! UTF-8 well-formedness in graceful mode.
//!
//! Graceful mode accepts raw multi-byte UTF-8 in path / query / fragment
//! / userinfo (browsers and curl do too), but every typed accessor
//! derives `&str` via `from_utf8_unchecked`. So the bytes must in fact
//! *be* well-formed UTF-8 — RFC 3629 §4 + Unicode 13 Table 3-7, which
//! also excludes overlong encodings, surrogate code points
//! (U+D800..=U+DFFF), and code points beyond U+10FFFF.
//!
//! Strict mode's byte-set check rejects non-ASCII outright, so these
//! tests target graceful mode (with one strict-mode crossover at the
//! end to pin the layering).

use super::{parse_graceful, parse_graceful_bytes, parse_strict_bytes};
use crate::uri::{ParseError, Uri};

/// Assert a parse fails with `ParseError::NonUtf8` at the expected byte
/// offset. Pinning the offset is stronger than `.is_err()` — a future
/// change that swaps the variant out doesn't silently regress.
#[track_caller]
fn assert_non_utf8(input: &[u8], expected_at: usize) {
    match Uri::parse(input) {
        Err(ParseError::NonUtf8 { at }) => assert_eq!(
            at, expected_at,
            "wrong offset for {input:?}: want {expected_at}, got {at}"
        ),
        other => panic!("expected NonUtf8 for {input:?}, got {other:?}"),
    }
}

#[test]
fn lone_high_byte_in_path_rejected() {
    // `\xFF` is not a valid UTF-8 byte in any position.
    assert_non_utf8(b"/\xff", 1);
}

#[test]
fn lone_continuation_byte_in_path_rejected() {
    // 0x80..=0xBF are continuation bytes; they may not start a sequence.
    assert_non_utf8(b"/\x80", 1);
    assert_non_utf8(b"/\xbf", 1);
}

#[test]
fn truncated_multibyte_sequence_in_path_rejected() {
    // Three-byte lead with only two bytes available.
    assert_non_utf8(b"/\xe2\x82", 1);
    // Four-byte lead with three bytes available.
    assert_non_utf8(b"/\xf0\x9f\x98", 1);
}

#[test]
fn invalid_continuation_byte_rejected() {
    // Lead 0xE2 expects two continuation bytes in 0x80..=0xBF.
    // Second byte 0x7F is below 0x80 — invalid.
    assert_non_utf8(b"/\xe2\x7f\xac", 2);
    // Third byte 0xC0 is above 0xBF — invalid.
    assert_non_utf8(b"/\xe2\x82\xc0", 3);
}

#[test]
fn overlong_encodings_rejected() {
    // U+0000 encoded as the two-byte form `0xC0 0x80` — overlong.
    // 0xC0 isn't a valid lead at all (lookup starts at 0xC2).
    assert_non_utf8(b"/\xc0\x80", 1);
    // U+007F encoded as `0xC1 0xBF` — overlong, 0xC1 also invalid lead.
    assert_non_utf8(b"/\xc1\xbf", 1);
    // U+007F encoded as `0xE0 0x81 0xBF` — overlong 3-byte. Lead 0xE0
    // requires its first continuation in 0xA0..=0xBF; 0x81 fails.
    assert_non_utf8(b"/\xe0\x81\xbf", 2);
    // U+FFFF encoded as `0xF0 0x8F 0xBF 0xBF` — overlong 4-byte. Lead
    // 0xF0 requires its first continuation in 0x90..=0xBF; 0x8F fails.
    assert_non_utf8(b"/\xf0\x8f\xbf\xbf", 2);
}

#[test]
fn surrogate_codepoints_rejected() {
    // U+D800 (low surrogate) encoded as `0xED 0xA0 0x80`. Lead 0xED
    // requires its first continuation in 0x80..=0x9F (not 0xA0..=0xBF),
    // which precisely excludes the surrogate block.
    assert_non_utf8(b"/\xed\xa0\x80", 2);
    // U+DFFF (high surrogate) — `0xED 0xBF 0xBF`. Same exclusion.
    assert_non_utf8(b"/\xed\xbf\xbf", 2);
}

#[test]
fn codepoints_above_u10ffff_rejected() {
    // U+110000 would be `0xF4 0x90 0x80 0x80`. Lead 0xF4 requires its
    // first continuation in 0x80..=0x8F; 0x90 fails.
    assert_non_utf8(b"/\xf4\x90\x80\x80", 2);
    // 0xF5..=0xFF are invalid leads — no code point lives there.
    assert_non_utf8(b"/\xf5\x80\x80\x80", 1);
    assert_non_utf8(b"/\xff\x80\x80\x80", 1);
}

#[test]
fn non_utf8_in_query_and_fragment_rejected() {
    assert_non_utf8(b"/?\xff", 2);
    assert_non_utf8(b"/?k=\xff", 4);
    assert_non_utf8(b"/#\xff", 2);
}

#[test]
fn non_utf8_in_userinfo_rejected() {
    // Userinfo in graceful mode previously had no validation — any
    // userinfo accessor then did `from_utf8_unchecked`. UB.
    parse_graceful_bytes(b"http://\xff@example.com/").unwrap_err();
    parse_graceful_bytes(b"http://user:\xff@example.com/").unwrap_err();
}

#[test]
fn valid_multibyte_sequences_accepted() {
    // Two-byte (ñ = U+00F1).
    parse_graceful_bytes("/ñ".as_bytes()).unwrap();
    // Three-byte (€ = U+20AC; CJK).
    parse_graceful_bytes("/€".as_bytes()).unwrap();
    parse_graceful_bytes("/?key=日本".as_bytes()).unwrap();
    parse_graceful_bytes("/#fragmöng".as_bytes()).unwrap();
    // Four-byte (😀 = U+1F600).
    parse_graceful_bytes("/😀".as_bytes()).unwrap();
    // Mixed ASCII + multi-byte across sections.
    parse_graceful_bytes("/path/€?q=日本#日本".as_bytes()).unwrap();
    // Userinfo with valid UTF-8.
    parse_graceful_bytes("http://üser@example.com/".as_bytes()).unwrap();
}

#[test]
fn strict_mode_rejects_non_ascii_via_byte_set() {
    // Layering pin: strict mode's byte-set check rejects non-ASCII
    // before the UTF-8 validator could ever fire, so the variant is
    // `StrictViolation` rather than `NonUtf8`.
    match parse_strict_bytes("/€".as_bytes()) {
        Err(ParseError::StrictViolation) => {}
        other => panic!("expected StrictViolation, got {other:?}"),
    }
    match parse_strict_bytes(b"/\xff") {
        Err(ParseError::StrictViolation) => {}
        other => panic!("expected StrictViolation, got {other:?}"),
    }
}

#[test]
fn accepted_uris_render_without_ub() {
    // Round-trip sanity: every accepted graceful-mode URI must be safe
    // to call `to_string()` on. If invalid UTF-8 ever slips through,
    // this test panics with a Utf8Error (or worse) rather than silent
    // UB — which is exactly the regression we want to catch.
    let inputs = [
        "/€",
        "/?q=日本",
        "/#frag",
        "http://example.com/€/€?q=日本#日本",
    ];
    for s in &inputs {
        let u: Uri = parse_graceful(s).unwrap();
        let rendered = u.to_string();
        assert!(rendered.contains(s.split('?').next().unwrap_or(s)));
    }
}
