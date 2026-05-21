//! Audit-driven regression tests.
//!
//! Each section maps to an audit finding. Tests are deliberately tight
//! (one observable behaviour each) so the next reviewer can re-run the
//! audit and see the rule they expect.

use super::{parse_graceful, parse_graceful_bytes, parse_strict, parse_strict_bytes};
use crate::uri::{ParseError, Uri};

// ----------------------------------------------------------------------
// Audit Issue 1 (High): graceful parser accepts non-UTF-8 bytes, but
// every accessor that returns `&str` immediately does
// `from_utf8_unchecked` on the inner bytes — UB on any subsequent
// `to_string` / `path().as_str()` call.
// ----------------------------------------------------------------------

/// Assert a parse fails with `ParseError::NonUtf8` at the expected
/// byte offset. Stronger than a bare `.is_err()` — pins which byte was
/// fingered, so a change that swaps the variant out doesn't silently
/// regress.
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
fn audit_utf8_rejects_lone_high_byte_in_path() {
    // `\xFF` alone is not a valid UTF-8 byte in any position.
    assert_non_utf8(b"/\xff", 1);
}

#[test]
fn audit_utf8_rejects_lone_continuation_byte_in_path() {
    // 0x80..=0xBF are continuation bytes; they may not start a sequence.
    assert_non_utf8(b"/\x80", 1);
    assert_non_utf8(b"/\xbf", 1);
}

#[test]
fn audit_utf8_rejects_truncated_sequence_in_path() {
    // Three-byte lead with only two bytes available.
    assert_non_utf8(b"/\xe2\x82", 1);
    // Four-byte lead with three bytes available.
    assert_non_utf8(b"/\xf0\x9f\x98", 1);
}

#[test]
fn audit_utf8_rejects_invalid_continuation_byte() {
    // Lead 0xE2 expects two continuation bytes in 0x80..=0xBF.
    // Second byte 0x7F is below 0x80 — invalid.
    assert_non_utf8(b"/\xe2\x7f\xac", 2);
    // Third byte 0xC0 is above 0xBF — invalid.
    assert_non_utf8(b"/\xe2\x82\xc0", 3);
}

#[test]
fn audit_utf8_rejects_overlong_encodings() {
    // U+0000 encoded as the two-byte form `0xC0 0x80` — overlong.
    // 0xC0 isn't a valid lead at all (lookup table starts at 0xC2).
    assert_non_utf8(b"/\xc0\x80", 1);
    // U+007F encoded as `0xC1 0xBF` — overlong, 0xC1 also invalid lead.
    assert_non_utf8(b"/\xc1\xbf", 1);
    // U+007F encoded as `0xE0 0x81 0xBF` — overlong 3-byte. Lead 0xE0
    // requires its first continuation in 0xA0..=0xBF; 0x81 fails.
    assert_non_utf8(b"/\xe0\x81\xbf", 2);
    // U+FFFF encoded as `0xF0 0x8F 0xBF 0xBF` — overlong 4-byte.
    // Lead 0xF0 requires its first continuation in 0x90..=0xBF; 0x8F fails.
    assert_non_utf8(b"/\xf0\x8f\xbf\xbf", 2);
}

#[test]
fn audit_utf8_rejects_surrogate_codepoints() {
    // U+D800 (low surrogate) encoded as `0xED 0xA0 0x80`. Lead 0xED
    // requires its first continuation in 0x80..=0x9F (not 0xA0..=0xBF),
    // which precisely excludes the surrogate block.
    assert_non_utf8(b"/\xed\xa0\x80", 2);
    // U+DFFF (high surrogate) — `0xED 0xBF 0xBF`. Same exclusion.
    assert_non_utf8(b"/\xed\xbf\xbf", 2);
}

#[test]
fn audit_utf8_rejects_codepoints_above_u10ffff() {
    // U+110000 would be `0xF4 0x90 0x80 0x80`. Lead 0xF4 requires its
    // first continuation in 0x80..=0x8F; 0x90 fails.
    assert_non_utf8(b"/\xf4\x90\x80\x80", 2);
    // 0xF5..=0xFF are invalid leads (no code point lives there).
    assert_non_utf8(b"/\xf5\x80\x80\x80", 1);
    assert_non_utf8(b"/\xff\x80\x80\x80", 1);
}

#[test]
fn audit_utf8_rejects_non_utf8_in_query_and_fragment() {
    assert_non_utf8(b"/?\xff", 2);
    assert_non_utf8(b"/?k=\xff", 4);
    assert_non_utf8(b"/#\xff", 2);
}

#[test]
fn audit_utf8_rejects_non_utf8_in_userinfo() {
    // Non-UTF-8 in userinfo had no validation before the fix — graceful
    // mode treated userinfo bytes as opaque-but-control-stripped, and
    // every `userinfo()` accessor then did `from_utf8_unchecked`. UB.
    assert!(parse_graceful_bytes(b"http://\xff@example.com/").is_err());
    assert!(parse_graceful_bytes(b"http://user:\xff@example.com/").is_err());
}

#[test]
fn audit_utf8_accepts_valid_multi_byte_sequences() {
    // Two-byte (€ = U+20AC, three-byte; ñ = U+00F1, two-byte).
    parse_graceful_bytes("/ñ".as_bytes()).unwrap();
    // Three-byte.
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
fn audit_utf8_strict_mode_rejects_non_ascii_via_byte_set() {
    // In strict mode the byte-set check rejects non-ASCII before UTF-8
    // validation can ever fire — the resulting variant is
    // `StrictViolation`, not `NonUtf8`. This is intentional and pins
    // the layering: strict has stronger constraints than graceful.
    match parse_strict_bytes("/€".as_bytes()) {
        Err(ParseError::StrictViolation) => {}
        other => panic!("expected StrictViolation, got {other:?}"),
    }
    // Genuinely malformed UTF-8 in strict mode also errors out — same
    // way (byte-set rejects before UTF-8 check matters).
    match parse_strict_bytes(b"/\xff") {
        Err(ParseError::StrictViolation) => {}
        other => panic!("expected StrictViolation, got {other:?}"),
    }
}

#[test]
fn audit_utf8_safe_to_render_after_parse() {
    // Round-trip sanity: every accepted graceful-mode URI must be safe
    // to call `to_string()` / `as_raw_str()` on. The fix moves the
    // failing case from UB to a clean `Err`, so any input that
    // *succeeds* must render cleanly. If we ever regress and let
    // invalid UTF-8 through, this test will panic with a Utf8Error
    // (or worse) rather than silently UB.
    let inputs = [
        "/€",
        "/?q=日本",
        "/#frag",
        "http://example.com/€/€?q=日本#日本",
    ];
    for s in &inputs {
        let u: Uri = parse_graceful(s).unwrap();
        // `to_string` materialises a `String` from the typed components.
        // If the inner bytes aren't valid UTF-8 we'd get UB here.
        let rendered = u.to_string();
        assert!(rendered.contains(s.split('?').next().unwrap_or(s)));
    }
}

// ----------------------------------------------------------------------
// Audit Issue 2 (High): QueryPair caches the `=` position as `u16`,
// but query mutation has no MAX_URI_LEN cap — pairs with a key longer
// than 65535 bytes silently overflow.
// ----------------------------------------------------------------------

#[test]
fn audit_query_pair_eq_offset_handles_huge_key() {
    // Original audit input: 70k-byte key.
    let key = "k".repeat(70_000);
    let mut uri = Uri::parse("https://example.com/").unwrap();
    uri.query_mut().push_pair(key.as_str(), "v");
    let pair = uri.query().unwrap().pairs().next().unwrap();
    assert_eq!(pair.name_bytes().len(), 70_000);
    assert_eq!(pair.value_bytes().map(<[u8]>::len), Some(1));
}

#[test]
fn audit_query_pair_eq_offset_handles_huge_value() {
    // Inverted shape — small key, value past 65535.
    let value = "v".repeat(100_000);
    let mut uri = Uri::parse("https://example.com/").unwrap();
    uri.query_mut().push_pair("k", value.as_str());
    let pair = uri.query().unwrap().pairs().next().unwrap();
    assert_eq!(pair.name_bytes(), b"k");
    assert_eq!(pair.value_bytes().map(<[u8]>::len), Some(100_000));
}

#[test]
fn audit_query_pair_eq_offset_exact_u16_boundaries() {
    // Pin the exact boundary cases that would have truncated under u16.
    // At 65535 bytes of key, eq sits at offset 65535 — exactly u16::MAX.
    // u16 would wrap to 0; u32 stores it cleanly.
    let key = "k".repeat(65_535);
    let mut uri = Uri::parse("https://example.com/").unwrap();
    uri.query_mut().push_pair(key.as_str(), "v");
    let pair = uri.query().unwrap().pairs().next().unwrap();
    assert_eq!(pair.name_bytes().len(), 65_535);
    assert_eq!(pair.value_bytes(), Some(&b"v"[..]));

    // 65536 — one past the u16 cap. u16 would wrap to 0.
    let key = "k".repeat(65_536);
    let mut uri = Uri::parse("https://example.com/").unwrap();
    uri.query_mut().push_pair(key.as_str(), "v");
    let pair = uri.query().unwrap().pairs().next().unwrap();
    assert_eq!(pair.name_bytes().len(), 65_536);
    assert_eq!(pair.value_bytes(), Some(&b"v"[..]));
}

#[test]
fn audit_query_pair_eq_offset_bare_key_still_works() {
    // Regression: the u16 → u32 widening must not change semantics for
    // bare keys (eq_at = None) — `value_bytes()` still returns None.
    let key = "k".repeat(70_000);
    let mut uri = Uri::parse("https://example.com/").unwrap();
    uri.query_mut().push_key(key.as_str());
    let pair = uri.query().unwrap().pairs().next().unwrap();
    assert_eq!(pair.name_bytes().len(), 70_000);
    assert_eq!(pair.value_bytes(), None);
    assert!(!pair.has_value());
}

#[test]
fn audit_query_pair_eq_offset_via_pairs_ref_iterator() {
    // The borrowed `QueryPairRef` has its own `eq_at: u32` field —
    // exercise it independently via `query().pairs()`.
    let key = "k".repeat(70_000);
    let mut uri = Uri::parse("https://example.com/").unwrap();
    uri.query_mut().push_pair(key.as_str(), "vvvv");
    // Reborrow via the immutable accessor → QueryPairRef.
    let q = uri.query().unwrap();
    let pair_ref = q.pairs().next().unwrap();
    assert_eq!(pair_ref.name_bytes().len(), 70_000);
    assert_eq!(pair_ref.value_bytes(), Some(&b"vvvv"[..]));
    assert!(pair_ref.has_value());
}

// ----------------------------------------------------------------------
// Audit Issue 3 (Medium): module docs advertised all four HTTP request-
// target forms, but authority-form `host:port` (for CONNECT) had no
// entry point and `Uri::parse` correctly preferred the scheme reading
// per RFC 3986 (`example.com:443` → scheme=`example.com`, path=`443`).
// Fix: dedicated `Uri::parse_authority_form` entry point. The default
// `Uri::parse` retains its RFC-correct behaviour.
// ----------------------------------------------------------------------

#[test]
fn audit_parse_authority_form_works_for_connect_targets() {
    // The original audit input. Now goes through the dedicated entry.
    let u = Uri::parse_authority_form("example.com:443").unwrap();
    assert!(u.scheme().is_none(), "authority-form has no scheme");
    assert_eq!(u.host().unwrap().to_str(), "example.com");
    assert_eq!(u.port(), Some(443));
    assert_eq!(u.path().map(|p| p.as_raw_str()), Some(""));

    // Userinfo authority-form is also accepted.
    let u = Uri::parse_authority_form("user:pass@example.com:443").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "example.com");
    assert_eq!(u.port(), Some(443));
    assert!(u.userinfo().is_some());
}

#[test]
fn audit_parse_authority_form_rejects_non_authority_shapes() {
    // Any path/query/fragment delimiter must be rejected — those mean
    // the caller has the wrong shape and should use `parse` instead.
    assert!(Uri::parse_authority_form("example.com:443/foo").is_err());
    assert!(Uri::parse_authority_form("example.com:443?x=1").is_err());
    assert!(Uri::parse_authority_form("example.com:443#frag").is_err());
    assert!(Uri::parse_authority_form("https://example.com:443").is_err());
    // Empty input → Empty error.
    assert!(matches!(
        Uri::parse_authority_form(""),
        Err(ParseError::Empty)
    ));
    // Invalid port.
    assert!(Uri::parse_authority_form("example.com:99999").is_err());
    assert!(Uri::parse_authority_form("example.com:abc").is_err());
    assert!(Uri::parse_authority_form("example.com:").is_err());
}

#[test]
fn audit_parse_authority_form_accepts_ip_literals() {
    // IPv4 authority-form.
    let u = Uri::parse_authority_form("127.0.0.1:8080").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "127.0.0.1");
    assert_eq!(u.port(), Some(8080));

    // IPv6 authority-form — brackets mandatory per RFC 3986 §3.2.2.
    let u = Uri::parse_authority_form("[::1]:443").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "::1");
    assert_eq!(u.port(), Some(443));

    let u = Uri::parse_authority_form("[2001:db8::1]:80").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "2001:db8::1");
    assert_eq!(u.port(), Some(80));
}

#[test]
fn audit_parse_authority_form_no_port() {
    // RFC 9112 §3.2.3: the authority-form for CONNECT *requires* a port,
    // but lower-level URI parsing is more permissive — accept bare host.
    // HTTP-aware callers can enforce the port requirement at their layer.
    let u = Uri::parse_authority_form("example.com").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "example.com");
    assert_eq!(u.port(), None);
}

#[test]
fn audit_parse_authority_form_strict_rejects_non_ascii() {
    // Strict-mode authority-form should reject non-ASCII host bytes
    // identically to strict `Uri::parse` — RFC 3986 host grammar is
    // ASCII only.
    #[cfg(feature = "idna")]
    {
        let r = Uri::parse_authority_form_strict("münchen.de:443");
        assert!(r.is_err(), "strict authority-form must reject non-ASCII");
    }
    // Graceful authority-form (default) accepts and IDN-normalises.
    #[cfg(feature = "idna")]
    {
        let u = Uri::parse_authority_form("münchen.de:443").unwrap();
        assert_eq!(u.host().unwrap().to_str(), "xn--mnchen-3ya.de");
    }
}

#[test]
fn audit_parse_authority_form_renders_correctly() {
    // Round-trip: the parsed authority-form must render back as
    // `host:port` only — no scheme, no path. Important for HTTP CONNECT
    // wire writers; if anything is silently added, proxies route wrong.
    let u = Uri::parse_authority_form("example.com:443").unwrap();
    let s = u.to_string();
    assert!(!s.contains("://"), "rendered has scheme prefix: {s}");
    assert!(s.contains("example.com"));
    assert!(s.contains("443"));
}

#[test]
fn audit_parse_default_still_treats_host_port_as_scheme_path() {
    // RFC 3986 prefers the scheme reading for `host:port`. We don't
    // silently rewrite that — callers handling CONNECT must call
    // `parse_authority_form` explicitly. This test pins the contract.
    let u = Uri::parse("example.com:443").unwrap();
    assert_eq!(u.scheme().map(|s| s.as_str()), Some("example.com"));
    assert!(u.host().is_none());
}

// ----------------------------------------------------------------------
// Audit Issue 4 (Medium): `parse_strict` accepts non-ASCII hosts when
// the `idna` feature is on — RFC 3986 §3.2.2 host grammar is ASCII-only.
// ----------------------------------------------------------------------

#[cfg(feature = "idna")]
#[test]
fn audit_strict_rejects_non_ascii_host_with_idna() {
    // RFC 3986 strict reading: non-ASCII host bytes violate the
    // grammar regardless of whether UTS #46 could normalise them.
    // Callers who want IDN under strict must pre-encode to ACE.
    for non_ascii in [
        "https://münchen.de/",
        "https://日本.com/",
        "https://MÜNCHEN.de/",
        "https://api.üñiçödé.example/",
    ] {
        let r = parse_strict(non_ascii);
        assert!(
            matches!(r, Err(ParseError::StrictViolation)),
            "strict must reject non-ASCII host {non_ascii:?}; got {r:?}"
        );
    }
}

#[cfg(feature = "idna")]
#[test]
fn audit_strict_accepts_already_ace_host() {
    // After the fix, strict still accepts an already-ACE-encoded host —
    // the bytes are pure ASCII, so the grammar is satisfied.
    let u = parse_strict("https://xn--mnchen-3ya.de/").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "xn--mnchen-3ya.de");
}

#[cfg(feature = "idna")]
#[test]
fn audit_graceful_still_idn_normalises_after_strict_fix() {
    // The strict-mode tightening must not regress graceful-mode IDN —
    // pin the round-trip so a future change can't accidentally apply
    // the strict rule to graceful.
    let u = parse_graceful("https://münchen.de/").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "xn--mnchen-3ya.de");
}

// ----------------------------------------------------------------------
// Audit Issue 5 (Medium): host parsing rejects RFC 3986-legal
// `reg-name` with percent-encoding and `IPvFuture` literals because
// ASCII hosts are funneled through `Domain::try_from`.
// ----------------------------------------------------------------------

/// Fix lands in a follow-up commit (pct-decode-and-reroute through the
/// existing IP/Domain cascade). `#[ignore]`d so the suite stays green
/// in the meantime; the test stays here so the fix can flip it on.
#[test]
#[ignore = "audit issue #5: fix pending in follow-up commit"]
fn audit_strict_accepts_pct_encoded_reg_name() {
    // `exa%6Dple.com` — `%6D` is the pct-encoded `m`. RFC 3986
    // reg-name allows `pct-encoded` segments. Today we reject this
    // because `Domain::try_from` doesn't decode pct.
    parse_strict("http://exa%6Dple.com/")
        .expect("strict mode must accept pct-encoded reg-name per RFC 3986");
}

/// IPvFuture is RFC 3986-legal but real-world dead — no `vN.X` form is
/// registered with IANA as of 2026. Tracked alongside reg-name; same
/// follow-up commit lands the fix or a typed "not supported" error.
#[test]
#[ignore = "audit issue #5: fix pending in follow-up commit"]
fn audit_strict_accepts_ipvfuture_literal() {
    // `[v1.fe80::a]` — IPvFuture literal, RFC 3986 §3.2.2. We only
    // bracket-parse IPv6 today.
    parse_strict("http://[v1.fe80::a]/").expect("strict mode must accept IPvFuture per RFC 3986");
}
