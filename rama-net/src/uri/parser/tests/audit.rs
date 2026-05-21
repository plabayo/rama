//! Tests that demonstrate audit-found behaviours. These start RED — each
//! `#[ignore]` lifts as the matching fix lands. Listed here so the fixes
//! and their regression tests live in the same place.

use super::{parse_graceful_bytes, parse_strict};
use crate::uri::Uri;

// ----------------------------------------------------------------------
// Audit Issue 1 (High): graceful parser accepts non-UTF-8 bytes, but
// every accessor that returns `&str` immediately does
// `from_utf8_unchecked` on the inner bytes — UB on any subsequent
// `to_string` / `path().as_str()` call.
// ----------------------------------------------------------------------

#[test]
fn audit_graceful_rejects_non_utf8_path() {
    // The original audit input: `/\xFF`. `\xFF` is not a UTF-8
    // continuation byte and not the first byte of any UTF-8 sequence,
    // so the whole input is invalid UTF-8. After the fix, graceful
    // mode rejects this; before the fix, it parsed successfully and
    // any `as_str()` / `to_string()` was UB.
    assert!(
        parse_graceful_bytes(b"/\xff").is_err(),
        "graceful mode must reject non-UTF-8 bytes in the path"
    );
    // Same for query and fragment.
    assert!(parse_graceful_bytes(b"/?\xff").is_err());
    assert!(parse_graceful_bytes(b"/#\xff").is_err());
    // Lone continuation byte (also invalid UTF-8).
    assert!(parse_graceful_bytes(b"/\x80").is_err());
    // Truncated multi-byte (3-byte char with only 2 bytes).
    assert!(parse_graceful_bytes(b"/\xe2\x82").is_err());
}

#[test]
fn audit_graceful_still_accepts_valid_utf8_path() {
    // Sanity: the fix must not regress valid multi-byte UTF-8.
    // `€` = E2 82 AC, three-byte UTF-8.
    parse_graceful_bytes("/€".as_bytes()).expect("valid utf-8 path must still parse");
    parse_graceful_bytes("/?key=日本".as_bytes()).expect("valid utf-8 query must still parse");
    parse_graceful_bytes("/#fragmöng".as_bytes()).expect("valid utf-8 fragment must still parse");
}

// ----------------------------------------------------------------------
// Audit Issue 2 (High): QueryPair caches the `=` position as `u16`,
// but query mutation has no MAX_URI_LEN cap — pairs with a key longer
// than 65535 bytes silently overflow.
// ----------------------------------------------------------------------

#[test]
fn audit_query_pair_eq_offset_handles_large_pairs() {
    // Build a single `huge_key=huge_value` pair larger than 65535 bytes.
    // After the fix the eq offset must be reported correctly; before
    // the fix it wraps to a small number and `value_bytes()` returns
    // the wrong slice.
    let key = "k".repeat(70_000);
    let value = "v".repeat(2);
    let mut uri = Uri::parse("https://example.com/").unwrap();
    {
        let mut qm = uri.query_mut();
        qm.push_pair(key.as_str(), value.as_str());
    }
    let q = uri.query().expect("query present");
    let pair = q.pairs().next().expect("at least one pair");
    assert_eq!(pair.name_bytes().len(), 70_000, "key length must match");
    assert_eq!(
        pair.value_bytes().map(<[u8]>::len),
        Some(2),
        "value length must match"
    );
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
    let r = parse_strict("https://münchen.de/");
    assert!(
        r.is_err(),
        "strict mode must reject non-ASCII host; got {r:?}"
    );
    // ACE form must still pass strict.
    parse_strict("https://xn--mnchen-3ya.de/").expect("strict must accept already-ACE host");
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
