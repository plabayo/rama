//! `Uri::canonicalize` / `parse_canonical` / `set_host` / `try_set_host`.
//!
//! Tests the RFC 3986 §6.2.2 normalization pipeline end-to-end, plus
//! the semantic-input host setter convenience methods.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::address::{Domain, Host};
use crate::uri::Uri;

// ----------------------------------------------------------------------
// Host promotion: Uninterpreted → typed when possible
// ----------------------------------------------------------------------

#[test]
fn canonicalize_promotes_pct_encoded_ascii_to_domain() {
    let uri = Uri::parse("http://exa%6Dple.com/").unwrap();
    let canonical = uri.canonicalize();
    let host = canonical.host().unwrap();
    assert_eq!(host.to_str(), "example.com");
    assert!(matches!(host.into_owned(), Host::Name(_)));
}

#[cfg(feature = "idna")]
#[test]
fn canonicalize_promotes_raw_utf8_to_ace_domain() {
    let uri = Uri::parse("https://münchen.de/").unwrap();
    let canonical = uri.canonicalize();
    assert_eq!(canonical.host().unwrap().to_str(), "xn--mnchen-3ya.de");
}

#[cfg(feature = "idna")]
#[test]
fn canonicalize_promotes_pct_encoded_utf8_to_ace_domain() {
    // %E4%B8%AD%E6%96%87.com → 中文.com → IDN → xn--…
    let uri = Uri::parse("https://%E4%B8%AD%E6%96%87.com/").unwrap();
    let canonical = uri.canonicalize();
    let host = canonical.host().unwrap().to_str().to_string();
    assert!(host.starts_with("xn--"), "got {host:?}");
    assert!(host.ends_with(".com"), "got {host:?}");
}

#[test]
fn canonicalize_promotes_pct_encoded_to_ipv4() {
    let uri = Uri::parse("http://%31%32%37.0.0.1/").unwrap();
    let canonical = uri.canonicalize();
    let host = canonical.host().unwrap().into_owned();
    assert_eq!(host, Host::Address(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
}

#[test]
fn canonicalize_leaves_sub_delim_host_as_uninterpreted() {
    // `tag,with,commas` is RFC-legal but not DNS-routable. No
    // canonical typed form — must stay Uninterpreted.
    let uri = Uri::parse("http://tag,with,commas/").unwrap();
    let canonical = uri.canonicalize();
    let host = canonical.host().unwrap().into_owned();
    assert!(matches!(host, Host::Uninterpreted(_)));
    assert_eq!(canonical.host().unwrap().to_str(), "tag,with,commas");
}

#[test]
fn canonicalize_leaves_ipvfuture_as_uninterpreted() {
    let uri = Uri::parse("http://[v1.fe80::a]/").unwrap();
    let canonical = uri.canonicalize();
    let host = canonical.host().unwrap().into_owned();
    let u = host.as_uninterpreted().unwrap();
    assert!(u.is_bracketed());
    assert_eq!(canonical.host().unwrap().to_str(), "[v1.fe80::a]");
}

#[test]
fn canonicalize_typed_host_unchanged() {
    // Already-canonical Domain stays Domain; already-canonical IP
    // stays IP. No round-trip surprises.
    let uri = Uri::parse("http://example.com/").unwrap();
    let canonical = uri.canonicalize();
    assert_eq!(canonical.host().unwrap().to_str(), "example.com");

    let uri = Uri::parse("http://127.0.0.1/").unwrap();
    let canonical = uri.canonicalize();
    assert_eq!(canonical.host().unwrap().to_str(), "127.0.0.1");
}

// ----------------------------------------------------------------------
// Pct-encoding normalization in path / query / fragment
// ----------------------------------------------------------------------

#[test]
fn canonicalize_pct_decodes_unreserved_in_path() {
    let uri = Uri::parse("http://example.com/exa%6Dple").unwrap();
    let canonical = uri.canonicalize();
    assert_eq!(canonical.path().unwrap().as_raw_str(), "/example");
}

#[test]
fn canonicalize_pct_keeps_reserved_in_path_uppercased() {
    // `%2f` (`/`) is reserved — stays encoded but uppercases hex.
    let uri = Uri::parse("http://example.com/foo%2fbar").unwrap();
    let canonical = uri.canonicalize();
    assert_eq!(canonical.path().unwrap().as_raw_str(), "/foo%2Fbar");
}

#[test]
fn canonicalize_pct_decodes_unreserved_in_query() {
    let uri = Uri::parse("http://example.com/?key=val%75e").unwrap();
    let canonical = uri.canonicalize();
    assert_eq!(canonical.query().unwrap().as_raw_str(), "key=value");
}

#[test]
fn canonicalize_pct_decodes_unreserved_in_fragment() {
    let uri = Uri::parse("http://example.com/#se%63tion").unwrap();
    let canonical = uri.canonicalize();
    assert_eq!(canonical.fragment().unwrap().as_raw_str(), "section");
}

#[test]
fn canonicalize_pct_no_change_when_already_canonical() {
    let uri = Uri::parse("http://example.com/path?x=1#frag").unwrap();
    let canonical = uri.clone().canonicalize();
    // Display is identical — no bytes moved.
    assert_eq!(canonical.to_string(), uri.to_string());
}

// ----------------------------------------------------------------------
// Default-port drop (RFC 3986 §6.2.3)
// ----------------------------------------------------------------------

#[test]
fn canonicalize_lowercases_uppercase_scheme() {
    // RFC 3986 §6.2.2.1: scheme is case-insensitive; canonical form
    // is lowercase. Known schemes (http, https, …) are already
    // case-normalized at `Protocol` construction. Custom schemes
    // preserve input case at parse time; canonicalize lowercases them.
    let uri = Uri::parse("CUSTOM://example.com/").unwrap();
    let canonical = uri.canonicalize();
    assert_eq!(canonical.scheme().unwrap().as_str(), "custom");
}

#[test]
fn canonicalize_lowercases_known_scheme_even_when_already_canonical() {
    // Sanity: known schemes (HTTP) round-trip cleanly. Parser
    // already lowercases via the `Protocol` enum at parse time, so
    // canonicalize is a no-op here.
    let uri = Uri::parse("HTTPS://example.com/").unwrap();
    let canonical = uri.canonicalize();
    assert_eq!(canonical.scheme().unwrap().as_str(), "https");
}

#[test]
fn canonicalize_drops_http_default_port() {
    let uri = Uri::parse("http://example.com:80/").unwrap();
    let canonical = uri.canonicalize();
    assert_eq!(canonical.port(), None);
    assert_eq!(canonical.to_string(), "http://example.com/");
}

#[test]
fn canonicalize_drops_https_default_port() {
    let uri = Uri::parse("https://example.com:443/").unwrap();
    let canonical = uri.canonicalize();
    assert_eq!(canonical.port(), None);
}

#[test]
fn canonicalize_preserves_non_default_port() {
    let uri = Uri::parse("http://example.com:8080/").unwrap();
    let canonical = uri.canonicalize();
    assert_eq!(canonical.port(), Some(8080));
}

#[test]
fn canonicalize_drops_default_port_only_when_scheme_matches() {
    // `:80` on https — keep, it's not the default for https.
    let uri = Uri::parse("https://example.com:80/").unwrap();
    let canonical = uri.canonicalize();
    assert_eq!(canonical.port(), Some(80));
}

// ----------------------------------------------------------------------
// Empty path → "/" with authority (§6.2.3)
// ----------------------------------------------------------------------

#[test]
fn canonicalize_empty_path_becomes_slash_when_authority_present() {
    let uri = Uri::parse("http://example.com").unwrap();
    let canonical = uri.canonicalize();
    assert_eq!(canonical.path().unwrap().as_raw_str(), "/");
    assert_eq!(canonical.to_string(), "http://example.com/");
}

#[test]
fn canonicalize_empty_path_stays_empty_for_opaque_uri() {
    // `mailto:` has opaque-path semantics, no authority.
    let uri = Uri::parse("mailto:user@example.com").unwrap();
    let canonical = uri.canonicalize();
    // No authority → empty-path rule does not apply.
    assert!(canonical.authority().is_none());
}

// ----------------------------------------------------------------------
// Dot-segment removal (§6.2.2.3)
// ----------------------------------------------------------------------

#[test]
fn canonicalize_removes_dot_segments() {
    let uri = Uri::parse("http://example.com/a/./b/../c").unwrap();
    let canonical = uri.canonicalize();
    assert_eq!(canonical.path().unwrap().as_raw_str(), "/a/c");
}

#[test]
fn canonicalize_clamps_excess_dot_dots_gracefully() {
    let uri = Uri::parse("http://example.com/a/../../b").unwrap();
    let canonical = uri.canonicalize();
    // Graceful clamp at root.
    assert_eq!(canonical.path().unwrap().as_raw_str(), "/b");
}

// ----------------------------------------------------------------------
// `parse_canonical` convenience
// ----------------------------------------------------------------------

#[test]
fn parse_canonical_combines_parse_and_canonicalize() {
    let uri = Uri::parse_canonical("http://exa%6Dple.com:80/foo/./bar").unwrap();
    assert_eq!(uri.host().unwrap().to_str(), "example.com");
    assert_eq!(uri.port(), None);
    assert_eq!(uri.path().unwrap().as_raw_str(), "/foo/bar");
}

#[cfg(feature = "idna")]
#[test]
fn parse_canonical_strict_combines_parse_strict_and_canonicalize() {
    // Strict rejects raw UTF-8 host — would error on münchen, but
    // canonicalize is opt-in normalization on top of strict parsing.
    let uri = Uri::parse_canonical_strict("https://xn--mnchen-3ya.de:443/").unwrap();
    assert_eq!(uri.host().unwrap().to_str(), "xn--mnchen-3ya.de");
    assert_eq!(uri.port(), None);
}

#[test]
fn parse_canonical_propagates_parse_error() {
    // Invalid input — parse fails, no canonicalize attempted.
    Uri::parse_canonical("http://exa%0Dmple.com/").unwrap_err();
}

// ----------------------------------------------------------------------
// Asterisk-form passes through unchanged
// ----------------------------------------------------------------------

#[test]
fn canonicalize_asterisk_is_no_op() {
    let uri = Uri::parse("*").unwrap();
    let canonical = uri.canonicalize();
    assert_eq!(canonical.to_string(), "*");
    assert!(canonical.is_asterisk());
}

// ----------------------------------------------------------------------
// set_host / try_set_host
// ----------------------------------------------------------------------

#[test]
fn set_host_accepts_typed_domain() {
    let mut uri = Uri::parse("http://old.example/").unwrap();
    uri.set_host(Domain::from_static("new.example"));
    assert_eq!(uri.host().unwrap().to_str(), "new.example");
}

#[test]
fn set_host_accepts_ipv4_addr() {
    let mut uri = Uri::parse("http://old.example/").unwrap();
    uri.set_host(Ipv4Addr::new(192, 0, 2, 1));
    assert_eq!(uri.host().unwrap().to_str(), "192.0.2.1");
}

#[test]
fn set_host_accepts_ipv6_addr() {
    let mut uri = Uri::parse("http://old.example/").unwrap();
    uri.set_host(Ipv6Addr::LOCALHOST);
    assert_eq!(uri.host().unwrap().to_str(), "::1");
}

#[test]
fn set_host_accepts_ip_addr() {
    let mut uri = Uri::parse("http://old.example/").unwrap();
    uri.set_host(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(uri.host().unwrap().to_str(), "127.0.0.1");
}

#[test]
fn set_host_accepts_typed_host() {
    let mut uri = Uri::parse("http://old.example/").unwrap();
    uri.set_host(Host::Name(Domain::from_static("typed.example")));
    assert_eq!(uri.host().unwrap().to_str(), "typed.example");
}

#[test]
fn set_host_preserves_port_and_userinfo() {
    let mut uri = Uri::parse("http://user:pass@old.example:8080/path").unwrap();
    uri.set_host(Domain::from_static("new.example"));
    assert_eq!(uri.host().unwrap().to_str(), "new.example");
    assert_eq!(uri.port(), Some(8080));
    assert!(uri.userinfo().is_some());
    assert_eq!(uri.path().unwrap().as_raw_str(), "/path");
}

#[test]
fn set_host_creates_authority_when_absent() {
    // Origin-form URI has no authority — set_host creates one.
    let mut uri = Uri::parse("/just/a/path").unwrap();
    assert!(uri.authority().is_none());
    uri.set_host(Domain::from_static("example.com"));
    assert_eq!(uri.host().unwrap().to_str(), "example.com");
    assert!(uri.userinfo().is_none());
    assert_eq!(uri.port(), None);
}

#[test]
fn with_host_returns_consuming_value() {
    let uri = Uri::parse("http://old.example/")
        .unwrap()
        .with_host(Domain::from_static("new.example"));
    assert_eq!(uri.host().unwrap().to_str(), "new.example");
}

#[test]
fn try_set_host_accepts_str_as_domain() {
    let mut uri = Uri::parse("http://old.example/").unwrap();
    uri.try_set_host("new.example").unwrap();
    assert_eq!(uri.host().unwrap().to_str(), "new.example");
}

#[test]
fn try_set_host_accepts_str_as_ip() {
    let mut uri = Uri::parse("http://old.example/").unwrap();
    uri.try_set_host("127.0.0.1").unwrap();
    assert_eq!(uri.host().unwrap().to_str(), "127.0.0.1");
}

#[cfg(feature = "idna")]
#[test]
fn try_set_host_normalises_idn_to_ace() {
    // The client-side ergonomic the user explicitly asked for —
    // typing "münchen.de" produces a canonical ACE Domain.
    let mut uri = Uri::parse("http://old.example/").unwrap();
    uri.try_set_host("münchen.de").unwrap();
    assert_eq!(uri.host().unwrap().to_str(), "xn--mnchen-3ya.de");
}

#[test]
fn try_set_host_rejects_invalid_input() {
    let mut uri = Uri::parse("http://old.example/").unwrap();
    // Spaces aren't valid in Host. Goes through Host::TryFrom<&str>
    // which tries IP first (fails) then Domain (fails) → Err.
    uri.try_set_host("not a valid host").unwrap_err();
}

#[test]
fn try_set_host_returns_typed_uri_error() {
    use crate::uri::{Component, UriError};
    let mut uri = Uri::parse("http://old.example/").unwrap();
    let err = uri.try_set_host("not a valid host").unwrap_err();
    match err {
        UriError::ComponentConversion { component, cause } => {
            assert_eq!(component, Component::Host);
            // Cause is the boxed upstream `Host::TryFrom` error. The
            // exact wording belongs to the address layer; we just want
            // some non-empty diagnostic so callers can log it.
            assert!(!format!("{cause}").is_empty());
        }
        other => panic!("expected ComponentConversion, got {other:?}"),
    }
}

#[test]
fn try_with_host_consuming_form() {
    let uri = Uri::parse("http://old.example/")
        .unwrap()
        .try_with_host("new.example")
        .unwrap();
    assert_eq!(uri.host().unwrap().to_str(), "new.example");
}

// ----------------------------------------------------------------------
// Idempotence: canonicalize(canonicalize(x)) == canonicalize(x).
//
// Strictly an observable-behaviour test — not a perf assertion. The
// implementation always materialises Owned (no fast-path), so the
// second pass costs the same as the first; the assertion here is just
// that the result is stable.
// ----------------------------------------------------------------------

#[test]
fn canonicalize_is_idempotent() {
    let once = Uri::parse_canonical("http://exa%6Dple.com:80/a/../b").unwrap();
    let twice = once.clone().canonicalize();
    assert_eq!(once.to_string(), twice.to_string());
}

#[test]
fn canonicalize_idempotent_on_clean_input() {
    let once = Uri::parse_canonical("http://example.com/path?a=1#f").unwrap();
    let twice = once.clone().canonicalize();
    assert_eq!(once.to_string(), twice.to_string());
}

// ----------------------------------------------------------------------
// Round-trip: pct-encoded → canonicalize → typed → wire-render
// ----------------------------------------------------------------------

#[test]
fn round_trip_pct_encoded_to_canonical_wire() {
    let uri = Uri::parse_canonical("http://exa%6Dple.com:80/p%61th?k=%76al#fr%61g").unwrap();
    // All unreserved pct sequences decoded; default port dropped;
    // host promoted to typed Domain.
    assert_eq!(uri.to_string(), "http://example.com/path?k=val#frag");
}

// ----------------------------------------------------------------------
// Host case + pct normalization (RFC 3986 §6.2.2.1 + §6.2.2.2)
// ----------------------------------------------------------------------

#[test]
fn canonicalize_lowercases_typed_domain_host() {
    // `Domain` already case-folds for Eq/Hash, but the canonical *render*
    // must lowercase too (RFC 3986 §6.2.2.1).
    let uri = Uri::parse_canonical("HTTP://EXAMPLE.COM/p").unwrap();
    assert_eq!(uri.to_string(), "http://example.com/p");
}

#[test]
fn canonicalize_lowercases_uninterpreted_reg_name() {
    // Sub-delim reg-names stay `Uninterpreted` (no typed canonical form);
    // canonicalize still lowercases the bytes per §6.2.2.1.
    let uri = Uri::parse_canonical("http://TAG,WITH,COMMAS/p").unwrap();
    assert_eq!(uri.to_string(), "http://tag,with,commas/p");
}

#[test]
fn canonicalize_lowercases_bracketed_ipvfuture() {
    // IPvFuture literals also stay `Uninterpreted`; the bracketed body
    // case-folds (FE80 → fe80) while the brackets are re-emitted by
    // Display.
    let uri = Uri::parse_canonical("http://[v1.FE80::A]/p").unwrap();
    assert_eq!(uri.to_string(), "http://[v1.fe80::a]/p");
}

#[test]
fn canonicalize_normalizes_pct_in_uninterpreted_host() {
    // `tag%21,more` — `%21` is sub-delim `!`, must stay encoded;
    // mixed-case input → uppercase-hex output. Host bytes also case-fold.
    let uri = Uri::parse_canonical("http://Tag%21,More/p").unwrap();
    assert_eq!(uri.to_string(), "http://tag%21,more/p");
}

// ----------------------------------------------------------------------
// Combined: every §6.2.2 rule firing on one input
// ----------------------------------------------------------------------

#[test]
fn canonicalize_applies_all_rules_in_one_pass() {
    // Exercises every rule the pipeline implements:
    //   - scheme case (HTTPS → https)
    //   - host promotion (Uninterpreted reg-name → Domain after pct-decode)
    //   - host case (EXa%6Dple.COM → example.com)
    //   - default-port drop (:443 with https)
    //   - dot-segment removal (/a/./b/../c → /a/c)
    //   - pct-decode unreserved on path  (p%61th → path)
    //   - pct-encoded reserved kept uppercased on path (%2f → %2F);
    //     it lives inside one segment, so dot-segment removal does NOT
    //     treat it as a separator
    //   - pct-decode unreserved on query (val%75e → value)
    //   - pct-decode unreserved on fragment (fr%61g → frag)
    let uri =
        Uri::parse_canonical("HTTPS://EXa%6Dple.COM:443/a/./b/../c/p%61th%2fmore?k=val%75e#fr%61g")
            .unwrap();
    assert_eq!(
        uri.to_string(),
        "https://example.com/a/c/path%2Fmore?k=value#frag"
    );
}
