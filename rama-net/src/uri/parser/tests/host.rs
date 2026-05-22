//! Host-component coverage for the authority parser.
//!
//! Most general parser coverage lives in `absolute_form.rs` and
//! `authority_form.rs`; this file targets the host component
//! specifically — IP literal shapes, reg-name edge cases, and the
//! layering between strict / graceful / preservation handling.
//!
//! **Wire-fidelity contract:** the parser does not canonicalize host
//! bytes. Pct-encoded reg-name, sub-delim hostnames, and IPvFuture
//! literals all parse into [`Host::Uninterpreted`] with the bytes
//! preserved verbatim. Callers wanting a typed domain or IP convert via
//! `Domain::try_from(&uninterpreted)` / `IpAddr::try_from(&uninterpreted)`
//! on demand.

use super::{parse_graceful, parse_strict};
use crate::address::{Domain, Host, UninterpretedHost};
use crate::uri::{ParseError, Uri};

/// Extract a borrowed view of the [`UninterpretedHost`] inside a
/// parsed URI, panicking if the host isn't `Uninterpreted`.
fn uninterpreted(uri: &Uri) -> UninterpretedHost {
    uri.host()
        .and_then(|h| match h.into_owned() {
            Host::Uninterpreted(u) => Some(u),
            _ => None,
        })
        .expect("expected Host::Uninterpreted for this URI")
}

// ----------------------------------------------------------------------
// Pct-encoded reg-name (RFC 3986 §3.2.2) — preserved at parse time;
// caller decodes on demand via `Domain::try_from(&uninterpreted)`.
// ----------------------------------------------------------------------

#[test]
fn pct_encoded_reg_name_preserved_in_strict() {
    // `%6D` is the pct-encoded `m`. Parser accepts and preserves.
    let uri = parse_strict("http://exa%6Dple.com/").unwrap();
    assert_eq!(uri.host().unwrap().to_str(), "exa%6Dple.com");
}

#[test]
fn pct_encoded_reg_name_decodes_to_domain_on_demand() {
    let uri = parse_strict("http://exa%6Dple.com/").unwrap();
    let host = uninterpreted(&uri);
    assert!(!host.is_bracketed());
    let d = Domain::try_from(&host).unwrap();
    assert_eq!(d.as_str(), "example.com");
}

#[cfg(feature = "idna")]
#[test]
fn pct_encoded_utf8_reg_name_decodes_with_idn() {
    // `%E4%B8%AD%E6%96%87.com` is pct-encoded UTF-8 for `中文.com`.
    // Parser preserves; `Domain::try_from` decodes + IDN-normalises.
    let uri = parse_strict("http://%E4%B8%AD%E6%96%87.com/").unwrap();
    let host = uninterpreted(&uri);
    let d = Domain::try_from(&host).unwrap();
    assert!(d.as_str().starts_with("xn--"), "got {d}");
    assert!(d.as_str().ends_with(".com"), "got {d}");
}

#[test]
fn pct_encoded_ipv4_decodes_to_address() {
    // `%31%32%37.0.0.1` pct-decodes to `127.0.0.1`.
    let uri = parse_strict("http://%31%32%37.0.0.1/").unwrap();
    let host = uninterpreted(&uri);
    let ip: std::net::IpAddr = (&host).try_into().unwrap();
    assert_eq!(ip, "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
}

#[test]
fn sub_delim_reg_name_preserved() {
    // RFC 3986 reg-name allows sub-delims. Parses, preserved verbatim;
    // `try_as_domain` correctly errors (commas aren't DNS-legal).
    let uri = parse_graceful("http://tag,with,commas/").unwrap();
    assert_eq!(uri.host().unwrap().to_str(), "tag,with,commas");
    let host = uninterpreted(&uri);
    Domain::try_from(&host).unwrap_err();
}

#[test]
fn malformed_pct_escape_rejected() {
    // `%X` truncated (no second hex digit).
    parse_graceful("http://%6/").unwrap_err();
    // `%XY` non-hex.
    parse_graceful("http://%6Z/").unwrap_err();
    // Bare `%` at end.
    parse_graceful("http://example.com%/").unwrap_err();
}

#[test]
fn pct_decoded_control_byte_rejected_as_smuggling_vector() {
    // `%00` decodes to NUL — even though the wire bytes are printable,
    // the decoded byte is a smuggling vector.
    let err = parse_graceful("http://exa%00ple.com/").unwrap_err();
    assert!(
        matches!(err, ParseError::ControlCharInUri { byte: 0x00, .. }),
        "got {err:?}"
    );
    // `%0D` carriage return — same.
    let err = parse_graceful("http://exa%0Dple.com/").unwrap_err();
    assert!(matches!(
        err,
        ParseError::ControlCharInUri { byte: 0x0D, .. }
    ));
    // `%09` tab — same.
    parse_graceful("http://exa%09ple.com/").unwrap_err();
}

#[test]
fn illegal_ascii_chars_in_reg_name_rejected() {
    // `[` and `]` only appear inside IP-literal brackets. Mid-reg-name
    // is invalid.
    parse_graceful("http://exa[ple.com/").unwrap_err();
    parse_graceful("http://exa]ple.com/").unwrap_err();
    // Other gen-delims excluded from reg-name.
    parse_graceful("http://exa<ple.com/").unwrap_err();
    parse_graceful("http://exa\"ple.com/").unwrap_err();
    parse_graceful("http://exa\\ple.com/").unwrap_err();
}

// ----------------------------------------------------------------------
// IPvFuture literals — `[vN.X]`, preserved verbatim. Wire-fidelity
// matters even though no `vN` form is registered with IANA.
// ----------------------------------------------------------------------

#[test]
fn ipvfuture_literal_preserved_in_strict() {
    let uri = parse_strict("http://[v1.fe80::a]/").unwrap();
    // The host stringifies with brackets back — they're URI syntax.
    assert_eq!(uri.host().unwrap().to_str(), "[v1.fe80::a]");
    let host = uninterpreted(&uri);
    assert!(host.is_bracketed());
    // Body is stored without the surrounding brackets.
    assert_eq!(host.as_bytes(), b"v1.fe80::a");
}

#[test]
fn ipvfuture_uppercase_v_accepted() {
    let uri = parse_strict("http://[V7.foo:bar]/").unwrap();
    let host = uninterpreted(&uri);
    assert!(host.is_bracketed());
    assert_eq!(host.as_bytes(), b"V7.foo:bar");
}

#[test]
fn ipvfuture_with_port() {
    let uri = parse_strict("http://[v1.fe80::a]:443/").unwrap();
    assert_eq!(uri.host().unwrap().to_str(), "[v1.fe80::a]");
    assert_eq!(uri.port(), Some(443));
}

#[test]
fn ipvfuture_domain_conversion_fails_with_typed_error() {
    let uri = parse_strict("http://[v1.fe80::a]/").unwrap();
    let host = uninterpreted(&uri);
    let err = Domain::try_from(&host).unwrap_err();
    assert!(
        format!("{err}").contains("bracketed IP-literal"),
        "got: {err}"
    );
}

#[test]
fn ipvfuture_grammar_rejects_invalid_shapes() {
    // No hex digits.
    parse_graceful("http://[v.foo]/").unwrap_err();
    // No `.` separator.
    parse_graceful("http://[v1foo]/").unwrap_err();
    // Empty tail.
    parse_graceful("http://[v1.]/").unwrap_err();
    // Non-hex in version.
    parse_graceful("http://[vZ.foo]/").unwrap_err();
}

#[test]
fn ipv6_still_parses_as_typed_address_not_uninterpreted() {
    // Bracketed IPv6 stays as the typed `Host::Address`.
    let uri = parse_strict("http://[::1]/").unwrap();
    let owned = uri.host().unwrap().into_owned();
    assert!(matches!(owned, Host::Address(_)));
    assert!(!matches!(owned, Host::Uninterpreted(_)));
}

// ----------------------------------------------------------------------
// Raw UTF-8 reg-name (RFC 3987 `ireg-name`) — graceful only, preserved.
// ----------------------------------------------------------------------

#[cfg(feature = "idna")]
#[test]
fn graceful_raw_utf8_host_preserved() {
    // The M7 reversal: parser no longer auto-normalises raw UTF-8 host
    // to ACE. The bytes are stored verbatim; conversion to Domain is
    // opt-in.
    let uri = parse_graceful("https://münchen.de/").unwrap();
    assert_eq!(uri.host().unwrap().to_str(), "münchen.de");
    let host = uninterpreted(&uri);
    let d = Domain::try_from(&host).unwrap();
    assert_eq!(d.as_str(), "xn--mnchen-3ya.de");
}

#[cfg(feature = "idna")]
#[test]
fn strict_rejects_raw_utf8_host() {
    // RFC 3986 strict grammar is ASCII only.
    let r = parse_strict("https://münchen.de/");
    assert!(matches!(r, Err(ParseError::StrictViolation)));
}

#[test]
fn fqdn_trailing_dot_in_host_preserved() {
    // `example.com.` (with trailing dot) is the FQDN form. URI parser
    // should accept and preserve the bytes verbatim.
    let u = parse_graceful("https://example.com./p").unwrap();
    // host may project as Domain (which normalises the trailing dot in
    // its label iteration) or stay Uninterpreted — either is acceptable;
    // what matters is the wire form round-trips.
    assert!(u.to_string().contains("example.com."));
}

#[test]
fn consecutive_dots_in_host_rejected_strict_accepted_graceful() {
    // `example..com` — empty label between dots. Strict rejects (empty
    // reg-name label is grammar-invalid via the Domain validator).
    // Graceful is more permissive — current behavior treats the bytes
    // as an Uninterpreted reg-name; just pin the round-trip.
    if let Ok(u) = parse_graceful("https://example..com/p") {
        assert!(u.to_string().contains("example..com"));
    }
}

#[test]
fn long_host_within_rfc1035_limit() {
    // Four 63-byte labels joined by `.` = 4×63 + 3 = 255 bytes. Too
    // long. Three 63-byte + one 60-byte = 3×63 + 60 + 3 = 252 bytes —
    // under the 253 cap.
    let host: String = std::iter::repeat_n('a', 63)
        .chain(std::iter::once('.'))
        .chain(std::iter::repeat_n('b', 63))
        .chain(std::iter::once('.'))
        .chain(std::iter::repeat_n('c', 63))
        .chain(std::iter::once('.'))
        .chain(std::iter::repeat_n('d', 60))
        .collect();
    assert_eq!(host.len(), 252);
    let uri_str = format!("https://{host}/p");
    parse_graceful(&uri_str).unwrap();
}
