//! IDNA / UTS #46 handling at the URI parsing layer.
//!
//! **Design contract: wire fidelity at parse time.** The parser does
//! *not* IDN-normalize non-ASCII hosts. Bytes that arrive intact survive
//! intact via [`Host::Uninterpreted`](crate::address::Host::Uninterpreted).
//! IDN normalization (UTS #46 → A-label / ACE form) is opt-in via
//! `Domain::try_from(&uninterpreted_host)`, run when the caller actually
//! needs a DNS-routable name. Strict mode rejects non-ASCII hosts per
//! RFC 3986 §3.2.2; graceful mode preserves them per RFC 3987
//! `ireg-name`.

use super::parse_graceful;
use crate::uri::Uri;

// ----------------------------------------------------------------------
// With `idna` feature ON — host bytes are preserved verbatim; convert
// to `Domain` on demand for the IDN A-label form.
// ----------------------------------------------------------------------

#[cfg(feature = "idna")]
mod with_idna {
    use super::*;
    use crate::address::{Domain, Host};

    #[test]
    fn ascii_host_unchanged_zero_copy() {
        // ASCII fast-path: parser slices Domain bytes directly out of
        // the parent buffer — no allocation, no UTS #46 processing.
        let uri: Uri = parse_graceful("https://example.com/path").unwrap();
        assert_eq!(uri.host().unwrap().to_str(), "example.com");
        assert_eq!(uri.to_string(), "https://example.com/path");
    }

    /// Non-ASCII host bytes are now preserved verbatim, not auto-IDN'd.
    /// The host is `Host::Uninterpreted` carrying the original UTF-8.
    #[test]
    fn german_idn_host_preserved_verbatim() {
        let uri: Uri = parse_graceful("https://münchen.de/").unwrap();
        let h = uri.host().unwrap();
        // Round-trip — wire bytes survived parsing.
        assert_eq!(h.to_str(), "münchen.de");
        assert_eq!(uri.to_string(), "https://münchen.de/");
    }

    /// Caller asks for the ACE form explicitly via the typed conversion.
    #[test]
    fn german_idn_converts_to_ace_on_demand() {
        let uri: Uri = parse_graceful("https://münchen.de/").unwrap();
        let owned = uri.host().unwrap().to_owned();
        let uninterpreted = owned
            .as_uninterpreted()
            .expect("non-ASCII host parses as Uninterpreted");
        let d = Domain::try_from(uninterpreted).unwrap();
        assert_eq!(d.as_str(), "xn--mnchen-3ya.de");
    }

    #[test]
    fn japanese_idn_host_preserved_and_converts_on_demand() {
        let uri: Uri = parse_graceful("https://日本.com/").unwrap();
        let h = uri.host().unwrap();
        assert_eq!(h.to_str(), "日本.com");
        // ACE recovery on demand.
        let owned = h.to_owned();
        let uninterpreted = owned.as_uninterpreted().unwrap();
        let d = Domain::try_from(uninterpreted).unwrap();
        assert!(d.as_str().starts_with("xn--"), "got {d}");
        assert!(d.as_str().ends_with(".com"), "got {d}");
    }

    #[test]
    fn already_ace_host_unchanged() {
        // Input is already in ACE form (pure ASCII, valid DNS labels) —
        // parses as `Host::Name(Domain)`, not Uninterpreted.
        let uri: Uri = parse_graceful("https://xn--mnchen-3ya.de/").unwrap();
        assert_eq!(uri.host().unwrap().to_str(), "xn--mnchen-3ya.de");
        let owned = uri.host().unwrap().to_owned();
        assert!(matches!(owned, Host::Name(_)));
    }

    /// Uppercase non-ASCII is preserved verbatim. UTS #46 case-folding
    /// happens only when the caller calls `Domain::try_from`.
    #[test]
    fn uppercase_non_ascii_preserved_then_normalised_on_convert() {
        let uri: Uri = parse_graceful("https://MÜNCHEN.de/").unwrap();
        assert_eq!(uri.host().unwrap().to_str(), "MÜNCHEN.de");
        let owned = uri.host().unwrap().to_owned();
        let uninterpreted = owned.as_uninterpreted().unwrap();
        let d = Domain::try_from(uninterpreted).unwrap();
        assert_eq!(d.as_str(), "xn--mnchen-3ya.de");
    }

    #[test]
    fn mixed_labels_preserved_then_normalised_on_convert() {
        let uri: Uri = parse_graceful("https://münchen.example.com/").unwrap();
        assert_eq!(uri.host().unwrap().to_str(), "münchen.example.com");
        let owned = uri.host().unwrap().to_owned();
        let uninterpreted = owned.as_uninterpreted().unwrap();
        let d = Domain::try_from(uninterpreted).unwrap();
        assert_eq!(d.as_str(), "xn--mnchen-3ya.example.com");
    }

    #[test]
    fn ipv4_address_unaffected() {
        let uri: Uri = parse_graceful("https://1.2.3.4:8080/").unwrap();
        assert_eq!(uri.host().unwrap().to_str(), "1.2.3.4");
    }

    #[test]
    fn ipv6_address_unaffected() {
        let uri: Uri = parse_graceful("https://[::1]:8080/").unwrap();
        assert_eq!(uri.host().unwrap().to_str(), "::1");
    }

    // -- as_unicode ---------------------------------------------------------

    #[test]
    fn as_unicode_borrows_when_no_ace_labels() {
        let d = Domain::try_from("example.com").unwrap();
        let unicode = d.as_unicode();
        assert!(matches!(unicode, std::borrow::Cow::Borrowed(_)));
        assert_eq!(&*unicode, "example.com");
    }

    #[test]
    fn as_unicode_decodes_ace_labels() {
        let d = Domain::try_from("xn--mnchen-3ya.de").unwrap();
        let unicode = d.as_unicode();
        assert!(matches!(unicode, std::borrow::Cow::Owned(_)));
        assert_eq!(&*unicode, "münchen.de");
    }

    /// Round-trip preservation: parse → host bytes survive intact →
    /// `as_unicode` returns the same bytes (no decoding work).
    #[test]
    fn as_unicode_preserves_non_ascii_host_via_uri() {
        let uri: Uri = parse_graceful("https://münchen.de/").unwrap();
        let host = uri.host().unwrap();
        assert_eq!(host.to_str(), "münchen.de");
        assert_eq!(&*host.as_unicode(), "münchen.de");
    }

    #[test]
    fn as_unicode_on_ip_returns_textual_form() {
        let uri: Uri = parse_graceful("https://1.2.3.4/").unwrap();
        assert_eq!(uri.host().unwrap().as_unicode(), "1.2.3.4");

        let uri: Uri = parse_graceful("https://[::1]/").unwrap();
        assert_eq!(uri.host().unwrap().as_unicode(), "::1");
    }

    // -- Error cases --------------------------------------------------------

    /// UTS #46 validation runs only on the conversion path
    /// (`Domain::try_from`), not at URI parse time. So the disallowed
    /// codepoint parses fine but rejects when the caller tries to
    /// extract a typed Domain.
    #[test]
    fn uts46_disallowed_codepoint_caught_on_domain_conversion() {
        let uri: Uri = parse_graceful("https://a\u{fe6e}b.com/")
            .expect("parser preserves the bytes; UTS #46 runs on convert");
        let owned = uri.host().unwrap().to_owned();
        let uninterpreted = owned.as_uninterpreted().unwrap();
        let r = Domain::try_from(uninterpreted);
        assert!(r.is_err(), "UTS #46 must reject disallowed codepoint");
    }

    // -- Domain entry-point parity ------------------------------------------

    #[test]
    fn domain_try_from_str_handles_idn() {
        let d = Domain::try_from("münchen.de").unwrap();
        assert_eq!(d.as_str(), "xn--mnchen-3ya.de");
    }

    #[test]
    fn domain_try_from_bytes_handles_idn() {
        let d = Domain::try_from("münchen.de".as_bytes()).unwrap();
        assert_eq!(d.as_str(), "xn--mnchen-3ya.de");
    }

    #[test]
    fn domain_try_from_string_handles_idn() {
        let d = Domain::try_from(String::from("münchen.de")).unwrap();
        assert_eq!(d.as_str(), "xn--mnchen-3ya.de");
    }

    // -- Strict mode + IDN -------------------------------------------------
    //
    // RFC 3986 §3.2.2 host grammar is ASCII-only. UTS #46 normalisation
    // is a graceful-mode convenience, not part of the spec — strict
    // mode must reject non-ASCII host bytes even with the `idna`
    // feature on. Callers wanting strict + IDN pre-encode to ACE.

    #[test]
    fn strict_rejects_non_ascii_host() {
        use crate::uri::ParseError;
        for non_ascii in [
            "https://münchen.de/",
            "https://日本.com/",
            "https://MÜNCHEN.de/",
            "https://api.üñiçödé.example/",
        ] {
            let r = crate::uri::Uri::parse_strict(non_ascii);
            assert!(
                matches!(r, Err(ParseError::StrictViolation)),
                "strict must reject non-ASCII host {non_ascii:?}; got {r:?}"
            );
        }
    }

    #[test]
    fn strict_accepts_already_ace_host() {
        // Already-ACE-encoded host is pure ASCII; strict grammar is
        // satisfied.
        let u = crate::uri::Uri::parse_strict("https://xn--mnchen-3ya.de/").unwrap();
        assert_eq!(u.host().unwrap().to_str(), "xn--mnchen-3ya.de");
    }

    /// Graceful mode preserves non-ASCII (wire-fidelity); strict mode
    /// rejects it. Layering pin: the strict tightening doesn't change
    /// graceful behaviour.
    #[test]
    fn graceful_preserves_non_ascii_strict_rejects() {
        let graceful = super::parse_graceful("https://münchen.de/").unwrap();
        assert_eq!(graceful.host().unwrap().to_str(), "münchen.de");

        let strict = crate::uri::Uri::parse_strict("https://münchen.de/");
        assert!(strict.is_err());
    }
}

// ----------------------------------------------------------------------
// Without `idna` feature — graceful mode preserves bytes (parser
// doesn't touch them), but `Domain::try_from` on the preserved bytes
// errors with `IdnaNotEnabled` at conversion time.
// ----------------------------------------------------------------------

#[cfg(not(feature = "idna"))]
mod without_idna {
    use super::*;
    use crate::address::Domain;

    /// Parser preserves bytes regardless of feature flag — the M7
    /// reversal applies in both. `idna`-less builds error only when
    /// the caller asks for the typed Domain.
    #[test]
    fn non_ascii_host_preserved_but_domain_conversion_errors() {
        let uri: Uri = parse_graceful("https://münchen.de/").unwrap();
        assert_eq!(uri.host().unwrap().to_str(), "münchen.de");
        let owned = uri.host().unwrap().to_owned();
        let uninterpreted = owned.as_uninterpreted().unwrap();
        let err = Domain::try_from(uninterpreted).unwrap_err();
        assert!(err.is_idna_not_enabled(), "got {err:?}");
    }

    #[test]
    fn ascii_host_still_works() {
        // No feature on — ASCII still parses as `Host::Name(Domain)`.
        let uri: Uri = parse_graceful("https://example.com/").unwrap();
        assert_eq!(uri.host().unwrap().to_str(), "example.com");
    }
}
