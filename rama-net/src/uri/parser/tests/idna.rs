//! IDNA / UTS #46 handling at the URI parsing layer.
//!
//! Most of these only run when the `idna` feature is enabled — the
//! [`#[cfg(feature = "idna")]`] gates below skip them otherwise. The
//! tests at the bottom of the file cover the no-feature path.

use super::parse_graceful;
use crate::uri::Uri;

// ----------------------------------------------------------------------
// With `idna` feature ON — host is ACE-encoded on parse
// ----------------------------------------------------------------------

#[cfg(feature = "idna")]
mod with_idna {
    use super::*;
    use crate::address::Domain;

    #[test]
    fn ascii_host_unchanged_zero_copy() {
        // ASCII fast-path: parser slices Domain bytes directly out of
        // the parent buffer — no allocation, no UTS #46 processing.
        let uri: Uri = parse_graceful("https://example.com/path").unwrap();
        assert_eq!(uri.host().unwrap().to_str(), "example.com");
        assert_eq!(uri.to_string(), "https://example.com/path");
    }

    #[test]
    fn german_idn_encodes_to_ace() {
        let uri: Uri = parse_graceful("https://münchen.de/").unwrap();
        assert_eq!(uri.host().unwrap().to_str(), "xn--mnchen-3ya.de");
        assert_eq!(uri.to_string(), "https://xn--mnchen-3ya.de/");
    }

    #[test]
    fn japanese_idn_encodes_to_ace() {
        let uri: Uri = parse_graceful("https://日本.com/").unwrap();
        let host = uri.host().unwrap();
        let host_str = host.to_str();
        assert!(host_str.starts_with("xn--"), "got {host_str:?}");
        assert!(host_str.ends_with(".com"), "got {host_str:?}");
    }

    #[test]
    fn already_ace_host_unchanged() {
        // Input is already in ACE form — passes through verbatim.
        let uri: Uri = parse_graceful("https://xn--mnchen-3ya.de/").unwrap();
        assert_eq!(uri.host().unwrap().to_str(), "xn--mnchen-3ya.de");
    }

    #[test]
    fn uppercase_normalises() {
        // UTS #46 case-folds A-labels; `MÜNCHEN` → `münchen` → ACE.
        let uri: Uri = parse_graceful("https://MÜNCHEN.de/").unwrap();
        assert_eq!(uri.host().unwrap().to_str(), "xn--mnchen-3ya.de");
    }

    #[test]
    fn mixed_labels_each_processed_independently() {
        // Only the non-ASCII label gets ACE-encoded; ASCII labels stay.
        let uri: Uri = parse_graceful("https://münchen.example.com/").unwrap();
        assert_eq!(uri.host().unwrap().to_str(), "xn--mnchen-3ya.example.com",);
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

    #[test]
    fn as_unicode_round_trip_via_uri() {
        // parse(IDN) → host bytes are ACE → as_unicode recovers original.
        let uri: Uri = parse_graceful("https://münchen.de/").unwrap();
        let host = uri.host().unwrap();
        assert_eq!(host.to_str(), "xn--mnchen-3ya.de");
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

    #[test]
    fn uts46_disallowed_codepoint_rejected() {
        // U+FE6E (small comma) is disallowed by UTS #46.
        let result = parse_graceful("https://a\u{fe6e}b.com/");
        assert!(result.is_err(), "expected rejection, got {result:?}");
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
}

// ----------------------------------------------------------------------
// Without `idna` feature — non-ASCII host fails with IdnaNotEnabled
// ----------------------------------------------------------------------

#[cfg(not(feature = "idna"))]
mod without_idna {
    use super::*;
    use crate::uri::ParseError;

    #[test]
    fn non_ascii_host_errors_idna_not_enabled() {
        let err = parse_graceful("https://münchen.de/").unwrap_err();
        assert!(matches!(err, ParseError::IdnaNotEnabled), "got {err:?}");
    }

    #[test]
    fn ascii_host_still_works() {
        // No feature on — ASCII-only is the only supported shape.
        let uri: Uri = parse_graceful("https://example.com/").unwrap();
        assert_eq!(uri.host().unwrap().to_str(), "example.com");
    }
}
