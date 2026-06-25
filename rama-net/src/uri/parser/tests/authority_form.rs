//! `Uri::parse_authority_form` — the HTTP CONNECT request-target shape
//! `[userinfo@]host[:port]` (RFC 9112 §3.2.3).
//!
//! Distinct entry point because the grammar is ambiguous with
//! `scheme:opaque-path` (`example.com:443` parses validly as both, and
//! RFC 3986 prefers the scheme reading). HTTP proxies handling CONNECT
//! must route through this entry; `Uri::parse` retains the RFC 3986
//! tie-break.

use crate::uri::{ParseError, Uri};

#[test]
fn host_port_pair() {
    let u = Uri::parse_authority_form("example.com:443").unwrap();
    assert!(u.scheme().is_none(), "authority-form has no scheme");
    assert_eq!(u.host().unwrap().to_str(), "example.com");
    assert_eq!(u.port_u16(), Some(443));
    assert_eq!(u.path().map(|p| p.as_encoded_str()).as_deref(), Some(""));
}

#[test]
fn host_port_with_userinfo() {
    let u = Uri::parse_authority_form("user:pass@example.com:443").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "example.com");
    assert_eq!(u.port_u16(), Some(443));
    assert!(u.userinfo().is_some());
}

#[test]
fn ipv4_literal() {
    let u = Uri::parse_authority_form("127.0.0.1:8080").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "127.0.0.1");
    assert_eq!(u.port_u16(), Some(8080));
}

#[test]
fn ipv6_bracketed_literal() {
    let u = Uri::parse_authority_form("[::1]:443").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "::1");
    assert_eq!(u.port_u16(), Some(443));

    let u = Uri::parse_authority_form("[2001:db8::1]:80").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "2001:db8::1");
    assert_eq!(u.port_u16(), Some(80));
}

#[test]
fn bare_host_without_port_accepted() {
    // RFC 9112 §3.2.3 says CONNECT *requires* a port; lower-level URI
    // parsing is more permissive — HTTP-aware callers can enforce the
    // port requirement at their layer.
    let u = Uri::parse_authority_form("example.com").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "example.com");
    assert_eq!(u.port_u16(), None);
}

#[test]
fn path_query_fragment_delimiters_rejected() {
    // Any of `/`, `?`, `#` means the caller has the wrong shape.
    Uri::parse_authority_form("example.com:443/foo").unwrap_err();
    Uri::parse_authority_form("example.com:443?x=1").unwrap_err();
    Uri::parse_authority_form("example.com:443#frag").unwrap_err();
    Uri::parse_authority_form("https://example.com:443").unwrap_err();
}

#[test]
fn empty_input_rejected() {
    assert!(matches!(
        Uri::parse_authority_form(""),
        Err(ParseError::Empty)
    ));
}

#[test]
fn invalid_port_rejected() {
    Uri::parse_authority_form("example.com:99999").unwrap_err();
    Uri::parse_authority_form("example.com:abc").unwrap_err();
}

#[test]
fn empty_port_accepted_in_graceful_as_bare_host() {
    // RFC 3986 §3.2.3 allows empty port; graceful authority-form
    // accepts bare-host shapes, so `example.com:` parses with `None`.
    let u = Uri::parse_authority_form("example.com:").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "example.com");
    assert_eq!(u.port_u16(), None);
}

#[test]
fn empty_port_rejected_in_strict_authority_form() {
    // RFC 9112 §3.2.3 requires `host ":" port` — strict mode rejects
    // the bare-host form an empty port produces.
    let r = Uri::parse_authority_form_strict("example.com:");
    assert!(matches!(r, Err(crate::uri::ParseError::StrictViolation)));
}

#[cfg(feature = "idna")]
#[test]
fn graceful_preserves_non_ascii_host_in_authority_form() {
    // Wire-fidelity preservation (M7 reversed): parser stores the bytes
    // verbatim. IDN conversion to ACE happens on demand via
    // `Domain::try_from(uri.host().as_uninterpreted())`.
    let u = Uri::parse_authority_form("münchen.de:443").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "münchen.de");
}

#[cfg(feature = "idna")]
#[test]
fn strict_rejects_non_ascii_host() {
    // Strict authority-form must reject non-ASCII identically to strict
    // `Uri::parse` — RFC 3986 host grammar is ASCII only.
    let r = Uri::parse_authority_form_strict("münchen.de:443");
    assert!(r.is_err(), "strict authority-form must reject non-ASCII");
}

#[test]
fn renders_without_scheme_or_path() {
    // Round-trip: parsed authority-form must render as `host:port` only.
    // If a scheme or path slips in, HTTP CONNECT proxies route wrong.
    let u = Uri::parse_authority_form("example.com:443").unwrap();
    let s = u.to_string();
    assert!(!s.contains("://"), "rendered has scheme prefix: {s}");
    assert!(s.contains("example.com"));
    assert!(s.contains("443"));
}

#[test]
fn plain_parse_treats_host_port_as_scheme_path() {
    // Pin RFC 3986 tie-break: `Uri::parse` on a bare `host:port` reads
    // it as `scheme:opaque-path`. Callers handling CONNECT must call
    // `parse_authority_form` instead.
    let u = Uri::parse("example.com:443").unwrap();
    assert_eq!(u.scheme().map(|s| s.as_str()), Some("example.com"));
    assert!(u.host().is_none());
}

// ---- Strict RFC 9112 §3.2.3 enforcement -----------------------------------

#[test]
fn strict_accepts_host_port() {
    // The canonical CONNECT shape passes through cleanly.
    let u = Uri::parse_authority_form_strict("example.com:443").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "example.com");
    assert_eq!(u.port_u16(), Some(443));
}

#[test]
fn strict_accepts_bracketed_ipv6_host_port() {
    let u = Uri::parse_authority_form_strict("[2001:db8::1]:443").unwrap();
    assert_eq!(u.host().unwrap().to_str(), "2001:db8::1");
    assert_eq!(u.port_u16(), Some(443));
}

#[test]
fn strict_rejects_userinfo() {
    // RFC 9112 §3.2.3: "The request-target consists of the host and port
    // number of the tunnel destination" — no userinfo permitted.
    let err = Uri::parse_authority_form_strict("user:pass@example.com:443").unwrap_err();
    assert!(
        matches!(err, ParseError::StrictViolation),
        "expected StrictViolation, got {err:?}"
    );
    // Userinfo on its own (no password) is also out.
    Uri::parse_authority_form_strict("user@example.com:443").unwrap_err();
}

#[test]
fn strict_rejects_bare_host_without_port() {
    // §3.2.3 mandates a port. Graceful accepts; strict does not.
    let err = Uri::parse_authority_form_strict("example.com").unwrap_err();
    assert!(
        matches!(err, ParseError::StrictViolation),
        "expected StrictViolation, got {err:?}"
    );
    // IPv6 bracketed without port also rejected.
    Uri::parse_authority_form_strict("[2001:db8::1]").unwrap_err();
}

#[test]
fn strict_keeps_path_query_fragment_rejection() {
    // Pre-port-check guard fires before the strict-mode shape check.
    // The error kind (InvalidComponent vs StrictViolation) doesn't matter
    // — both modes reject — but pin both still error so we don't accept
    // a CONNECT target with a path under any setting.
    Uri::parse_authority_form_strict("example.com:443/p").unwrap_err();
    Uri::parse_authority_form_strict("example.com:443?q").unwrap_err();
    Uri::parse_authority_form_strict("example.com:443#f").unwrap_err();
}

#[test]
fn as_authority_form_projects_full_uri() {
    // Drops scheme/path/query/fragment, keeps host[:port].
    let u = Uri::parse("https://example.com:8443/some/path?q=1#frag").unwrap();
    let auth = u.as_authority_form().unwrap();
    assert!(auth.scheme().is_none());
    assert_eq!(auth.host().unwrap().to_str(), "example.com");
    assert_eq!(auth.port_u16(), Some(8443));
    assert_eq!(auth.path().map(|p| p.as_encoded_str()).as_deref(), Some(""));
    assert_eq!(auth, "example.com:8443");

    // No explicit port → bare host.
    let u = Uri::parse("http://example.com/a").unwrap();
    assert_eq!(u.as_authority_form().unwrap(), "example.com");

    // Already authority-form → idempotent.
    let u = Uri::parse_authority_form("example.com:443").unwrap();
    assert_eq!(u.as_authority_form().unwrap(), "example.com:443");

    // No authority (origin-form / asterisk) → None.
    assert!(
        Uri::parse("/just/a/path")
            .unwrap()
            .as_authority_form()
            .is_none()
    );
    assert!(Uri::parse("*").unwrap().as_authority_form().is_none());
}

#[test]
fn ergonomic_accessors() {
    let u = Uri::parse("https://example.com:8443/api/v2/users?q=1").unwrap();
    assert_eq!(u.path_or_root(), "/api/v2/users");
    assert_eq!(u.query_or_empty(), "q=1");
    assert_eq!(u.scheme_str(), Some("https"));
    assert_eq!(u.host_str().as_deref(), Some("example.com"));
    assert_eq!(u.request_target(), "/api/v2/users?q=1");
    assert!(u.has_path_prefix("/api"));
    assert!(u.has_path_suffix("/users"));
    assert_eq!(
        u.first_path_segment()
            .map(|s| s.as_encoded_str())
            .as_deref(),
        Some("api")
    );
    assert_eq!(
        u.path_segment(2).map(|s| s.as_encoded_str()).as_deref(),
        Some("users")
    );
    assert!(u.path_segment(3).is_none());

    // empty / absent path defaults
    let u = Uri::parse("http://example.com").unwrap();
    assert_eq!(u.path_or_root(), "/");
    assert_eq!(u.query_or_empty(), "");
    assert_eq!(u.request_target(), "/");
    assert!(!u.has_path_suffix("/x"));

    // origin-form
    let u = Uri::parse("/foo/bar").unwrap();
    assert_eq!(u.request_target(), "/foo/bar");
    assert_eq!(u.scheme_str(), None);
    assert_eq!(u.host_str(), None);
}

#[test]
fn ensure_path_trailing_slash_works() {
    let mut u = Uri::parse("http://example.com/dir").unwrap();
    u.ensure_path_trailing_slash();
    assert_eq!(u.path_or_root(), "/dir/");
    // idempotent
    u.ensure_path_trailing_slash();
    assert_eq!(u.path_or_root(), "/dir/");
    // query preserved
    let mut u = Uri::parse("http://example.com/dir?x=1").unwrap();
    u.ensure_path_trailing_slash();
    assert_eq!(u.request_target(), "/dir/?x=1");
}

#[cfg(test)]
mod path_match {
    use crate::uri::{PathMatchOptions, Uri};

    fn uri(s: &str) -> Uri {
        Uri::parse(s).unwrap()
    }

    #[test]
    fn has_prefix_boundary_default() {
        let u = uri("https://example.com/api/v2/users");
        assert!(u.has_path_prefix("/api"));
        assert!(u.has_path_prefix("api")); // leading slash optional
        assert!(u.has_path_prefix("/api/v2"));
        assert!(u.has_path_prefix("")); // empty matches
        assert!(u.has_path_prefix("/api/v2/users")); // whole path
        // mid-segment rejected at boundary
        assert!(!u.has_path_prefix("/ap"));
        assert!(!u.has_path_prefix("/api/v")); // partial last segment
        assert!(!uri("https://example.com/apixyz").has_path_prefix("/api"));
    }

    #[test]
    fn has_prefix_partial() {
        let opts = PathMatchOptions {
            partial: true,
            ..Default::default()
        };
        let u = uri("https://example.com/apixyz/v2");
        assert!(u.has_path_prefix_with_opts("/api", opts));
        assert!(u.has_path_prefix_with_opts("/apixyz/v", opts));
        assert!(!u.has_path_prefix_with_opts("/xyz", opts));
    }

    #[test]
    fn has_suffix_boundary_and_partial() {
        let u = uri("https://example.com/api/style.css");
        // boundary: whole last segment
        assert!(u.has_path_suffix("style.css"));
        assert!(u.has_path_suffix("api/style.css"));
        assert!(!u.has_path_suffix(".css")); // mid-segment rejected
        assert!(!u.has_path_suffix("le.css"));
        // partial: byte suffix
        let partial = PathMatchOptions {
            partial: true,
            ..Default::default()
        };
        assert!(u.has_path_suffix_with_opts(".css", partial));
        assert!(u.has_path_suffix_with_opts("le.css", partial));
        assert!(!u.has_path_suffix_with_opts(".png", partial));
    }

    #[test]
    fn percent_decode_default_on() {
        let u = uri("https://example.com/foo%20bar/baz");
        // normalized: decoded "foo bar" matches both decoded and encoded patterns
        assert!(u.has_path_prefix("/foo bar"));
        assert!(u.has_path_prefix("/foo%20bar"));
        // opt out of decoding → only the raw byte form matches
        let raw = PathMatchOptions {
            percent_decode: false,
            ..Default::default()
        };
        assert!(!u.has_path_prefix_with_opts("/foo bar", raw));
        assert!(u.has_path_prefix_with_opts("/foo%20bar", raw));
        // encoded slash stays in-segment (no phantom separator)
        assert!(!uri("https://example.com/a%2Fb/c").has_path_prefix("/a/b"));
    }

    #[test]
    fn ignore_ascii_case_opt() {
        let u = uri("https://example.com/API/v2");
        assert!(!u.has_path_prefix("/api"));
        let ci = PathMatchOptions {
            ignore_ascii_case: true,
            ..Default::default()
        };
        assert!(u.has_path_prefix_with_opts("/api", ci));
        assert!(u.has_path_prefix_with_opts("/API", ci));
    }

    #[test]
    fn strip_prefix_boundary_and_partial() {
        let mut u = uri("https://example.com/api/v2/x");
        assert!(u.path_mut().strip_prefix("/api"));
        assert_eq!(u, "https://example.com/v2/x");

        // boundary rejects mid-segment
        let mut u = uri("https://example.com/api/v2");
        assert!(!u.path_mut().strip_prefix("/ap"));
        assert_eq!(u, "https://example.com/api/v2"); // unchanged

        // partial allows mid-segment
        let mut u = uri("https://example.com/api/v2");
        let partial = PathMatchOptions {
            partial: true,
            ..Default::default()
        };
        assert!(u.path_mut().strip_prefix_with_opts("/ap", partial));
        assert_eq!(u, "https://example.com/i/v2");
    }

    #[test]
    fn strip_suffix_works() {
        let mut u = uri("https://example.com/a/b/c");
        assert!(u.path_mut().strip_suffix("c"));
        assert_eq!(u, "https://example.com/a/b");

        let mut u = uri("https://example.com/a/b/c");
        assert!(u.path_mut().strip_suffix("b/c"));
        assert_eq!(u, "https://example.com/a");

        // boundary rejects mid-segment suffix
        let mut u = uri("https://example.com/a/bc");
        assert!(!u.path_mut().strip_suffix("c"));
        assert_eq!(u, "https://example.com/a/bc");

        // partial allows it
        let mut u = uri("https://example.com/a/bc");
        let partial = PathMatchOptions {
            partial: true,
            ..Default::default()
        };
        assert!(u.path_mut().strip_suffix_with_opts("c", partial));
        assert_eq!(u, "https://example.com/a/b");
    }

    #[test]
    fn has_and_strip_agree() {
        // The check and the strip must use identical matching.
        let cases = ["/api/v2", "/apixyz", "/a/b/c", "/", "/foo%20bar/x"];
        let patterns = ["/api", "api", "/a/b", "ap", "/foo bar"];
        for opts in [
            PathMatchOptions::default(),
            PathMatchOptions {
                partial: true,
                ..Default::default()
            },
            PathMatchOptions {
                ignore_ascii_case: true,
                ..Default::default()
            },
            PathMatchOptions {
                percent_decode: false,
                ..Default::default()
            },
        ] {
            for path in cases {
                for pat in patterns {
                    let u = uri(&format!("http://h{path}"));
                    let has = u.has_path_prefix_with_opts(pat, opts);
                    let mut s = u.clone();
                    let stripped = s.path_mut().strip_prefix_with_opts(pat, opts);
                    assert_eq!(
                        has, stripped,
                        "disagree for path={path:?} pat={pat:?} opts={opts:?}"
                    );
                }
            }
        }
    }
}
