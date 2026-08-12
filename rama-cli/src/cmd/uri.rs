use rama::{
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
    net::{
        Protocol,
        uri::{PathRef, Uri},
    },
};

/// Parse a user-provided URI, curl-style: a missing scheme means `http`,
/// and a bare `:port` or `:/path` means localhost.
pub(super) fn parse_user_uri(input: &str) -> Result<Uri, BoxError> {
    if input.is_empty() {
        return http_uri("localhost");
    }

    let uri = Uri::parse_reference(input).context("parse URI")?;

    match uri.scheme() {
        // RFC 3986 reads `host:port[/path]` as a scheme and opaque path.
        Some(_) if is_host_port_shorthand(&uri) => http_uri(input),
        Some(scheme) => Ok(if uri.authority().is_some() {
            uri.canonicalize()
        } else {
            // An opaque URI (`data:`, `urn:`, ...) has payload where a
            // hierarchical one has a path. Only its scheme is safe to normalize.
            let scheme = scheme.clone();
            uri.with_scheme(scheme)
        }),
        None if uri.authority().is_some() => Ok(uri.with_scheme(Protocol::HTTP).canonicalize()),
        None => match input.strip_prefix(':') {
            Some(rest) if rest.starts_with('/') => http_uri(format!("localhost{rest}")),
            Some(_) => {
                let candidate = format!("localhost{input}");
                let shorthand = Uri::parse_reference(candidate.as_str())
                    .is_ok_and(|uri| is_host_port_shorthand(&uri));
                if !shorthand {
                    return Err(BoxError::from_static_str(
                        "leading `:` must be followed by a port or a `/path` (an IPv6 address needs brackets: `[::1]`)",
                    )
                    .context_str_field("uri", input));
                }
                http_uri(candidate)
            }
            None => http_uri(input),
        },
    }
}

fn http_uri(authority: impl std::fmt::Display) -> Result<Uri, BoxError> {
    Uri::parse_canonical(format!("{}://{authority}", Protocol::HTTP_SCHEME))
        .context("parse URI with implied http scheme")
}

fn is_host_port_shorthand(uri: &Uri) -> bool {
    if uri.scheme().is_none() || uri.authority().is_some() {
        return false;
    }
    uri.path()
        .filter(|path| !path.as_encoded_str().starts_with('/'))
        .and_then(PathRef::first_segment)
        .is_some_and(|segment| {
            let port = segment.as_encoded_str();
            !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_uri_parser_accepts_http_shorthand_and_absolute_uris() {
        for (input, expected) in [
            ("example.com", "http://example.com/"),
            ("http://example.com", "http://example.com/"),
            ("https://example.com", "https://example.com/"),
            ("example.com:8080", "http://example.com:8080/"),
            (":8080/foo", "http://localhost:8080/foo"),
            (":8080", "http://localhost:8080/"),
            ("", "http://localhost/"),
            ("localhost:8080?q=1", "http://localhost:8080/?q=1"),
            ("localhost:8080#f", "http://localhost:8080/#f"),
            ("example.com?q=1", "http://example.com/?q=1"),
            ("[::1]:8080", "http://[::1]:8080/"),
            ("127.0.0.1:8080/x", "http://127.0.0.1:8080/x"),
            ("//example.com/x", "http://example.com/x"),
            ("file:///tmp/x", "file:///tmp/x"),
            ("file:/tmp/x", "file:/tmp/x"),
            ("data:,hello", "data:,hello"),
            ("DATA:text/plain;base64,aGk=", "data:text/plain;base64,aGk="),
            (
                "example.com/?next=http://x",
                "http://example.com/?next=http://x",
            ),
            (
                "localhost:8080/auth?redirect_uri=http://localhost:3000/cb",
                "http://localhost:8080/auth?redirect_uri=http://localhost:3000/cb",
            ),
            (":/path", "http://localhost/path"),
            ("mailto:someone@example.com", "mailto:someone@example.com"),
            ("urn:isbn:0451450523", "urn:isbn:0451450523"),
            ("wibble:whatever", "wibble:whatever"),
        ] {
            let uri = parse_user_uri(input).unwrap_or_else(|err| panic!("`{input}`: {err}"));
            assert_eq!(uri.to_string(), expected, "{input}");
        }
    }

    #[test]
    fn user_uri_parser_keeps_opaque_payload_intact() {
        for (input, expected) in [
            ("data:,a/../b", "data:,a/../b"),
            ("data:,a/./b", "data:,a/./b"),
            ("data:text/plain,../x", "data:text/plain,../x"),
            ("file:/tmp/sub/../pac.js", "file:/tmp/sub/../pac.js"),
        ] {
            let uri = parse_user_uri(input).unwrap_or_else(|err| panic!("`{input}`: {err}"));
            assert_eq!(uri.to_string(), expected, "{input}");
        }
    }

    #[test]
    fn user_uri_parser_canonicalizes_hierarchical_uris() {
        for (input, expected) in [
            ("http://example.com/a/../b", "http://example.com/b"),
            ("http://example.com/a/./b", "http://example.com/a/b"),
            ("file:///tmp/sub/../pac.js", "file:///tmp/pac.js"),
            ("HTTP://EXAMPLE.com:80/x", "http://example.com/x"),
        ] {
            let uri = parse_user_uri(input).unwrap_or_else(|err| panic!("`{input}`: {err}"));
            assert_eq!(uri.to_string(), expected, "{input}");
        }
    }

    #[test]
    fn user_uri_parser_rejects_unsafe_colon_shorthand() {
        for input in [
            "::1",
            ":hello",
            ":.evil.com",
            ":@evil.com",
            ":8080@evil.com",
            ":8080.evil.com",
        ] {
            let err = parse_user_uri(input).unwrap_err();
            assert!(
                err.to_string().contains("leading `:`"),
                "`{input}`: unexpected error: {err}"
            );
        }
    }

    #[test]
    fn user_uri_parser_rejects_out_of_range_port() {
        let err = parse_user_uri("example.com:99999").unwrap_err();
        assert!(
            err.to_string().contains("http scheme"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn host_port_shorthand_is_narrow() {
        for input in [
            "example.com:8080",
            "example.com:8080/x",
            "localhost:8080?q=1",
            "localhost:8080#f",
            "localhost:8080/auth?redirect_uri=http://localhost:3000/cb",
            "example.com:99999",
        ] {
            let uri = Uri::parse_reference(input).unwrap_or_else(|err| panic!("`{input}`: {err}"));
            assert!(is_host_port_shorthand(&uri), "{input}");
        }

        for input in [
            "http://example.com",
            "https://example.com",
            "ws://example.com",
            "file:///tmp/x",
            "file:/tmp/x",
            "data:,hello",
            "DATA:,hello",
            "mailto:someone@example.com",
            "urn:isbn:0451450523",
            "example.com:+8080",
            "example.com:80x",
            "example.com",
            "example.com/?next=http://x",
            "[::1]:8080",
            ":8080",
        ] {
            let uri = Uri::parse_reference(input).unwrap_or_else(|err| panic!("`{input}`: {err}"));
            assert!(!is_host_port_shorthand(&uri), "{input}");
        }
    }
}
