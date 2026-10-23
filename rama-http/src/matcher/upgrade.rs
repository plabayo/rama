use crate::{Method, Request, Version, header, proto::ext::Protocol};
use rama_core::extensions::{Extensions, ExtensionsRef as _};

/// Matches requests opening a protocol by upgrade token, on any HTTP version.
///
/// HTTP/1.1 requests list the token in `Upgrade`; HTTP/2 and HTTP/3 send Extended
/// CONNECT with the token as `:protocol` ([RFC 8441], [RFC 9220]). Tokens compare
/// ASCII case-insensitively. Only the token is matched: validating the rest of the
/// handshake is the protocol's own.
///
/// [RFC 8441]: https://datatracker.ietf.org/doc/html/rfc8441
/// [RFC 9220]: https://datatracker.ietf.org/doc/html/rfc9220
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeTokenMatcher(Protocol);

impl UpgradeTokenMatcher {
    /// Match requests for `token`.
    #[must_use]
    pub const fn new(token: Protocol) -> Self {
        Self(token)
    }

    /// The token matched.
    #[must_use]
    pub fn token(&self) -> &Protocol {
        &self.0
    }
}

impl<Body> rama_core::matcher::Matcher<Request<Body>> for UpgradeTokenMatcher {
    fn matches(&self, _ext: Option<&Extensions>, req: &Request<Body>) -> bool {
        let token = self.0.as_str().as_bytes();
        match req.version() {
            Version::HTTP_11 => req
                .headers()
                .get_all(header::UPGRADE)
                .iter()
                .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
                .any(|offered| {
                    // A protocol may carry a version: `token/version`.
                    let name = offered.trim_ascii();
                    let name = name.split(|byte| *byte == b'/').next().unwrap_or(name);
                    name.eq_ignore_ascii_case(token)
                }),
            Version::HTTP_2 | Version::HTTP_3 => {
                req.method() == Method::CONNECT
                    && req
                        .extensions()
                        .get_ref::<Protocol>()
                        .is_some_and(|protocol| {
                            protocol.as_str().as_bytes().eq_ignore_ascii_case(token)
                        })
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Body;
    use rama_core::matcher::Matcher as _;

    const CONNECT_UDP: Protocol = Protocol::from_static("connect-udp");

    fn h1(upgrade: &str) -> Request<Body> {
        Request::builder()
            .uri("/")
            .header(header::UPGRADE, upgrade)
            .body(Body::empty())
            .unwrap()
    }

    fn extended_connect(version: Version, method: Method, protocol: &'static str) -> Request<Body> {
        let request = Request::builder()
            .version(version)
            .method(method)
            .uri("https://proxy.example/")
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(Protocol::from_static(protocol));
        request
    }

    #[test]
    fn http1_matches_the_token_among_offers() {
        let matcher = UpgradeTokenMatcher::new(CONNECT_UDP);
        for upgrade in [
            "connect-udp",
            "CONNECT-UDP",
            "h2c, connect-udp",
            " connect-udp/1 ",
        ] {
            assert!(matcher.matches(None, &h1(upgrade)), "{upgrade}");
        }
        for upgrade in ["websocket", "connect-udp-listen", "x-connect-udp"] {
            assert!(!matcher.matches(None, &h1(upgrade)), "{upgrade}");
        }
        let plain = Request::builder().uri("/").body(Body::empty()).unwrap();
        assert!(!matcher.matches(None, &plain));
    }

    #[test]
    fn http2_and_http3_need_extended_connect() {
        let matcher = UpgradeTokenMatcher::new(CONNECT_UDP);
        for version in [Version::HTTP_2, Version::HTTP_3] {
            assert!(matcher.matches(
                None,
                &extended_connect(version, Method::CONNECT, "connect-udp")
            ));
            assert!(matcher.matches(
                None,
                &extended_connect(version, Method::CONNECT, "Connect-UDP")
            ));
            assert!(!matcher.matches(
                None,
                &extended_connect(version, Method::CONNECT, "websocket")
            ));
            assert!(!matcher.matches(None, &extended_connect(version, Method::GET, "connect-udp")));
        }
        assert!(!matcher.matches(
            None,
            &extended_connect(Version::HTTP_10, Method::CONNECT, "connect-udp")
        ));
    }
}
