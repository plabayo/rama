use super::header::X_FORWARDED_HOST;
use super::{dep::http::request::Parts, Request, Version};
use crate::http::{header::FORWARDED, HeaderMap};
use crate::net::{
    address::{Authority, Host},
    Protocol,
};

#[derive(Debug, Clone)]
/// The context of the [`Request`] being served by the [`HttpServer`]
///
/// [`Request`]: crate::http::Request
/// [`HttpServer`]: crate::http::server::HttpServer
pub struct RequestContext {
    /// The HTTP Version.
    pub http_version: Version,
    /// The [`Protocol`] as defined by the scheme of the [`Uri`](crate::http::Uri).
    pub protocol: Protocol,
    /// The host component of the [`Uri`](crate::http::Uri).
    pub host: Option<Host>,
    /// The port component of the [`Uri`](crate::http::Uri).
    pub port: Option<u16>,
}

impl RequestContext {
    /// Create a new [`RequestContext`] from the given [`Request`](crate::http::Request)
    pub fn new<Body>(req: &Request<Body>) -> Self {
        req.into()
    }

    /// Get the authority for this request, if defined.
    pub fn authority(&self) -> Option<Authority> {
        self.host.clone().map(|host| {
            let port = self.port.unwrap_or_else(|| self.protocol.default_port());
            Authority::new(host, port)
        })
    }

    /// Get the authority string for this request, if defined.
    pub fn authority_string(&self) -> Option<String> {
        self.host.as_ref().map(|host| {
            let port = self.port.unwrap_or_else(|| self.protocol.default_port());
            format!("{host}:{port}")
        })
    }
}

impl<Body> From<Request<Body>> for RequestContext {
    fn from(req: Request<Body>) -> Self {
        RequestContext::from(&req)
    }
}

impl From<Parts> for RequestContext {
    fn from(parts: Parts) -> Self {
        RequestContext::from(&parts)
    }
}

impl From<&Parts> for RequestContext {
    fn from(parts: &Parts) -> Self {
        let uri = &parts.uri;

        let protocol: Protocol = uri.scheme().into();

        let maybe_authority =
            extract_authority_from_headers(&protocol, &parts.headers).or_else(|| {
                uri.host().and_then(|h| {
                    Host::try_from(h).ok().map(|h| {
                        (h, uri.port_u16().unwrap_or_else(|| protocol.default_port())).into()
                    })
                })
            });
        let (host, port) = match maybe_authority {
            Some(authority) => {
                let (host, port) = authority.into_parts();
                (Some(host), Some(port))
            }
            None => (None, None),
        };

        let http_version = parts.version;

        RequestContext {
            http_version,
            protocol,
            host,
            port,
        }
    }
}

impl<Body> From<&Request<Body>> for RequestContext {
    fn from(req: &Request<Body>) -> Self {
        let uri = &req.uri();

        let protocol: Protocol = uri.scheme().into();

        let maybe_authority =
            extract_authority_from_headers(&protocol, req.headers()).or_else(|| {
                uri.host().and_then(|h| {
                    Host::try_from(h).ok().map(|h| {
                        (h, uri.port_u16().unwrap_or_else(|| protocol.default_port())).into()
                    })
                })
            });
        let (host, port) = match maybe_authority {
            Some(authority) => {
                let (host, port) = authority.into_parts();
                (Some(host), Some(port))
            }
            None => (None, None),
        };

        let port = match port.or_else(|| uri.port_u16()) {
            Some(port) => Some(port),
            None => match protocol {
                Protocol::Https | Protocol::Wss => Some(443),
                Protocol::Http | Protocol::Ws => Some(80),
                Protocol::Custom(_) | Protocol::Socks5 | Protocol::Socks5h => None,
            },
        };

        let http_version = req.version();

        RequestContext {
            http_version,
            protocol,
            host,
            port,
        }
    }
}

// TODO: clean up forward mess once we have proper forward integration

/// Extract the host from the headers ([`HeaderMap`]).
fn extract_authority_from_headers(protocol: &Protocol, headers: &HeaderMap) -> Option<Authority> {
    if let Some(host) = parse_forwarded(headers).and_then(|v| v.try_into().ok()) {
        return Some(host);
    }

    if let Some(host) = headers.get(&X_FORWARDED_HOST).and_then(|host| {
        host.try_into()
            .or_else(|_| Host::try_from(host).map(|h| (h, protocol.default_port()).into()))
            .ok()
    }) {
        return Some(host);
    }

    if let Some(host) = headers.get(http::header::HOST).and_then(|host| {
        host.try_into()
            .or_else(|_| Host::try_from(host).map(|h| (h, protocol.default_port()).into()))
            .ok()
    }) {
        return Some(host);
    }

    None
}

fn parse_forwarded(headers: &HeaderMap) -> Option<&str> {
    // if there are multiple `Forwarded` `HeaderMap::get` will return the first one
    let forwarded_values = headers.get(FORWARDED)?.to_str().ok()?;

    // get the first set of values
    let first_value = forwarded_values.split(',').next()?;

    // find the value of the `host` field
    first_value.split(';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("host")
            .then(|| value.trim().trim_matches('"'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HeaderName;

    #[test]
    fn test_request_context_from_request() {
        let req = Request::builder()
            .uri("http://example.com:8080")
            .version(Version::HTTP_11)
            .body(())
            .unwrap();

        let ctx = RequestContext::from(&req);

        assert_eq!(ctx.http_version, Version::HTTP_11);
        assert_eq!(ctx.protocol, Protocol::Http);
        assert_eq!(ctx.host.unwrap(), "example.com");
        assert_eq!(ctx.port, Some(8080));
    }

    #[test]
    fn test_request_context_from_parts() {
        let req = Request::builder()
            .uri("http://example.com:8080")
            .version(Version::HTTP_11)
            .body(())
            .unwrap();

        let (parts, _) = req.into_parts();
        let ctx: RequestContext = parts.into();

        assert_eq!(ctx.http_version, Version::HTTP_11);
        assert_eq!(ctx.protocol, Protocol::Http);
        assert_eq!(ctx.host.unwrap(), "example.com");
        assert_eq!(ctx.port, Some(8080));
    }

    #[test]
    fn test_request_context_authority() {
        let ctx = RequestContext {
            http_version: Version::HTTP_11,
            protocol: Protocol::Http,
            host: Some("example.com".try_into().unwrap()),
            port: Some(8080),
        };

        assert_eq!(ctx.authority().unwrap().to_string(), "example.com:8080");

        let ctx = RequestContext {
            http_version: Version::HTTP_11,
            protocol: Protocol::Http,
            host: Some("example.com".try_into().unwrap()),
            port: None,
        };

        assert_eq!(ctx.authority().unwrap().to_string(), "example.com:80");

        let ctx = RequestContext {
            http_version: Version::HTTP_11,
            protocol: Protocol::Https,
            host: Some("example.com".try_into().unwrap()),
            port: None,
        };

        assert_eq!(ctx.authority().unwrap().to_string(), "example.com:443");

        let ctx = RequestContext {
            http_version: Version::HTTP_11,
            protocol: Protocol::Ws,
            host: Some("example.com".try_into().unwrap()),
            port: None,
        };

        assert_eq!(ctx.authority().unwrap().to_string(), "example.com:80");

        let ctx = RequestContext {
            http_version: Version::HTTP_11,
            protocol: Protocol::Wss,
            host: Some("example.com".try_into().unwrap()),
            port: None,
        };

        assert_eq!(ctx.authority().unwrap().to_string(), "example.com:443");
    }

    #[test]
    fn forwarded_parsing() {
        // the basic case
        let headers = header_map(&[(FORWARDED, "host=192.0.2.60;proto=http;by=203.0.113.43")]);
        let value = parse_forwarded(&headers).unwrap();
        assert_eq!(value, "192.0.2.60");

        // is case insensitive
        let headers = header_map(&[(FORWARDED, "host=192.0.2.60;proto=http;by=203.0.113.43")]);
        let value = parse_forwarded(&headers).unwrap();
        assert_eq!(value, "192.0.2.60");

        // ipv6
        let headers = header_map(&[(FORWARDED, "host=\"[2001:db8:cafe::17]:4711\"")]);
        let value = parse_forwarded(&headers).unwrap();
        assert_eq!(value, "[2001:db8:cafe::17]:4711");

        // multiple values in one header
        let headers = header_map(&[(FORWARDED, "host=192.0.2.60, host=127.0.0.1")]);
        let value = parse_forwarded(&headers).unwrap();
        assert_eq!(value, "192.0.2.60");

        // multiple header values
        let headers = header_map(&[
            (FORWARDED, "host=192.0.2.60"),
            (FORWARDED, "host=127.0.0.1"),
        ]);
        let value = parse_forwarded(&headers).unwrap();
        assert_eq!(value, "192.0.2.60");
    }

    fn header_map(values: &[(HeaderName, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (key, value) in values {
            headers.append(key, value.parse().unwrap());
        }
        headers
    }
}
