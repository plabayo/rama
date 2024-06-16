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
/// [`HttpServer`]: crate::http::server::HttpServer
pub struct RequestContext {
    /// The HTTP Version.
    pub http_version: Version,
    /// The [`Protocol`] of the [`Request`].
    pub protocol: Protocol,
    /// The authority of the [`Request`].
    ///
    /// In http/1.1 this is typically defined by the `Host` header,
    /// whereas for h2 and h3 this is found in the pseudo `:authority` header.
    ///
    /// This can be also manually set in case there is support for
    /// forward headers (e.g. `Forwarded`, or `X-Forwarded-Host`)
    /// or forward protocols (e.g. `HaProxy`).
    ///
    /// Strictly speaking an authority is always required. It is however up to the user
    /// of this [`RequestContext`] to turn this into a dealbreaker if desired.
    pub authority: Option<Authority>,
}

impl RequestContext {
    /// Create a new [`RequestContext`] from the given [`Request`](crate::http::Request)
    pub fn new<Body>(req: &Request<Body>) -> Self {
        req.into()
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
        let default_port = uri.port_u16().unwrap_or_else(|| protocol.default_port());

        let authority =
            extract_authority_from_headers(default_port, &parts.headers).or_else(|| {
                uri.host()
                    .and_then(|h| Host::try_from(h).ok().map(|h| (h, default_port).into()))
            });

        let http_version = parts.version;

        RequestContext {
            http_version,
            protocol,
            authority,
        }
    }
}

impl<Body> From<&Request<Body>> for RequestContext {
    fn from(req: &Request<Body>) -> Self {
        let uri = &req.uri();

        let protocol: Protocol = uri.scheme().into();
        let default_port = uri.port_u16().unwrap_or_else(|| protocol.default_port());

        let authority = extract_authority_from_headers(default_port, req.headers()).or_else(|| {
            uri.host()
                .and_then(|h| Host::try_from(h).ok().map(|h| (h, default_port).into()))
        });

        let http_version = req.version();

        RequestContext {
            http_version,
            protocol,
            authority,
        }
    }
}

// TODO: clean up forward mess once we have proper forward integration

/// Extract the host from the headers ([`HeaderMap`]).
fn extract_authority_from_headers(default_port: u16, headers: &HeaderMap) -> Option<Authority> {
    if let Some(host) = parse_forwarded(headers).and_then(|v| v.try_into().ok()) {
        return Some(host);
    }

    if let Some(host) = headers.get(&X_FORWARDED_HOST).and_then(|host| {
        host.try_into() // try to consume as Authority, otherwise as Host
            .or_else(|_| Host::try_from(host).map(|h| (h, default_port).into()))
            .ok()
    }) {
        return Some(host);
    }

    if let Some(host) = headers.get(http::header::HOST).and_then(|host| {
        host.try_into() // try to consume as Authority, otherwise as Host
            .or_else(|_| Host::try_from(host).map(|h| (h, default_port).into()))
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
        assert_eq!(ctx.authority.unwrap().to_string(), "example.com:8080");
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
        assert_eq!(
            ctx.authority.unwrap(),
            Authority::try_from("example.com:8080").unwrap()
        );
    }

    #[test]
    fn test_request_context_authority() {
        let ctx = RequestContext {
            http_version: Version::HTTP_11,
            protocol: Protocol::Http,
            authority: Some("example.com:8080".try_into().unwrap()),
        };

        assert_eq!(ctx.authority.unwrap().to_string(), "example.com:8080");
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
