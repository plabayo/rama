use super::{
    dep::http::request::Parts, headers::extract::extract_host_from_headers, Request, Version,
};
use crate::uri::Scheme;

#[derive(Debug, Clone)]
/// The context of the [`Request`] being served by the [`HttpServer`]
///
/// [`Request`]: crate::http::Request
/// [`HttpServer`]: crate::http::server::HttpServer
pub struct RequestContext {
    /// The version of the HTTP that is required for
    /// the given [`Request`](crate::http::Request) to be proxied.
    pub http_version: Version,
    /// The [`Scheme`] of the HTTP's [`Uri`](crate::http::Uri) that is defined for
    /// the given [`Request`](crate::http::Request) to be proxied.
    pub scheme: Scheme,
    /// The host of the HTTP's [`Uri`](crate::http::Uri) Authority component that is defined for
    /// the given [`Request`](crate::http::Request) to be proxied.
    pub host: Option<String>,
    /// The port of the HTTP's [`Uri`](crate::http::Uri) Authority component that is defined for
    /// the given [`Request`](crate::http::Request) to be proxied.
    ///
    /// It defaults to the standard port of the scheme if not present.
    pub port: Option<u16>,
}

impl RequestContext {
    /// Create a new [`RequestContext`] from the given [`Request`](crate::http::Request)
    pub fn new<Body>(req: &Request<Body>) -> Self {
        req.into()
    }

    /// Get the authority from the [`RequestContext`] (`host[:port]`).
    pub fn authority(&self) -> Option<String> {
        self.host.as_ref().map(|host| match self.port {
            Some(port) => format!("{host}:{port}"),
            None => match self.scheme {
                Scheme::Http | Scheme::Ws => format!("{host}:80"),
                Scheme::Https | Scheme::Wss => format!("{host}:443"),
                _ => host.clone(),
            },
        })
    }

    /// Get the address from the [`RequestContext`] (`scheme://host[:port]`).
    pub fn address(&self) -> Option<String> {
        self.authority()
            .map(|authority| format!("{}://{}", self.scheme, authority))
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

        let scheme = uri.scheme().into();
        let host =
            extract_host_from_headers(&parts.headers).or_else(|| uri.host().map(str::to_owned));
        let port = uri.port().map(u16::from);
        let http_version = parts.version;

        RequestContext {
            http_version,
            scheme,
            host,
            port,
        }
    }
}

impl<Body> From<&Request<Body>> for RequestContext {
    fn from(req: &Request<Body>) -> Self {
        let uri = req.uri();

        let scheme = uri.scheme().into();
        let host =
            extract_host_from_headers(req.headers()).or_else(|| uri.host().map(str::to_owned));
        let port = uri.port().map(u16::from);
        let http_version = req.version();

        RequestContext {
            http_version,
            scheme,
            host,
            port,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_context_from_request() {
        let req = Request::builder()
            .uri("http://example.com:8080")
            .version(Version::HTTP_11)
            .body(())
            .unwrap();

        let ctx = RequestContext::from(&req);

        assert_eq!(ctx.http_version, Version::HTTP_11);
        assert_eq!(ctx.scheme, Scheme::Http);
        assert_eq!(ctx.host, Some("example.com".to_owned()));
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
        assert_eq!(ctx.scheme, Scheme::Http);
        assert_eq!(ctx.host, Some("example.com".to_owned()));
        assert_eq!(ctx.port, Some(8080));
    }

    #[test]
    fn test_request_context_authority() {
        let ctx = RequestContext {
            http_version: Version::HTTP_11,
            scheme: Scheme::Http,
            host: Some("example.com".to_owned()),
            port: Some(8080),
        };

        assert_eq!(ctx.authority(), Some("example.com:8080".to_owned()));

        let ctx = RequestContext {
            http_version: Version::HTTP_11,
            scheme: Scheme::Http,
            host: Some("example.com".to_owned()),
            port: None,
        };

        assert_eq!(ctx.authority(), Some("example.com:80".to_owned()));

        let ctx = RequestContext {
            http_version: Version::HTTP_11,
            scheme: Scheme::Https,
            host: Some("example.com".to_owned()),
            port: None,
        };

        assert_eq!(ctx.authority(), Some("example.com:443".to_owned()));

        let ctx = RequestContext {
            http_version: Version::HTTP_11,
            scheme: Scheme::Ws,
            host: Some("example.com".to_owned()),
            port: None,
        };

        assert_eq!(ctx.authority(), Some("example.com:80".to_owned()));

        let ctx = RequestContext {
            http_version: Version::HTTP_11,
            scheme: Scheme::Wss,
            host: Some("example.com".to_owned()),
            port: None,
        };

        assert_eq!(ctx.authority(), Some("example.com:443".to_owned()));
    }

    #[test]
    fn test_request_context_address() {
        let ctx = RequestContext {
            http_version: Version::HTTP_11,
            scheme: Scheme::Http,
            host: Some("example.com".to_owned()),
            port: Some(8080),
        };

        assert_eq!(ctx.address(), Some("http://example.com:8080".to_owned()));

        let ctx = RequestContext {
            http_version: Version::HTTP_11,
            scheme: Scheme::Http,
            host: Some("example.com".to_owned()),
            port: None,
        };

        assert_eq!(ctx.address(), Some("http://example.com:80".to_owned()));

        let ctx = RequestContext {
            http_version: Version::HTTP_11,
            scheme: Scheme::Https,
            host: Some("example.com".to_owned()),
            port: None,
        };

        assert_eq!(ctx.address(), Some("https://example.com:443".to_owned()));

        let ctx = RequestContext {
            http_version: Version::HTTP_11,
            scheme: Scheme::Ws,
            host: Some("example.com".to_owned()),
            port: None,
        };

        assert_eq!(ctx.address(), Some("ws://example.com:80".to_owned()));

        let ctx = RequestContext {
            http_version: Version::HTTP_2,
            scheme: Scheme::Wss,
            host: Some("example.com".to_owned()),
            port: None,
        };

        assert_eq!(ctx.address(), Some("wss://example.com:443".to_owned()));
    }
}
