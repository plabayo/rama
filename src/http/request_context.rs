use super::Version;
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
