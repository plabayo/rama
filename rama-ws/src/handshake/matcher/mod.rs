//! WebSocket matcher utilities

use rama_core::{
    extensions::{Extensions, ExtensionsRef},
    matcher::Matcher,
    telemetry::tracing::{self},
};
use rama_http::{
    Method, Request, Version,
    headers::{self, HeaderMapExt},
    proto::h2::ext::Protocol,
};

mod service;
pub use self::service::{
    HttpWebSocketRelayServiceRequestMatcher, HttpWebSocketRelayServiceResponseMatcher,
};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// WebSocket [`Matcher`] to match on incoming WebSocket requests.
///
/// The [`Default`] ws matcher does already out of the box the basic checks:
///
/// - for http/1.1: require GET method and `Upgrade: websocket` + `Connection: upgrade` headers
/// - for h2: require CONNECT method and `:protocol: websocket` pseudo header
pub struct WebSocketMatcher;

impl WebSocketMatcher {
    #[inline]
    /// Create a new default [`WebSocketMatcher`].
    #[must_use]
    pub fn new() -> Self {
        Default::default()
    }
}

pub fn is_http_req_websocket_handshake<Body>(req: &Request<Body>) -> bool {
    match req.version() {
        version @ (Version::HTTP_10 | Version::HTTP_11) => {
            match req.method() {
                &Method::GET => (),
                method => {
                    tracing::debug!(
                        http.version = ?version,
                        http.request.method = %method,
                        "WebSocketMatcher: h1: unexpected method found: no match",
                    );
                    return false;
                }
            }

            if !req
                .headers()
                .typed_get::<headers::Upgrade>()
                .map(|u| u.is_websocket())
                .unwrap_or_default()
            {
                tracing::trace!(
                    http.version = ?version,
                    "WebSocketMatcher: h1: no websocket upgrade header found: no match"
                );
                return false;
            }

            if !req
                .headers()
                .typed_get::<headers::Connection>()
                .map(|c| c.contains_upgrade())
                .unwrap_or_default()
            {
                tracing::trace!(
                    http.version = ?version,
                    "WebSocketMatcher: h1: no connection upgrade header found: no match",
                );
                return false;
            }
        }
        version @ Version::HTTP_2 => {
            match req.method() {
                &Method::CONNECT => (),
                method => {
                    tracing::debug!(
                        http.version = ?version,
                        http.request.method = %method,
                        "WebSocketMatcher: h2: unexpected method found: no match",
                    );
                    return false;
                }
            }

            if !req
                .extensions()
                .get::<Protocol>()
                .map(|p| p.as_str().trim().eq_ignore_ascii_case("websocket"))
                .unwrap_or_default()
            {
                tracing::trace!(
                    http.version = ?version,
                    "WebSocketMatcher: h2: no websocket protocol (pseudo ext) found",
                );
                return false;
            }
        }
        version => {
            tracing::debug!(
                http.version = ?version,
                "WebSocketMatcher: unexpected http version found: no match",
            );
            return false;
        }
    }

    true
}

impl<Body> Matcher<Request<Body>> for WebSocketMatcher
where
    Body: Send + 'static,
{
    #[inline(always)]
    fn matches(&self, _ext: Option<&mut Extensions>, req: &Request<Body>) -> bool {
        is_http_req_websocket_handshake(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_http::Body;

    macro_rules! request {
        (
            $method:literal $version:literal $uri:literal
            $(
                $header_name:literal: $header_value:literal
            )*
        ) => {
            request!(
                $method $version $uri
                $(
                    $header_name: $header_value
                )*
                w/ []
            )
        };
        (
            $method:literal $version:literal $uri:literal
            $(
                $header_name:literal: $header_value:literal
            )*
            w/ [$($extension:expr),* $(,)?]
        ) => {
            {
                let req = Request::builder()
                    .uri($uri)
                    .version(match $version {
                        "HTTP/1.1" => Version::HTTP_11,
                        "HTTP/2" => Version::HTTP_2,
                        _ => unreachable!(),
                    })
                    .method(match $method {
                        "GET" => Method::GET,
                        "POST" => Method::POST,
                        "CONNECT" => Method::CONNECT,
                        _ => unreachable!(),
                    });

                $(
                    let req = req.header($header_name, $header_value);
                )*

                $(
                    let req = req.extension($extension);
                )*

                req.body(Body::empty()).unwrap()
            }
        };
    }

    fn assert_websocket_no_match(request: &Request, matcher: &WebSocketMatcher) {
        assert!(
            !matcher.matches(None, request),
            "!({matcher:?}).matches({request:?})"
        );
    }

    fn assert_websocket_match(request: &Request, matcher: &WebSocketMatcher) {
        assert!(
            matcher.matches(None, request),
            "({matcher:?}).matches({request:?})"
        );
    }

    #[test]
    fn test_websocket_match_default_http_11() {
        let matcher = WebSocketMatcher::default();

        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/1.1" "/"
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Upgrade": "websocket"
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
            },
            &matcher,
        );
        assert_websocket_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
            },
            &matcher,
        );
    }

    #[test]
    fn test_websocket_match_default_http_2() {
        let matcher = WebSocketMatcher::default();

        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/2" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
            },
            &matcher,
        );
        assert_websocket_match(
            &request! {
                "CONNECT" "HTTP/2" "/"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/2" "/"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );
    }
}
