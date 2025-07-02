//! WebSocket server types and utilities

use std::fmt;

use rama_core::{
    Context, context::Extensions, error::ErrorContext, matcher::Matcher, telemetry::tracing,
};
use rama_http::{
    Method, Request, Version, header,
    headers::{self, HeaderMapExt},
    matcher::HttpMatcher,
    proto::h2::ext::Protocol,
};
use smallvec::SmallVec;
use smol_str::SmolStr;

use crate::handshake::SubProtocols;

/// WebSocket [`Matcher`] to match on incoming WebSocket requests.
///
/// The [`Default`] ws matcher does already out of the box the basic checks:
///
/// - for http/1.1: require GET method and `Upgrade: websocket` + `Connection: upgrade` headers
/// - for h2: require CONNECT method and `:protocol: websocket` pseudo header
/// - for all versions: require `sec-websocket-version: 13` header and the existance of the `sec-websocket-key` header
/// - expect no `sec-websocket-protocol` header
///
/// The matching behaviour in regards to the `sec-websocket-protocol` header can customized using
/// the provided builder and set methods of this matcher.
pub struct WebSocketMatcher<State, Body> {
    sub_protocols: Option<SubProtocols>,
    sub_protocol_optional: bool,
    http_matcher: Option<HttpMatcher<State, Body>>,
}

impl<State, Body> Clone for WebSocketMatcher<State, Body> {
    fn clone(&self) -> Self {
        Self {
            sub_protocols: self.sub_protocols.clone(),
            sub_protocol_optional: self.sub_protocol_optional,
            http_matcher: self.http_matcher.clone(),
        }
    }
}

impl<State, Body> fmt::Debug for WebSocketMatcher<State, Body> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebSocketMatcher")
            .field("sub_protocols", &self.sub_protocols)
            .field("sub_protocol_optional", &self.sub_protocol_optional)
            .field("http_matcher", &self.http_matcher)
            .finish()
    }
}

impl<State, Body> Default for WebSocketMatcher<State, Body> {
    fn default() -> Self {
        WebSocketMatcher {
            sub_protocols: None,
            sub_protocol_optional: false,
            http_matcher: None,
        }
    }
}

impl<State, Body> WebSocketMatcher<State, Body> {
    #[inline]
    /// Create a new default [`WebSocketMatcher`].
    pub fn new() -> Self {
        Default::default()
    }

    rama_utils::macros::generate_set_and_with! {
        /// Define an [`HttpMatcher`] that can be used for this server matcher.
        ///
        /// This can be useful in case you wish to narrow your match further down
        /// based on things like resource, http version, headers and so on.
        pub fn http_matcher(mut self, matcher: Option<HttpMatcher<State, Body>>) -> Self {
            self.http_matcher = matcher;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Define if the sub protocol is optional.
        ///
        /// - In case no sub protocols are defined by server it implies that
        ///   the server will accept any incoming sub protocol instead of denying sub protocols.
        /// - Or in case server did specify a sub protocol allow list it will also
        ///   accept incoming requests which do not define a sub protocol.
        pub fn sub_protocol_optional(mut self, optional: bool) -> Self {
            self.sub_protocol_optional = optional;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the WebSocket sub protocol, overwriting any existing sub protocol.
        ///
        /// The sub protocols defined by the server (matcher) act as an allow list.
        /// You can make sub protocols optional in case you also wish to allow no
        /// sub protocols to be defined.
        pub fn sub_protocol(mut self, protocol: impl Into<SmolStr>) -> Self {
            self.sub_protocols = Some(SubProtocols::new(protocol));
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Add the WebSocket sub protocol, appending it to any existing sub protocol(s).
        ///
        /// The sub protocols defined by the server (matcher) act as an allow list.
        /// You can make sub protocols optional in case you also wish to allow no
        /// sub protocols to be defined.
        pub fn additional_sub_protocol(mut self, protocol: impl Into<SmolStr>) -> Self {
            self.sub_protocols = Some(match self.sub_protocols.take() {
                Some(protocols) => protocols.with_additional_sub_protocol(protocol),
                None => SubProtocols::new(protocol),
            });
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the WebSocket sub protocols, overwriting any existing sub protocol.
        ///
        /// The sub protocols defined by the server (matcher) act as an allow list.
        /// You can make sub protocols optional in case you also wish to allow no
        /// sub protocols to be defined.
        pub fn sub_protocols(mut self, protocols: impl IntoIterator<Item = impl Into<SmolStr>>) -> Self {
            let protocols: SmallVec<_> = protocols.into_iter().map(Into::into).collect();
            self.sub_protocols = (!protocols.is_empty()).then_some(SubProtocols(protocols));
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Add the WebSocket sub protocols, appending it to any existing sub protocol(s).
        ///
        /// The sub protocols defined by the server (matcher) act as an allow list.
        /// You can make sub protocols optional in case you also wish to allow no
        /// sub protocols to be defined.
        pub fn additional_sub_protocols(mut self, protocols: impl IntoIterator<Item = impl Into<SmolStr>>) -> Self {
            let protocols = protocols.into_iter();
            self.sub_protocols = match self.sub_protocols.take() {
                Some(existing_protocols) => Some(existing_protocols.with_additional_sub_protocols(protocols)),
                None => {
                    let protocols: SmallVec<_> = protocols.into_iter().map(Into::into).collect();
                    (!protocols.is_empty()).then_some(SubProtocols(protocols))
                }
            };
            self
        }
    }
}

impl<State, Body> Matcher<State, Request<Body>> for WebSocketMatcher<State, Body>
where
    State: Clone + Send + Sync + 'static,
    Body: Send + 'static,
{
    fn matches(
        &self,
        ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        match req.version() {
            Version::HTTP_10 | Version::HTTP_11 => {
                match req.method() {
                    &Method::GET => (),
                    method => {
                        tracing::debug!(http.request.method = %method, "WebSocketMatcher: h1: unexpected method found: no match");
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
                        "WebSocketMatcher: h1: no connection upgrade header found: no match"
                    );
                    return false;
                }
            }
            Version::HTTP_2 => {
                match req.method() {
                    &Method::CONNECT => (),
                    method => {
                        tracing::debug!(http.request.method = %method, "WebSocketMatcher: h2: unexpected method found: no match");
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
                        "WebSocketMatcher: h2: no websocket protocol (pseudo ext) found"
                    );
                    return false;
                }
            }
            version => {
                tracing::debug!(http.version = ?version, "WebSocketMatcher: unexpected http version found: no match");
                return false;
            }
        }

        if req
            .headers()
            .typed_get::<headers::SecWebsocketVersion>()
            .is_none()
        {
            // Assumption: decodes only if exists and the value == "13", the one version to rule them all
            tracing::debug!("WebSocketMatcher: missing sec-websocket-version: no match");
            return false;
        }

        if req.headers().get(header::SEC_WEBSOCKET_KEY).is_none() {
            // not a typed check so we do not decode twice, for now validating it exist should be ok
            tracing::debug!("WebSocketMatcher: missing sec-websocket-key: no match");
            return false;
        }

        let sub_protocol_optional = self.sub_protocol_optional;
        let found_sub_protocols: Option<SubProtocols> = match req
            .headers()
            .get(header::SEC_WEBSOCKET_PROTOCOL)
            .map(|h| {
                h.to_str()
                    .context("utf-8 decode sec-websocket-protocol header")
                    .and_then(|v| v.parse())
            })
            .transpose()
        {
            Ok(maybe) => maybe,
            Err(err) => {
                tracing::debug!("WebSocketMatcher: invalid sec-websocket-protocol header: {err}");
                return false;
            }
        };
        let allowed_sub_protocols = self.sub_protocols.as_ref();

        match (
            sub_protocol_optional,
            found_sub_protocols,
            allowed_sub_protocols,
        ) {
            (false, Some(protocols), None) => {
                tracing::debug!(
                    "WebSocketMatcher: sub-protocols found while none were expected: {protocols}"
                );
                return false;
            }
            (false, None, Some(protocols)) => {
                tracing::debug!(
                    "WebSocketMatcher: no sub-protocols found while one of following was expected: {protocols}"
                );
                return false;
            }
            (_, None, None) | (true, None, Some(_)) | (true, Some(_), None) => (),
            (_, Some(found_protocols), Some(expected_protocols)) => {
                if !found_protocols.iter().any(|p| {
                    expected_protocols
                        .iter()
                        .any(|e| p.trim().eq_ignore_ascii_case(e.trim()))
                }) {
                    tracing::debug!(
                        "WebSocketMatcher: protocols found ({found_protocols}) are not expected according to allow list: {expected_protocols}"
                    );
                    return false;
                }
            }
        }

        if let Some(ref http_matcher) = self.http_matcher {
            if !http_matcher.matches(ext, ctx, req) {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_http::{Body, HeaderName, matcher::UriParams};

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

    fn assert_websocket_no_match(request: &Request, matcher: &WebSocketMatcher<(), Body>) {
        assert!(
            !matcher.matches(None, &Context::default(), request),
            "!({matcher:?}).matches({request:?})"
        );
    }

    fn assert_websocket_match(request: &Request, matcher: &WebSocketMatcher<(), Body>) {
        assert!(
            matcher.matches(None, &Context::default(), request),
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
                "Sec-WebSocket-Version": "13"
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
        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Sec-WebSocket-Version": "13"
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "14"
                "Sec-WebSocket-Key": "foobar"
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "keep-alive"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "foobar"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
            },
            &matcher,
        );

        assert_websocket_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
            },
            &matcher,
        );

        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                "Sec-WebSocket-Protocol": "foo"
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
        assert_websocket_no_match(
            &request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "14"
                "Sec-WebSocket-Key": "foobar"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                w/ [
                    Protocol::from_static("foobar"),
                ]
            },
            &matcher,
        );

        assert_websocket_match(
            &request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );

        // no key value validation is done in matcher
        assert_websocket_match(
            &request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": ""
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );

        assert_websocket_no_match(
            &request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                "Sec-WebSocket-Protocol": "foo"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );
    }

    #[test]
    fn test_websocket_match_optional_sub_protocols() {
        let matcher = WebSocketMatcher::default().with_sub_protocol_optional(true);

        // no protocols

        assert_websocket_match(
            &request! {
                "GET" "HTTP/1.1" "/"
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
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );

        // with protocols

        assert_websocket_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                "Sec-WebSocket-Protocol": "foo"
            },
            &matcher,
        );
        assert_websocket_match(
            &request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                "Sec-WebSocket-Protocol": "foo"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );

        // with multiple protocols

        assert_websocket_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                "Sec-WebSocket-Protocol": "foo, bar"
            },
            &matcher,
        );
        assert_websocket_match(
            &request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                "Sec-WebSocket-Protocol": "foo,baz, foo"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );

        // without protocols, even though we have allow list, fine due to it being optional,
        // but we still only accept allowed protocols if defined

        let matcher = matcher.with_sub_protocol("foo");

        assert_websocket_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
            },
            &matcher,
        );

        assert_websocket_no_match(
            &request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                "Sec-WebSocket-Protocol": "baz,fo"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );
    }

    #[test]
    fn test_websocket_match_required_sub_protocols() {
        let matcher = WebSocketMatcher::default()
            .with_sub_protocol("foo")
            .with_additional_sub_protocols(["a", "b"]);

        // no protocols, required so all bad

        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );

        // with allowed protocol

        assert_websocket_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                "Sec-WebSocket-Protocol": "foo"
            },
            &matcher,
        );
        assert_websocket_match(
            &request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                "Sec-WebSocket-Protocol": "b"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );

        // with multiple protocols (including at least one allowed one)

        assert_websocket_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                "Sec-WebSocket-Protocol": "test, b"
            },
            &matcher,
        );
        assert_websocket_match(
            &request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                "Sec-WebSocket-Protocol": "a,test, c"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );

        // only with non-allowed protocol(s)

        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                "Sec-WebSocket-Protocol": "test, c"
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                "Sec-WebSocket-Protocol": "test"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );
    }

    #[test]
    fn test_websocket_match_with_http_matcher_http_2() {
        let matcher = WebSocketMatcher::default().with_http_matcher(
            HttpMatcher::path("/foo").and_header_exists(HeaderName::from_static("x-matcher-test")),
        );

        assert_websocket_no_match(
            &request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                "x-Matcher-TEST": "1"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "CONNECT" "HTTP/2" "/foo"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );

        assert_websocket_match(
            &request! {
                "CONNECT" "HTTP/2" "/foo"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                "x-Matcher-TEST": "1"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );
    }

    #[test]
    fn test_websocket_match_with_http_matcher_http_11() {
        let matcher = WebSocketMatcher::default().with_http_matcher(
            HttpMatcher::path("/foo").and_header_exists(HeaderName::from_static("x-matcher-test")),
        );

        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "x-Matcher-TEST": "1"
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/1.1" "/foo"
                "Sec-WebSocket-Version": "13"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "Sec-WebSocket-Key": "foobar"
            },
            &matcher,
        );

        assert_websocket_match(
            &request! {
                "GET" "HTTP/1.1" "/foo"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "x-Matcher-TEST": "1"
            },
            &matcher,
        );
    }

    #[test]
    fn test_websocket_match_with_http_matcher_and_sub_protocol() {
        let matcher = WebSocketMatcher::default()
            .with_http_matcher(
                HttpMatcher::path("/foo")
                    .and_header_exists(HeaderName::from_static("x-matcher-test")),
            )
            .with_sub_protocol("chat");

        assert_websocket_no_match(
            &request! {
                "CONNECT" "HTTP/2" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );
        assert_websocket_no_match(
            &request! {
                "GET" "HTTP/1.1" "/"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "x-Matcher-TEST": "1"
            },
            &matcher,
        );

        assert_websocket_match(
            &request! {
                "GET" "HTTP/1.1" "/foo"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                "Connection": "upgrade"
                "Upgrade": "websocket"
                "SEC-websocket-protocol": "chat"
                "x-Matcher-TEST": "1"
            },
            &matcher,
        );
        assert_websocket_match(
            &request! {
                "CONNECT" "HTTP/2" "/foo"
                "Sec-WebSocket-Version": "13"
                "Sec-WebSocket-Key": "foobar"
                "SEC-websocket-protocol": "chat"
                "x-Matcher-TEST": "1"
                w/ [
                    Protocol::from_static("websocket"),
                ]
            },
            &matcher,
        );
    }

    #[test]
    fn test_websocket_match_with_http_matcher_path_extension_exists() {
        let matcher =
            WebSocketMatcher::default().with_http_matcher(HttpMatcher::path("/foo/{bar}"));

        let mut extensions = Extensions::default();

        let request = request! {
            "CONNECT" "HTTP/2" "/foo/hello"
            "Sec-WebSocket-Version": "13"
            "Sec-WebSocket-Key": "foobar"
            "x-Matcher-TEST": "1"
            w/ [
                Protocol::from_static("websocket"),
            ]
        };

        assert!(
            matcher.matches(Some(&mut extensions), &Context::default(), &request),
            "({matcher:?}).matches({request:?})"
        );

        let path_params: &UriParams = extensions.get().unwrap();
        assert_eq!(path_params.get("bar"), Some("hello"));

        // ensure that no match is made in case no match is made

        extensions.clear();

        let request = request! {
            "CONNECT" "HTTP/2" "/bar/hello"
            "Sec-WebSocket-Version": "13"
            "Sec-WebSocket-Key": "foobar"
            "x-Matcher-TEST": "1"
            w/ [
                Protocol::from_static("websocket"),
            ]
        };

        assert!(
            !matcher.matches(Some(&mut extensions), &Context::default(), &request),
            "!({matcher:?}).matches({request:?})"
        );

        assert!(extensions.get::<UriParams>().is_none());
    }
}
