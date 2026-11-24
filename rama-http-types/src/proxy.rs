use crate::{
    Method, Request, StreamingBody, Version,
    body::{Frame, SizeHint},
    proto::ext::Protocol,
};
use pin_project_lite::pin_project;
use rama_core::{
    extensions::{Extension, Extensions, ExtensionsRef as _},
    matcher::Matcher,
};
use std::{
    pin::Pin,
    task::{Context, Poll},
};

pin_project! {
    /// The body of a request sent to a proxy: the client's own body for a request the
    /// proxy forwards, none for the CONNECT or CONNECT-UDP request opening a tunnel.
    #[project = ProxyRequestBodyProj]
    #[derive(Debug, Default)]
    pub enum ProxyRequestBody<B> {
        /// The body of a request the proxy forwards to its origin.
        Forwarded { #[pin] body: B },
        /// The request opens a tunnel and carries no body.
        #[default]
        Empty,
    }
}

impl<B> ProxyRequestBody<B> {
    /// The body of a request the proxy forwards to its origin.
    pub const fn forwarded(body: B) -> Self {
        Self::Forwarded { body }
    }
}

impl<B: StreamingBody> StreamingBody for ProxyRequestBody<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.project() {
            ProxyRequestBodyProj::Forwarded { body } => body.poll_frame(cx),
            ProxyRequestBodyProj::Empty => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Forwarded { body } => body.is_end_stream(),
            Self::Empty => true,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Forwarded { body } => body.size_hint(),
            Self::Empty => SizeHint::with_exact(0),
        }
    }
}

/// Requested handling of plaintext HTTP and WebSocket traffic through an
/// HTTP(S) proxy.
///
/// Keeping this preference on the request lets route-aware connection pools
/// distinguish ordinary forward-proxy connections from CONNECT tunnels before
/// selecting a connection. An HTTP-proxy connector consumes the preference
/// while establishing that connection; custom connectors must do the same for
/// this option to have an effect. CONNECT does not encrypt the plaintext origin
/// traffic carried inside it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Extension)]
#[extension(tags(http, proxy))]
pub enum PlaintextHttpProxyMode {
    /// Send an ordinary forward-proxy request (absolute-form on HTTP/1).
    #[default]
    Forward,
    /// Establish an HTTP CONNECT tunnel before sending the origin request.
    Tunnel,
}

impl PlaintextHttpProxyMode {
    /// Whether the application protocol should use ordinary forwarding when
    /// connecting through an HTTP(S) proxy. Secure, unknown, and non-HTTP
    /// application protocols require a tunnel regardless of this preference.
    #[must_use]
    pub fn should_forward(self, application_protocol: Option<&rama_net::Protocol>) -> bool {
        self == Self::Forward
            && application_protocol
                .is_some_and(|protocol| protocol.is_http_based() && !protocol.is_secure())
    }
}

/// Returns true if the provided request is an ordinary (proxy) CONNECT request.
///
/// On HTTP/2 and HTTP/3 a CONNECT carrying a [`Protocol`] is Extended CONNECT
/// (RFC 8441, RFC 9220), which targets an origin resource rather than a tunnel.
pub fn is_req_http_proxy_connect<Body>(req: &Request<Body>) -> bool {
    req.method() == Method::CONNECT
        && (req.version() <= Version::HTTP_11 || !req.extensions().contains::<Protocol>())
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// [`Matcher`] implementation which uses [`is_req_http_proxy_connect`].
pub struct HttpProxyConnectMatcher;

impl HttpProxyConnectMatcher {
    #[inline(always)]
    #[must_use]
    /// Create a new [`HttpProxyConnectMatcher`].
    pub fn new() -> Self {
        Self
    }
}

impl<Body> Matcher<Request<Body>> for HttpProxyConnectMatcher {
    #[inline(always)]
    fn matches(&self, _ext: Option<&Extensions>, req: &Request<Body>) -> bool {
        is_req_http_proxy_connect(req)
    }
}

#[cfg(test)]
mod tests {
    use super::{PlaintextHttpProxyMode, ProxyRequestBody, is_req_http_proxy_connect};
    use crate::{
        Body, BodyExtractExt as _, Method, Request, StreamingBody as _, Version,
        proto::ext::Protocol as UpgradeProtocol,
    };
    use rama_core::extensions::ExtensionsRef as _;

    #[tokio::test]
    async fn a_proxy_request_body_is_empty_or_the_forwarded_one() {
        let empty = ProxyRequestBody::<Body>::default();
        assert!(empty.is_end_stream());
        assert_eq!(empty.size_hint().exact(), Some(0));
        assert_eq!(Body::new(empty).try_into_string().await.unwrap(), "");

        let forwarded = ProxyRequestBody::forwarded(Body::from("hello"));
        assert!(!forwarded.is_end_stream());
        assert_eq!(forwarded.size_hint().exact(), Some(5));
        assert_eq!(
            Body::new(forwarded).try_into_string().await.unwrap(),
            "hello"
        );
    }

    #[test]
    fn ordinary_connect_is_recognized_on_every_version() {
        for version in [
            Version::HTTP_10,
            Version::HTTP_11,
            Version::HTTP_2,
            Version::HTTP_3,
        ] {
            let request = Request::builder()
                .method(Method::CONNECT)
                .version(version)
                .uri("example.com:443")
                .body(())
                .unwrap();
            assert!(is_req_http_proxy_connect(&request), "{version:?}");
            request.extensions().insert(UpgradeProtocol::WEBSOCKET);
            assert_eq!(
                is_req_http_proxy_connect(&request),
                version <= Version::HTTP_11,
                "{version:?}"
            );
            let get = Request::builder().version(version).body(()).unwrap();
            assert!(!is_req_http_proxy_connect(&get));
        }
    }
    use rama_net::Protocol;

    #[test]
    fn plaintext_forwarding_requires_a_known_plaintext_http_protocol() {
        for (protocol, forward) in [
            (None, false),
            (Some(Protocol::HTTP), true),
            (Some(Protocol::WS), true),
            (Some(Protocol::HTTPS), false),
            (Some(Protocol::WSS), false),
            (Some(Protocol::SOCKS5), false),
            (Some("custom".parse().unwrap()), false),
        ] {
            assert_eq!(
                PlaintextHttpProxyMode::Forward.should_forward(protocol.as_ref()),
                forward,
                "application protocol: {protocol:?}"
            );
            assert!(!PlaintextHttpProxyMode::Tunnel.should_forward(protocol.as_ref()));
        }
    }
}
