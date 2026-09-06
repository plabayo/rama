use crate::{Method, Request, Version, proto::h2::ext::Protocol};
use rama_core::{
    extensions::{Extension, Extensions, ExtensionsRef as _},
    matcher::Matcher,
};

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

#[cfg(test)]
mod tests {
    use super::PlaintextHttpProxyMode;
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

/// Returns true if the provided reuqest is a HTTP Proxy Connect request.
pub fn is_req_http_proxy_connect<Body>(req: &Request<Body>) -> bool {
    let http_version = req.version();
    if http_version <= Version::HTTP_11 {
        req.method() == Method::CONNECT
    } else if http_version == Version::HTTP_2 {
        req.method() == Method::CONNECT && !req.extensions().contains::<Protocol>()
    } else {
        false
    }
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
