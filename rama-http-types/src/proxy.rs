use crate::{Method, Request, Version, proto::h2::ext::Protocol};
use rama_core::{
    extensions::{Extensions, ExtensionsRef as _},
    matcher::Matcher,
};

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
    fn matches(&self, _ext: Option<&mut Extensions>, req: &Request<Body>) -> bool {
        is_req_http_proxy_connect(req)
    }
}
