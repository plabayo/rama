mod response;
use rama_core::extensions::ExtensionsRef;
use rama_http::{Method, Request, Version};
use rama_http_core::h2::ext::Protocol;

pub use self::response::DefaultHttpProxyConnectReplyService;

mod mitm;
pub use self::mitm::{HttpProxyConnectMitmRelay, HttpProxyConnectMitmRelayLayer};

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
