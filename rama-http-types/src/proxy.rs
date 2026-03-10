use crate::{Method, Request, Version, proto::h2::ext::Protocol};
use rama_core::extensions::ExtensionsRef as _;

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
