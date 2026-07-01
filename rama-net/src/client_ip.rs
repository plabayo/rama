//! Resolve the client IP of a request or connection from its extensions.
//!
//! [`client_ip`] is the reusable resolver: it prefers the proxy-supplied
//! [`Forwarded`] client IP (populated by forwarded-header / PROXY-protocol
//! parsing) and falls back to the transport [`SocketInfo`] peer address.
//!
//! [`ClientIp`] is method sugar (`x.client_ip()`). It is intentionally a
//! plain trait — **not** bounded on [`ExtensionsRef`] and **not** blanket-
//! implemented — so each request/input type opts in with the behaviour that
//! fits it. Most types delegate to [`client_ip`]; a type that knows its peer
//! directly could resolve it differently.

use core::net::IpAddr;

use crate::forwarded::Forwarded;

use rama_core::extensions::ExtensionsRef;

#[cfg(feature = "std")]
use crate::stream::SocketInfo;

/// Best-effort client IP read from `ext`'s extensions: the [`Forwarded`]
/// client IP when present, otherwise the [`SocketInfo`] peer IP, otherwise
/// `None`.
pub fn client_ip(ext: &impl ExtensionsRef) -> Option<IpAddr> {
    let extensions = ext.extensions();
    let forwarded = extensions
        .get_ref::<Forwarded>()
        .and_then(Forwarded::client_ip);
    #[cfg(feature = "std")]
    {
        forwarded.or_else(|| {
            extensions
                .get_ref::<SocketInfo>()
                .map(|info| info.peer_addr().ip_addr)
        })
    }
    #[cfg(not(feature = "std"))]
    {
        forwarded
    }
}

/// Best-effort client-IP accessor, implemented per request/input type.
///
/// Deliberately has no [`ExtensionsRef`] bound and no blanket impl: a blanket
/// would force one behaviour onto every extensions-carrying type (including
/// IO/service wrappers) and block custom impls. Implement it explicitly per
/// type instead — e.g. the http `Request`/`Parts` impls in `rama-http-types`
/// delegate to [`client_ip`], but other inputs may resolve their client IP
/// differently.
pub trait ClientIp {
    /// Best-effort client IP — see [`client_ip`] for the common resolution.
    fn client_ip(&self) -> Option<IpAddr>;
}

#[cfg(test)]
mod tests {
    use super::*;

    use rama_core::extensions::Extensions;

    #[cfg(feature = "std")]
    use crate::address::SocketAddress;
    #[cfg(feature = "std")]
    use crate::forwarded::{ForwardedElement, NodeId};
    #[cfg(feature = "std")]
    use crate::stream::SocketInfo;

    #[cfg(feature = "std")]
    fn socket_info(ip: &str) -> SocketInfo {
        SocketInfo::new(None, SocketAddress::new(ip.parse().unwrap(), 0))
    }

    #[test]
    fn none_when_no_extensions() {
        let ext = Extensions::new();
        assert_eq!(client_ip(&ext), None);
    }

    #[cfg(feature = "std")]
    fn forwarded_for(node: &str) -> Forwarded {
        Forwarded::new(ForwardedElement::new_forwarded_for(
            NodeId::try_from(node).unwrap(),
        ))
    }

    #[cfg(feature = "std")]
    #[test]
    fn falls_back_to_socket_info_peer() {
        let ext = Extensions::new();
        ext.insert(socket_info("203.0.113.5"));
        assert_eq!(client_ip(&ext), Some("203.0.113.5".parse().unwrap()));
    }

    #[cfg(feature = "std")]
    #[test]
    fn prefers_forwarded_over_socket_info() {
        let ext = Extensions::new();
        ext.insert(socket_info("203.0.113.5"));
        ext.insert(forwarded_for("192.0.2.43"));
        assert_eq!(client_ip(&ext), Some("192.0.2.43".parse().unwrap()));
    }

    #[cfg(feature = "std")]
    #[test]
    fn forwarded_without_client_ip_falls_back_to_socket_info() {
        let ext = Extensions::new();
        ext.insert(socket_info("203.0.113.5"));
        // obfuscated node -> no client IP from Forwarded
        ext.insert(forwarded_for("_hidden"));
        assert_eq!(client_ip(&ext), Some("203.0.113.5".parse().unwrap()));
    }
}
