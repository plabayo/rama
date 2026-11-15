use rama_core::extensions::{Extensions, ExtensionsRef, NoConnectionTransfer};

use crate::{
    address::ProxyAddress,
    client::{
        ConnectRequest, ConnectionError, ConnectorService, ConnectorTarget,
        ConnectorTransportProtocol, ProxyRoute,
    },
    http::{FallbackHttpVersion, HttpRequestVersion, TargetHttpVersion, Version},
    transport::TransportProtocol,
};

/// Create the request to establish the connection to `proxy` itself.
///
/// Connecting through a proxy is a nested client connection: the proxy is the target,
/// and the protocol spoken to it is its own. Its extensions are forked from those of
/// the request that will travel through the proxy, so per-request configuration still
/// reaches the connection to the proxy while its own writes stay local.
///
/// Everything deciding how the proxy is reached is the proxy's own, never the origin's: the
/// connection boundary stops the origin's connection facts such as its [`TargetHttpVersion`],
/// and this request writes its own [`ConnectorTarget`], [`ConnectorTransportProtocol`] and
/// [`ProxyRoute`]. A proxy is reached directly: it is never itself behind a proxy. An HTTP
/// proxy whose address names no version negotiates one, whatever the origin request asks.
#[must_use]
pub fn proxy_request(proxy: &ProxyAddress, extensions: &Extensions) -> ConnectRequest {
    let version = proxy.protocol.http_version();
    let transport_protocol = match version {
        Some(Version::HTTP_3) => TransportProtocol::Udp,
        _ => TransportProtocol::Tcp,
    };

    let extensions = extensions.fork_nested_connection(&NoConnectionTransfer);
    extensions.insert(ProxyRoute::Direct);
    extensions.insert(ConnectorTarget(proxy.address.clone()));
    extensions.insert(ConnectorTransportProtocol(transport_protocol));
    if let Some(version) = version {
        extensions.insert(TargetHttpVersion(version));
    } else if proxy.protocol.is_http() {
        extensions.insert(HttpRequestVersion(Version::HTTP_11));
        extensions.insert(FallbackHttpVersion(Version::HTTP_11));
    }

    ConnectRequest::new_with_extensions(proxy.address.clone(), extensions)
        .maybe_with_application_protocol(proxy.protocol.as_protocol())
        .with_transport_protocol(transport_protocol)
}

/// Establish the connection to `proxy` itself with `connector`, from [`proxy_request`].
pub async fn connect_to_proxy<S>(
    connector: &S,
    proxy: &ProxyAddress,
    extensions: &Extensions,
) -> Result<S::Connection, ConnectionError>
where
    S: ConnectorService<ConnectRequest>,
{
    connector
        .connect(proxy_request(proxy, extensions))
        .await
        .map(|established| established.conn)
        .map_err(|error| {
            error
                .context("establish connection to proxy")
                .context_field("address", proxy.address.clone())
                .context_debug_field("protocol", proxy.protocol.clone())
        })
}

/// The HTTP version spoken on `conn`, a connection to `proxy` made from [`proxy_request`].
///
/// That is the version the proxy address names, otherwise the one the connection settled on
/// as its [`TargetHttpVersion`], otherwise HTTP/1.1.
#[must_use]
pub fn proxy_http_version(proxy: &ProxyAddress, conn: &impl ExtensionsRef) -> Version {
    proxy
        .protocol
        .http_version()
        .or_else(|| {
            conn.extensions()
                .get_ref::<TargetHttpVersion>()
                .map(|target| target.0)
        })
        .unwrap_or(Version::HTTP_11)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ConnectorTargetInputExt as _, ConnectorTransportProtocolInputExt as _, Protocol,
        ProtocolInputExt as _, TargetHttpVersionInputExt as _, TransportProtocolInputExt as _,
        address::HostWithPort,
    };
    use rama_core::extensions::Extension;

    #[derive(Debug, Extension, PartialEq)]
    struct OriginMarker(u8);

    fn socks_proxy() -> ProxyAddress {
        "socks5://user:secret@proxy.example:1080".parse().unwrap()
    }

    #[test]
    fn the_connection_to_a_proxy_is_direct() {
        let origin = Extensions::new();
        origin.insert(ProxyRoute::Proxy(socks_proxy()));
        let request = proxy_request(&socks_proxy(), &origin);

        assert_eq!(
            request.extensions.get_ref::<ProxyRoute>(),
            Some(&ProxyRoute::Direct),
        );
    }

    #[test]
    fn proxy_request_targets_the_proxy_with_its_own_protocol() {
        let proxy = socks_proxy();
        let request = proxy_request(&proxy, &Extensions::new());

        assert_eq!(request.authority, proxy.address);
        assert_eq!(request.protocol(), Some(&Protocol::SOCKS5));
        assert_eq!(request.transport_protocol(), Some(TransportProtocol::Tcp));
    }

    #[test]
    fn an_http3_proxy_is_dialed_over_udp_with_its_version() {
        let proxy: ProxyAddress = "https://proxy.example:443".parse().unwrap();
        let proxy = proxy.with_http_version(Version::HTTP_3);
        let request = proxy_request(&proxy, &Extensions::new());

        assert_eq!(request.transport_protocol(), Some(TransportProtocol::Udp));
        assert_eq!(request.target_http_version(), Some(Version::HTTP_3));
    }

    #[test]
    fn proxy_request_forks_the_origin_extensions() {
        let origin = Extensions::new();
        origin.insert(OriginMarker(1));

        let request = proxy_request(&socks_proxy(), &origin);
        assert_eq!(request.extensions.get_ref(), Some(&OriginMarker(1)));

        request.extensions.insert(OriginMarker(2));
        assert_eq!(origin.get_ref(), Some(&OriginMarker(1)));
    }

    #[test]
    fn origin_connector_overrides_do_not_decide_how_the_proxy_is_dialed() {
        let proxy: ProxyAddress = "http://proxy.example:8080".parse().unwrap();
        let origin = Extensions::new();
        origin.insert(ConnectorTarget(
            HostWithPort::try_from("alternative.example:8443").unwrap(),
        ));
        origin.insert(ConnectorTransportProtocol(TransportProtocol::Udp));
        origin.insert(TargetHttpVersion(Version::HTTP_2));

        let request = proxy_request(&proxy, &origin);
        assert_eq!(request.connector_target(), Some(proxy.address));
        assert_eq!(
            request.connector_transport_protocol(),
            Some(TransportProtocol::Tcp)
        );
        assert_eq!(request.target_http_version(), Some(Version::HTTP_11));
    }

    #[test]
    fn a_proxy_without_a_version_negotiates_whatever_the_origin_asks_for() {
        let proxy: ProxyAddress = "https://proxy.example:443".parse().unwrap();
        let origin = Extensions::new();
        origin.insert(TargetHttpVersion(Version::HTTP_3));
        origin.insert(HttpRequestVersion(Version::HTTP_3));

        let request = proxy_request(&proxy, &origin);
        assert_eq!(request.target_http_version(), None);
        assert_eq!(
            request.extensions.get_ref::<HttpRequestVersion>(),
            Some(&HttpRequestVersion(Version::HTTP_11))
        );
        assert_eq!(
            request.connector_transport_protocol(),
            Some(TransportProtocol::Tcp)
        );
    }
}
