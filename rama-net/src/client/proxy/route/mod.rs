mod failure_cache;
#[doc(inline)]
pub use failure_cache::{
    ProxyRouteFailureCache, ProxyRouteFailureCacheConfig, ProxyRouteFailureCacheConnector,
    ProxyRouteFailureCacheLayer, ProxyRouteFailureCacheScope, ProxyRouteFailureCachedError,
};

mod routes;
#[doc(inline)]
pub use routes::{
    ProxyRouteConnectError, ProxyRoutesConnector, ProxyRoutesConnectorLayer, ProxyRoutesLayer,
    ProxyRoutesService,
};

use rama_core::extensions::{Extension, Extensions};

use crate::{address::ProxyAddress, std::vec::Vec};

/// Index of the selected route within the ordered route collection.
///
/// [`ProxyRoutesConnector`](super::ProxyRoutesConnector) inserts this into the
/// successful attempt input alongside its singular [`ProxyRoute`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
#[extension(tags(net, proxy))]
pub struct ProxyRouteIndex(usize);

impl ProxyRouteIndex {
    /// Create a selected route index.
    #[must_use]
    pub const fn new(index: usize) -> Self {
        Self(index)
    }

    /// Return the zero-based index in the ordered route collection.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

/// A requested route through which a client connection should be established.
///
/// This is connection input, not evidence that a proxy was used. Inspect
/// [`EstablishedProxyRoute`] on the connection for the actual outcome after
/// route fallback and connection-pool selection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Extension)]
#[extension(tags(net, proxy))]
pub enum ProxyRoute {
    /// Connect to the requested authority without using a proxy.
    #[default]
    Direct,
    /// Connect to the requested authority through the given proxy.
    Proxy(ProxyAddress),
}

impl ProxyRoute {
    /// Return the proxy address when this is a proxied route.
    #[must_use]
    pub const fn proxy_address(&self) -> Option<&ProxyAddress> {
        match self {
            Self::Direct => None,
            Self::Proxy(address) => Some(address),
        }
    }

    /// Consume this route and return its proxy address when proxied.
    #[must_use]
    pub fn into_proxy_address(self) -> Option<ProxyAddress> {
        match self {
            Self::Direct => None,
            Self::Proxy(address) => Some(address),
        }
    }
}

impl From<ProxyAddress> for ProxyRoute {
    fn from(value: ProxyAddress) -> Self {
        Self::Proxy(value)
    }
}

/// The proxy route actually established by a connector.
///
/// This is the authoritative connection outcome; [`ProxyRoute`] only describes
/// the requested route. The connector publishes this extension after success,
/// preserving the selected proxy address and credentials before dial-address
/// normalization. HTTP forwarding and CONNECT are distinct outcomes even when
/// they use the same proxy and origin.
///
/// A requested route that connects directly, including direct fallback or an
/// explicit bypass, publishes [`Self::Direct`]. An ordinary direct connection
/// for which no route was requested has no `EstablishedProxyRoute` extension.
/// Custom connectors must follow the same contract. Request metadata must never
/// be used to infer an established proxy connection.
#[derive(Debug, Clone, PartialEq, Eq, Extension)]
#[extension(tags(net, proxy))]
#[non_exhaustive]
pub enum EstablishedProxyRoute {
    /// A route was requested, but the connection was established without a proxy.
    Direct,
    /// Application requests are sent directly to an HTTP(S) forward proxy.
    Forward(ProxyAddress),
    /// A successful HTTP or SOCKS CONNECT exchange established an opaque tunnel.
    /// The selected proxy address carries its configured protocol. A tunnel
    /// does not itself imply encryption of the application traffic.
    Tunnel(ProxyAddress),
}

impl EstablishedProxyRoute {
    /// Return the exact selected proxy address when a proxy was established.
    #[must_use]
    pub const fn proxy_address(&self) -> Option<&ProxyAddress> {
        match self {
            Self::Direct => None,
            Self::Forward(proxy) | Self::Tunnel(proxy) => Some(proxy),
        }
    }

    /// Whether application requests are addressed to an HTTP forward proxy.
    #[must_use]
    pub fn is_http_forward(&self) -> bool {
        matches!(self, Self::Forward(proxy) if proxy.protocol.as_ref().is_none_or(|protocol| protocol.is_http()))
    }
}

/// Ordered proxy routes to try while establishing a client connection.
///
/// An empty route collection has the same meaning as a single
/// [`ProxyRoute::Direct`] route.
///
/// Each route can optionally carry route-specific [`Extensions`]. The
/// [`ProxyRoutesConnector`](super::ProxyRoutesConnector) installs those only
/// on that route's isolated connection attempt. Collect `(route, extensions)`
/// pairs to attach them without exposing an entry wrapper in the public API.
/// [`ProxyRoutesLayer`](super::ProxyRoutesLayer) and
/// [`ProxyRoutesConnector`](super::ProxyRoutesConnector) resolve this type
/// together with [`ProxyRoute`] using insertion order: the most recently
/// inserted decision wins. Compose `ProxyRoutesLayer` after route-selection
/// layers when downstream middleware needs the selected singular route.
#[derive(Debug, Clone, Default, Extension)]
#[extension(tags(net, proxy))]
pub struct ProxyRoutes {
    routes: Box<[ProxyRoute]>,
    extensions: Box<[Option<Extensions>]>,
}

impl ProxyRoutes {
    /// Create an ordered collection from the given proxy routes.
    #[must_use]
    pub fn new(routes: impl IntoIterator<Item = ProxyRoute>) -> Self {
        routes.into_iter().collect()
    }

    /// Return the explicitly configured routes in their preferred order.
    #[must_use]
    pub const fn as_slice(&self) -> &[ProxyRoute] {
        &self.routes
    }

    /// Iterate over the explicitly configured routes in preferred order.
    pub fn iter(&self) -> impl Iterator<Item = &ProxyRoute> {
        self.routes.iter()
    }

    /// Return the extensions attached to the route at `index`, when present.
    #[must_use]
    pub fn route_extensions(&self, index: usize) -> Option<&Extensions> {
        self.extensions.get(index).and_then(Option::as_ref)
    }
}

impl From<Vec<ProxyRoute>> for ProxyRoutes {
    fn from(value: Vec<ProxyRoute>) -> Self {
        value.into_iter().collect()
    }
}

impl From<Box<[ProxyRoute]>> for ProxyRoutes {
    fn from(value: Box<[ProxyRoute]>) -> Self {
        let extensions = Box::new([]);
        Self {
            routes: value,
            extensions,
        }
    }
}

impl From<ProxyRoute> for ProxyRoutes {
    fn from(value: ProxyRoute) -> Self {
        Self::new([value])
    }
}

impl From<ProxyAddress> for ProxyRoutes {
    fn from(value: ProxyAddress) -> Self {
        core::iter::once(value).collect()
    }
}

impl FromIterator<ProxyRoute> for ProxyRoutes {
    fn from_iter<I: IntoIterator<Item = ProxyRoute>>(iter: I) -> Self {
        let routes = iter.into_iter().collect();
        let extensions = Box::new([]);
        Self { routes, extensions }
    }
}

/// Collect proxy-address-like values into ordered proxy routes.
impl<T> FromIterator<T> for ProxyRoutes
where
    T: Into<ProxyAddress>,
{
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        iter.into_iter()
            .map(|address| ProxyRoute::Proxy(address.into()))
            .collect()
    }
}

/// Collect proxy-address-like values with optional route-specific extensions.
impl<T, E> FromIterator<(T, E)> for ProxyRoutes
where
    T: Into<ProxyAddress>,
    E: Into<Option<Extensions>>,
{
    fn from_iter<I: IntoIterator<Item = (T, E)>>(iter: I) -> Self {
        let (routes, extensions): (Vec<_>, Vec<_>) = iter
            .into_iter()
            .map(|(address, extensions)| (ProxyRoute::Proxy(address.into()), extensions.into()))
            .unzip();
        Self {
            routes: routes.into(),
            extensions: extensions.into(),
        }
    }
}

/// Collect direct or proxied routes with optional route-specific extensions.
impl<E> FromIterator<(ProxyRoute, E)> for ProxyRoutes
where
    E: Into<Option<Extensions>>,
{
    fn from_iter<I: IntoIterator<Item = (ProxyRoute, E)>>(iter: I) -> Self {
        let (routes, extensions): (Vec<_>, Vec<_>) = iter
            .into_iter()
            .map(|(route, extensions)| (route, extensions.into()))
            .unzip();
        Self {
            routes: routes.into(),
            extensions: extensions.into(),
        }
    }
}

impl<'a> IntoIterator for &'a ProxyRoutes {
    type Item = &'a ProxyRoute;
    type IntoIter = core::slice::Iter<'a, ProxyRoute>;

    fn into_iter(self) -> Self::IntoIter {
        self.routes.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct IntoProxyAddress(ProxyAddress);

    impl From<IntoProxyAddress> for ProxyAddress {
        fn from(value: IntoProxyAddress) -> Self {
            value.0
        }
    }

    #[derive(Debug, Extension)]
    struct RoutePreference(&'static str);

    fn proxy_address(name: &str) -> ProxyAddress {
        format!("http://{name}.example:8080").parse().unwrap()
    }

    #[test]
    fn direct_is_the_default_route() {
        assert_eq!(ProxyRoute::default(), ProxyRoute::Direct);
    }

    #[test]
    fn established_forward_route_requires_an_http_proxy_protocol() {
        assert!(!EstablishedProxyRoute::Direct.is_http_forward());
        for (protocol, forwards) in [
            (None, true),
            (Some(crate::Protocol::HTTP), true),
            (Some(crate::Protocol::HTTPS), true),
            (Some(crate::Protocol::SOCKS5), false),
            (Some(crate::Protocol::SOCKS5H), false),
            (Some(crate::Protocol::WS), false),
            (Some(crate::Protocol::from_static("custom")), false),
        ] {
            let proxy = ProxyAddress {
                protocol,
                ..proxy_address("selected")
            };
            assert_eq!(
                EstablishedProxyRoute::Forward(proxy.clone()).is_http_forward(),
                forwards,
                "proxy protocol: {:?}",
                proxy.protocol,
            );
            assert!(!EstablishedProxyRoute::Tunnel(proxy).is_http_forward());
        }
    }

    #[test]
    fn established_route_debug_redacts_proxy_secrets() {
        let proxy: ProxyAddress = "http://alice:proxy-secret@proxy.example:8080"
            .parse()
            .unwrap();
        for route in [
            EstablishedProxyRoute::Forward(proxy.clone()),
            EstablishedProxyRoute::Tunnel(proxy),
        ] {
            let debug = format!("{route:?}");
            assert!(debug.contains("proxy.example"), "{debug}");
            assert!(!debug.contains("proxy-secret"), "{debug}");
        }
    }

    #[test]
    fn empty_routes_are_preserved_for_direct_fallback() {
        let routes = ProxyRoutes::default();
        assert!(routes.as_slice().is_empty());
        assert_eq!(routes.iter().count(), 0);
    }

    #[test]
    fn proxy_routes_collect_values_convertible_into_proxy_addresses() {
        let routes = [
            IntoProxyAddress(proxy_address("first")),
            IntoProxyAddress(proxy_address("second")),
        ]
        .into_iter()
        .collect::<ProxyRoutes>();

        assert_eq!(routes.as_slice().len(), 2);
        assert_eq!(
            routes.as_slice()[0]
                .proxy_address()
                .unwrap()
                .address
                .host
                .to_string(),
            "first.example"
        );
        assert!(routes.route_extensions(0).is_none());
        assert!(routes.route_extensions(1).is_none());
    }

    #[test]
    fn proxy_routes_collect_addresses_with_optional_extensions() {
        let extensions = Extensions::new();
        extensions.insert(RoutePreference("http/2"));
        let routes = [
            (IntoProxyAddress(proxy_address("first")), Some(extensions)),
            (IntoProxyAddress(proxy_address("second")), None),
        ]
        .into_iter()
        .collect::<ProxyRoutes>();

        assert_eq!(routes.as_slice().len(), 2);
        assert_eq!(
            routes
                .route_extensions(0)
                .and_then(|extensions| extensions.get_ref::<RoutePreference>())
                .map(|preference| preference.0),
            Some("http/2")
        );
        assert!(routes.route_extensions(1).is_none());
    }

    #[test]
    fn proxy_routes_collect_direct_route_with_extensions() {
        let extensions = Extensions::new();
        extensions.insert(RoutePreference("direct"));
        let routes = [(ProxyRoute::Direct, extensions)]
            .into_iter()
            .collect::<ProxyRoutes>();

        assert_eq!(routes.as_slice(), [ProxyRoute::Direct]);
        assert_eq!(
            routes
                .route_extensions(0)
                .and_then(|extensions| extensions.get_ref::<RoutePreference>())
                .map(|preference| preference.0),
            Some("direct")
        );
    }

    #[test]
    fn selected_route_index_roundtrips() {
        assert_eq!(ProxyRouteIndex::new(42).get(), 42);
    }
}
