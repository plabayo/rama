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
use rama_utils::macros::generate_set_and_with;

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

/// A single route through which a client connection can be established.
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

/// Ordered proxy routes to try while establishing a client connection.
///
/// An empty route collection has the same meaning as a single
/// [`ProxyRoute::Direct`] route.
///
/// Each route can optionally carry route-specific [`Extensions`]. The
/// [`ProxyRoutesConnector`](super::ProxyRoutesConnector) installs those only
/// on that route's isolated connection attempt. Collect `(route, extensions)`
/// pairs to attach them without exposing an entry wrapper in the public API.
#[derive(Debug, Clone, Default, Extension)]
#[extension(tags(net, proxy))]
pub struct ProxyRoutes {
    routes: Box<[ProxyRoute]>,
    extensions: Box<[Option<Extensions>]>,
    overwrite: bool,
}

impl ProxyRoutes {
    /// Create an ordered collection from the given proxy routes.
    #[must_use]
    pub fn new(routes: impl IntoIterator<Item = ProxyRoute>) -> Self {
        routes.into_iter().collect()
    }

    generate_set_and_with! {
        /// Allow this route collection to take precedence over an existing
        /// singular [`ProxyRoute`].
        ///
        /// Overwriting is disabled by default.
        pub const fn overwrite(mut self, overwrite: bool) -> Self {
            self.overwrite = overwrite;
            self
        }
    }

    /// Return whether this collection may overwrite a singular route.
    #[must_use]
    pub const fn overwrite(&self) -> bool {
        self.overwrite
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
            overwrite: false,
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
        Self {
            routes,
            extensions,
            overwrite: false,
        }
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
            overwrite: false,
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
            overwrite: false,
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
    fn empty_routes_are_preserved_for_direct_fallback() {
        let routes = ProxyRoutes::default();
        assert!(routes.as_slice().is_empty());
        assert_eq!(routes.iter().count(), 0);
        assert!(!routes.overwrite());
    }

    #[test]
    fn route_collection_can_opt_into_overwrite() {
        let routes = ProxyRoutes::default().with_overwrite(true);
        assert!(routes.overwrite());
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
