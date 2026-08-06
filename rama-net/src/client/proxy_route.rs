use rama_core::extensions::Extension;

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
#[derive(Debug, Clone, Default, PartialEq, Eq, Extension)]
#[extension(tags(net, proxy))]
pub struct ProxyRoutes {
    routes: Box<[ProxyRoute]>,
    overwrite: bool,
}

impl ProxyRoutes {
    /// Create an ordered collection from the given proxy routes.
    #[must_use]
    pub fn new(routes: impl IntoIterator<Item = ProxyRoute>) -> Self {
        Self {
            routes: routes.into_iter().collect(),
            overwrite: false,
        }
    }

    /// Allow this route collection to take precedence over an existing
    /// singular [`ProxyRoute`].
    ///
    /// Overwriting is disabled by default.
    #[must_use]
    pub const fn with_overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite = overwrite;
        self
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
}

impl From<Vec<ProxyRoute>> for ProxyRoutes {
    fn from(value: Vec<ProxyRoute>) -> Self {
        Self {
            routes: value.into_boxed_slice(),
            overwrite: false,
        }
    }
}

impl From<Box<[ProxyRoute]>> for ProxyRoutes {
    fn from(value: Box<[ProxyRoute]>) -> Self {
        Self {
            routes: value,
            overwrite: false,
        }
    }
}

impl From<ProxyRoute> for ProxyRoutes {
    fn from(value: ProxyRoute) -> Self {
        Self {
            routes: Box::new([value]),
            overwrite: false,
        }
    }
}

impl FromIterator<ProxyRoute> for ProxyRoutes {
    fn from_iter<T: IntoIterator<Item = ProxyRoute>>(iter: T) -> Self {
        Self::new(iter)
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
    fn selected_route_index_roundtrips() {
        assert_eq!(ProxyRouteIndex::new(42).get(), 42);
    }
}
