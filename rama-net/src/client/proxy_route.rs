use rama_core::extensions::Extension;

use crate::{address::ProxyAddress, std::vec::Vec};

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
pub struct ProxyRoutes(Box<[ProxyRoute]>);

impl ProxyRoutes {
    /// Create an ordered collection from the given proxy routes.
    #[must_use]
    pub fn new(routes: impl IntoIterator<Item = ProxyRoute>) -> Self {
        Self(routes.into_iter().collect())
    }

    /// Return the explicitly configured routes in their preferred order.
    #[must_use]
    pub const fn as_slice(&self) -> &[ProxyRoute] {
        &self.0
    }

    /// Iterate over the explicitly configured routes in preferred order.
    pub fn iter(&self) -> impl Iterator<Item = &ProxyRoute> {
        self.0.iter()
    }
}

impl From<Vec<ProxyRoute>> for ProxyRoutes {
    fn from(value: Vec<ProxyRoute>) -> Self {
        Self(value.into_boxed_slice())
    }
}

impl From<Box<[ProxyRoute]>> for ProxyRoutes {
    fn from(value: Box<[ProxyRoute]>) -> Self {
        Self(value)
    }
}

impl From<ProxyRoute> for ProxyRoutes {
    fn from(value: ProxyRoute) -> Self {
        Self(Box::new([value]))
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
        self.0.iter()
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
    }
}
