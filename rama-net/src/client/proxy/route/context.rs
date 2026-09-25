use super::{ProxyRoute, ProxyRoutes};
use rama_core::extensions::{Extensions, FromExtensions};
use std::{
    hash::{Hash, Hasher},
    sync::Arc,
};

/// Requested proxy route or ordered route plan used to scope connection outcomes.
///
/// Capture this before route selection and retain it with the attempt: a failure
/// of one plan says nothing about another plan or a direct connection. Routes and
/// credentials remain shared. Consult [`Self::cacheable`] before sharing outcomes;
/// equality does not compare opaque route-local extensions.
#[derive(Clone, Debug, FromExtensions)]
pub enum ProxyRouteContext {
    /// A singular requested route; this is not proof of an established proxy.
    Route(Arc<ProxyRoute>),
    /// A configured route plan, before one route succeeds.
    Routes(Arc<ProxyRoutes>),
}

impl ProxyRouteContext {
    /// Capture the most recently inserted route decision from request metadata.
    /// Plain direct routing returns `None`; direct plans with opaque policy are retained.
    pub fn for_request(extensions: &Extensions) -> Option<Self> {
        Self::from_extensions(extensions).filter(|context| {
            !context.cacheable()
                || context
                    .routes()
                    .iter()
                    .any(|route| route.proxy_address().is_some())
        })
    }

    /// Whether the route plan contains only stable, comparable route policies.
    /// Opaque route-local extensions must not contribute to shared backoff.
    pub fn cacheable(&self) -> bool {
        match self {
            Self::Route(_) => true,
            // Route-local extensions are opaque to this outer selector. They
            // may change DNS, TLS or network policy despite identical addresses.
            Self::Routes(routes) => {
                (0..routes.as_slice().len()).all(|index| routes.route_extensions(index).is_none())
            }
        }
    }

    fn routes(&self) -> &[ProxyRoute] {
        match self {
            Self::Route(route) => std::slice::from_ref(route.as_ref()),
            Self::Routes(routes) => routes.as_slice(),
        }
    }
}

impl PartialEq for ProxyRouteContext {
    fn eq(&self, other: &Self) -> bool {
        self.routes() == other.routes()
    }
}

impl Eq for ProxyRouteContext {}

impl Hash for ProxyRouteContext {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.routes().len().hash(state);
        for route in self.routes() {
            route.proxy_address().hash(state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;

    fn hash(context: &ProxyRouteContext) -> u64 {
        let mut state = DefaultHasher::new();
        context.hash(&mut state);
        state.finish()
    }

    #[test]
    fn capture_preserves_the_latest_route_decision() {
        let extensions = Extensions::new();
        let proxy = ProxyRoute::Proxy("http://proxy.example:3128".parse().unwrap());
        extensions.insert(ProxyRoutes::new([proxy.clone(), ProxyRoute::Direct]));
        let plan = ProxyRouteContext::for_request(&extensions).unwrap();
        extensions.insert(proxy.clone());
        let selected = ProxyRouteContext::for_request(&extensions).unwrap();
        assert_ne!(plan, selected);
        let single = ProxyRouteContext::Routes(Arc::new(ProxyRoutes::new([proxy])));
        assert_eq!(single, selected);
        assert_eq!(hash(&single), hash(&selected));
        extensions.insert(ProxyRoute::Direct);
        assert!(ProxyRouteContext::for_request(&extensions).is_none());
    }

    #[test]
    fn direct_plans_with_opaque_policy_remain_request_scoped() {
        let extensions = Extensions::new();
        extensions.insert(ProxyRoutes::from_iter([(
            ProxyRoute::Direct,
            Extensions::new(),
        )]));
        let context = ProxyRouteContext::for_request(&extensions).unwrap();
        assert!(!context.cacheable());
    }
}
