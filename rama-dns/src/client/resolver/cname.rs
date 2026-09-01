use std::{convert::Infallible, pin::Pin, sync::Arc};

use rama_core::{
    error::{BoxError, ErrorExt, extra::OpaqueError},
    futures::{Stream, StreamExt as _, TryStreamExt as _, stream},
};
use rama_net::address::{Domain, DomainTrie};

use crate::wire::Name;

/// A resolver of domains into CNAME records.
pub trait DnsCnameResolver: Sized + Send + Sync + 'static {
    /// Error returned by this resolver.
    type Error: Into<BoxError> + Send + 'static;

    /// Resolve CNAME targets for the given domain.
    ///
    /// Each successful stream item is one CNAME target. A recursive resolver
    /// may return more than one item when it exposes an alias chain. This is
    /// an explicit CNAME query; other record lookups may follow aliases
    /// internally without exposing them through this method.
    fn lookup_cname(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Name, Self::Error>> + Send + '_;

    /// Box this resolver to allow dynamic dispatch.
    fn into_box_dns_cname_resolver(self) -> BoxDnsCnameResolver {
        BoxDnsCnameResolver::new(self)
    }
}

impl<R: DnsCnameResolver> DnsCnameResolver for Arc<R> {
    type Error = R::Error;

    #[inline(always)]
    fn lookup_cname(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Name, Self::Error>> + Send + '_ {
        self.as_ref().lookup_cname(domain)
    }
}

impl<R: DnsCnameResolver> DnsCnameResolver for Option<R> {
    type Error = R::Error;

    #[inline(always)]
    fn lookup_cname(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Name, Self::Error>> + Send + '_ {
        stream::iter(self.as_ref().map(|resolver| resolver.lookup_cname(domain))).flatten()
    }
}

impl DnsCnameResolver for Name {
    type Error = Infallible;

    fn lookup_cname(&self, _: Domain) -> impl Stream<Item = Result<Self, Self::Error>> + Send + '_ {
        stream::once(std::future::ready(Ok(self.clone())))
    }
}

impl<R: DnsCnameResolver> DnsCnameResolver for DomainTrie<R> {
    type Error = R::Error;

    fn lookup_cname(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Name, Self::Error>> + Send + '_ {
        stream::iter(self.match_exact(domain.clone()))
            .flat_map(move |resolver| resolver.lookup_cname(domain.clone()))
    }
}

trait DynDnsCnameResolver {
    fn dyn_lookup_cname(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Name, OpaqueError>> + Send + '_>>;
}

impl<T: DnsCnameResolver> DynDnsCnameResolver for T {
    fn dyn_lookup_cname(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Name, OpaqueError>> + Send + '_>> {
        Box::pin(
            self.lookup_cname(domain)
                .map_err(ErrorExt::into_opaque_error),
        )
    }
}

/// A boxed [`DnsCnameResolver`] mapping errors into [`OpaqueError`].
pub struct BoxDnsCnameResolver {
    inner: Arc<dyn DynDnsCnameResolver + Send + Sync + 'static>,
}

impl Clone for BoxDnsCnameResolver {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl BoxDnsCnameResolver {
    /// Create a boxed resolver.
    #[inline]
    pub fn new<T>(resolver: T) -> Self
    where
        T: DnsCnameResolver,
    {
        Self {
            inner: Arc::new(resolver),
        }
    }
}

impl std::fmt::Debug for BoxDnsCnameResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoxDnsCnameResolver").finish()
    }
}

impl DnsCnameResolver for BoxDnsCnameResolver {
    type Error = OpaqueError;

    #[inline(always)]
    fn lookup_cname(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Name, Self::Error>> + Send + '_ {
        self.inner.dyn_lookup_cname(domain)
    }

    fn into_box_dns_cname_resolver(self) -> BoxDnsCnameResolver {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn name_is_a_static_cname_resolver() {
        let name = Name::from_wire(b"\x03www\x07example\x03com\0").unwrap();
        let resolved = std::pin::pin!(name.lookup_cname(Domain::example()))
            .next()
            .await
            .expect("one item")
            .expect("infallible");
        assert_eq!(resolved, name);
    }

    #[tokio::test]
    async fn arc_option_trie_and_box_preserve_cname_targets() {
        let name = Name::from_wire(b"\x05alias\x07example\x03com\0").unwrap();
        let resolver = Arc::new(name.clone());
        assert_eq!(first(resolver.lookup_cname(Domain::example())).await, name);

        let optional = Some(resolver.as_ref().clone());
        assert_eq!(first(optional.lookup_cname(Domain::example())).await, name);

        let mut trie = DomainTrie::new();
        trie.insert_domain(Domain::example(), resolver.as_ref().clone());
        assert_eq!(first(trie.lookup_cname(Domain::example())).await, name);
        assert!(
            std::pin::pin!(trie.lookup_cname(Domain::from_static("other.example")))
                .next()
                .await
                .is_none()
        );

        let resolver = trie.into_box_dns_cname_resolver();
        assert_eq!(format!("{resolver:?}"), "BoxDnsCnameResolver");
        assert_eq!(first(resolver.lookup_cname(Domain::example())).await, name);
        let same = resolver.clone().into_box_dns_cname_resolver();
        assert_eq!(first(same.lookup_cname(Domain::example())).await, name);
    }

    async fn first<S, E>(stream: S) -> Name
    where
        S: Stream<Item = Result<Name, E>>,
        E: std::fmt::Debug,
    {
        std::pin::pin!(stream)
            .next()
            .await
            .expect("one record")
            .expect("successful record")
    }
}
