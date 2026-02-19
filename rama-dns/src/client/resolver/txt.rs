use std::{convert::Infallible, pin::Pin, sync::Arc};

use rama_core::{
    bytes::Bytes,
    error::BoxError,
    futures::{Stream, StreamExt as _, TryStreamExt, stream},
};
use rama_net::address::{Domain, DomainTrie};

/// A resolver of Domains into TXT records.
pub trait DnsTxtResolver: Sized + Send + Sync + 'static {
    /// Error returned by the [`DnsTxtResolver`]
    type Error: Into<BoxError> + Send + 'static;

    /// Resolve the 'TXT' records accessible by this resolver for the given [`Domain`] into [`Bytes`].
    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_;

    /// Box this resolver to allow for dynamic dispatch.
    fn into_box_dns_txt_resolver(self) -> BoxDnsTxtResolver {
        BoxDnsTxtResolver::new(self)
    }
}

impl<R: DnsTxtResolver> DnsTxtResolver for Arc<R> {
    type Error = R::Error;

    #[inline(always)]
    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_ {
        self.as_ref().lookup_txt(domain)
    }
}

impl<R: DnsTxtResolver> DnsTxtResolver for Option<R> {
    type Error = R::Error;

    #[inline(always)]
    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_ {
        stream::iter(self.as_ref().map(|resolver| resolver.lookup_txt(domain))).flatten()
    }
}

impl DnsTxtResolver for Bytes {
    type Error = Infallible;

    fn lookup_txt(&self, _: Domain) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_ {
        stream::once(std::future::ready(Ok(self.clone())))
    }
}

impl<R: DnsTxtResolver> DnsTxtResolver for DomainTrie<R> {
    type Error = R::Error;

    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_ {
        stream::iter(self.match_exact(domain.clone()))
            .flat_map(move |resolver| resolver.lookup_txt(domain.clone()))
    }
}

/// Internal trait for dynamic dispatch of Async Traits,
/// implemented according to the pioneers of this Design Pattern
/// found at <https://rust-lang.github.io/async-fundamentals-initiative/evaluation/case-studies/builder-provider-api.html#dynamic-dispatch-behind-the-api>
/// and widely published at <https://blog.rust-lang.org/inside-rust/2023/05/03/stabilizing-async-fn-in-trait.html>.
trait DynDnsTxtResolver {
    fn dyn_lookup_txt(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Bytes, BoxError>> + Send + '_>>;
}

impl<T: DnsTxtResolver> DynDnsTxtResolver for T {
    fn dyn_lookup_txt(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Bytes, BoxError>> + Send + '_>> {
        Box::pin(self.lookup_txt(domain).map_err(Into::into))
    }
}

/// A boxed [`DnsTxtResolver`], to resolve dns TXT records,
/// for where you require dynamic dispatch.
pub struct BoxDnsTxtResolver {
    inner: Arc<dyn DynDnsTxtResolver + Send + Sync + 'static>,
}

impl Clone for BoxDnsTxtResolver {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl BoxDnsTxtResolver {
    /// Create a new [`BoxDnsTxtResolver`] from the given dns resolver.
    #[inline]
    pub fn new<T>(txt_resolver: T) -> Self
    where
        T: DnsTxtResolver,
    {
        Self {
            inner: Arc::new(InnerDnsTxtResolver(txt_resolver)),
        }
    }
}

struct InnerDnsTxtResolver<T>(T);

impl<T: DnsTxtResolver> DnsTxtResolver for InnerDnsTxtResolver<T> {
    type Error = BoxError;

    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_ {
        self.0.lookup_txt(domain).map_err(Into::into)
    }
}

impl std::fmt::Debug for BoxDnsTxtResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoxDnsTxtResolver").finish()
    }
}

impl DnsTxtResolver for BoxDnsTxtResolver {
    type Error = BoxError;

    #[inline]
    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_ {
        self.inner.dyn_lookup_txt(domain)
    }

    fn into_box_dns_txt_resolver(self) -> BoxDnsTxtResolver {
        self
    }
}
