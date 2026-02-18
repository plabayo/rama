use std::{pin::Pin, sync::Arc};

use rama_core::{
    bytes::Bytes,
    error::BoxError,
    futures::{Stream, TryStreamExt},
};
use rama_net::address::Domain;

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

/// Internal trait for dynamic dispatch of Async Traits,
/// implemented according to the pioneers of this Design Pattern
/// found at <https://rust-lang.github.io/async-fundamentals-initiative/evaluation/case-studies/builder-provider-api.html#dynamic-dispatch-behind-the-api>
/// and widely published at <https://blog.rust-lang.org/inside-rust/2023/05/03/stabilizing-async-fn-in-trait.html>.
trait DynDnsTxtResolver {
    type Error: Into<BoxError> + Send + 'static;

    fn dyn_lookup_txt(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Bytes, Self::Error>> + Send + '_>>;
}

impl<T: DnsTxtResolver> DynDnsTxtResolver for T {
    type Error = T::Error;

    fn dyn_lookup_txt(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Bytes, Self::Error>> + Send + '_>> {
        Box::pin(self.lookup_txt(domain))
    }
}

/// A boxed [`DnsTxtResolver`], to resolve dns TXT records,
/// for where you require dynamic dispatch.
pub struct BoxDnsTxtResolver {
    inner: Arc<dyn DynDnsTxtResolver<Error = BoxError> + Send + Sync + 'static>,
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
