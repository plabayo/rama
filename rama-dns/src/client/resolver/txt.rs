use std::{convert::Infallible, pin::Pin, sync::Arc};

use rama_core::{
    bytes::Bytes,
    error::{BoxError, ErrorExt, extra::OpaqueError},
    futures::{Stream, StreamExt as _, TryStreamExt, stream},
};
use rama_net::address::{Domain, DomainTrie};

use crate::wire::{Txt, TxtParseError};

/// A resolver of Domains into TXT records.
pub trait DnsTxtResolver: Sized + Send + Sync + 'static {
    /// Error returned by the [`DnsTxtResolver`]
    type Error: Into<BoxError> + Send + 'static;

    /// Resolve the TXT records accessible for the given [`Domain`].
    ///
    /// Each successful stream item is one DNS record. Its [`Txt`] value
    /// preserves that record's one-or-more binary character-strings in order.
    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Txt, Self::Error>> + Send + '_;

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
    ) -> impl Stream<Item = Result<Txt, Self::Error>> + Send + '_ {
        self.as_ref().lookup_txt(domain)
    }
}

impl<R: DnsTxtResolver> DnsTxtResolver for Option<R> {
    type Error = R::Error;

    #[inline(always)]
    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Txt, Self::Error>> + Send + '_ {
        stream::iter(self.as_ref().map(|resolver| resolver.lookup_txt(domain))).flatten()
    }
}

impl DnsTxtResolver for Bytes {
    type Error = TxtParseError;

    /// Treat these bytes as one character-string in one TXT record.
    ///
    /// DNS character-strings are limited to 255 octets. Longer or explicitly
    /// multi-string records should use [`Txt::try_from_strings`] and the
    /// infallible [`DnsTxtResolver`] implementation for [`Txt`] instead. This
    /// implementation never splits the bytes automatically.
    fn lookup_txt(&self, _: Domain) -> impl Stream<Item = Result<Txt, Self::Error>> + Send + '_ {
        stream::once(std::future::ready(Txt::try_from_strings([self.as_ref()])))
    }
}

impl DnsTxtResolver for Txt {
    type Error = Infallible;

    fn lookup_txt(&self, _: Domain) -> impl Stream<Item = Result<Self, Self::Error>> + Send + '_ {
        stream::once(std::future::ready(Ok(self.clone())))
    }
}

impl<R: DnsTxtResolver> DnsTxtResolver for DomainTrie<R> {
    type Error = R::Error;

    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Txt, Self::Error>> + Send + '_ {
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
    ) -> Pin<Box<dyn Stream<Item = Result<Txt, OpaqueError>> + Send + '_>>;
}

impl<T: DnsTxtResolver> DynDnsTxtResolver for T {
    fn dyn_lookup_txt(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<Txt, OpaqueError>> + Send + '_>> {
        Box::pin(self.lookup_txt(domain).map_err(ErrorExt::into_opaque_error))
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
    ) -> impl Stream<Item = Result<Txt, Self::Error>> + Send + '_ {
        self.0.lookup_txt(domain).map_err(Into::into)
    }
}

impl std::fmt::Debug for BoxDnsTxtResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoxDnsTxtResolver").finish()
    }
}

impl DnsTxtResolver for BoxDnsTxtResolver {
    type Error = OpaqueError;

    #[inline]
    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Txt, Self::Error>> + Send + '_ {
        self.inner.dyn_lookup_txt(domain)
    }

    fn into_box_dns_txt_resolver(self) -> BoxDnsTxtResolver {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bytes_resolver_maps_to_one_string_without_splitting() {
        let value = Bytes::from(vec![b'x'; 255]);
        let mut stream = std::pin::pin!(value.lookup_txt(Domain::example()));
        let record = stream.next().await.expect("one item").expect("valid TXT");
        assert_eq!(record.len(), 1);
        assert_eq!(record.iter().next().expect("one string"), &[b'x'; 255]);
        assert!(stream.next().await.is_none());

        let oversized = Bytes::from(vec![0; 256]);
        let error = std::pin::pin!(oversized.lookup_txt(Domain::example()))
            .next()
            .await
            .expect("one item")
            .expect_err("Bytes convenience does not split long values");
        assert_eq!(
            error.to_string(),
            "TXT character-string length 256 exceeds 255 octets"
        );
    }

    #[tokio::test]
    async fn txt_resolver_preserves_a_complete_multi_string_record() {
        let value =
            Txt::try_from_strings([b"one".as_slice(), b"two".as_slice()]).expect("valid TXT");
        let record = std::pin::pin!(value.lookup_txt(Domain::example()))
            .next()
            .await
            .expect("one item")
            .expect("infallible");
        assert_eq!(
            record.iter().collect::<Vec<_>>(),
            [b"one".as_slice(), b"two".as_slice()]
        );
    }
}
