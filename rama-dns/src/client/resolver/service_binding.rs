use std::{pin::Pin, sync::Arc};

use rama_core::{
    error::{BoxError, ErrorExt, extra::OpaqueError},
    futures::{Stream, StreamExt as _, TryStreamExt as _, stream},
};
use rama_net::address::{Domain, DomainTrie};

use crate::wire::ServiceBinding;

/// A resolver of domains into SVCB and HTTPS Service Binding records.
pub trait DnsServiceBindingResolver: Sized + Send + Sync + 'static {
    /// Error returned by this resolver.
    type Error: Into<BoxError> + Send + 'static;

    /// Resolve the complete SVCB RRset for the given domain.
    ///
    /// Implementations must validate the complete RRset before yielding any
    /// records. If one record is malformed, the stream must yield an error and
    /// no records from that RRset, as required by RFC 9460 section 2.2.
    fn lookup_svcb(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_;

    /// Resolve the complete HTTPS RRset for the given domain.
    ///
    /// Implementations must validate the complete RRset before yielding any
    /// records. If one record is malformed, the stream must yield an error and
    /// no records from that RRset, as required by RFC 9460 section 2.2.
    fn lookup_https(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_;

    /// Box this resolver to allow dynamic dispatch.
    fn into_box_dns_service_binding_resolver(self) -> BoxDnsServiceBindingResolver {
        BoxDnsServiceBindingResolver::new(self)
    }
}

impl<R: DnsServiceBindingResolver> DnsServiceBindingResolver for Arc<R> {
    type Error = R::Error;

    #[inline(always)]
    fn lookup_svcb(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
        self.as_ref().lookup_svcb(domain)
    }

    #[inline(always)]
    fn lookup_https(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
        self.as_ref().lookup_https(domain)
    }
}

impl<R: DnsServiceBindingResolver> DnsServiceBindingResolver for Option<R> {
    type Error = R::Error;

    #[inline(always)]
    fn lookup_svcb(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
        stream::iter(self.as_ref().map(|resolver| resolver.lookup_svcb(domain))).flatten()
    }

    #[inline(always)]
    fn lookup_https(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
        stream::iter(self.as_ref().map(|resolver| resolver.lookup_https(domain))).flatten()
    }
}

impl<R: DnsServiceBindingResolver> DnsServiceBindingResolver for DomainTrie<R> {
    type Error = R::Error;

    fn lookup_svcb(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
        stream::iter(self.match_exact(domain.clone()))
            .flat_map(move |resolver| resolver.lookup_svcb(domain.clone()))
    }

    fn lookup_https(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
        stream::iter(self.match_exact(domain.clone()))
            .flat_map(move |resolver| resolver.lookup_https(domain.clone()))
    }
}

trait DynDnsServiceBindingResolver {
    fn dyn_lookup_svcb(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<ServiceBinding, OpaqueError>> + Send + '_>>;

    fn dyn_lookup_https(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<ServiceBinding, OpaqueError>> + Send + '_>>;
}

impl<T: DnsServiceBindingResolver> DynDnsServiceBindingResolver for T {
    fn dyn_lookup_svcb(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<ServiceBinding, OpaqueError>> + Send + '_>> {
        Box::pin(
            self.lookup_svcb(domain)
                .map_err(ErrorExt::into_opaque_error),
        )
    }

    fn dyn_lookup_https(
        &self,
        domain: Domain,
    ) -> Pin<Box<dyn Stream<Item = Result<ServiceBinding, OpaqueError>> + Send + '_>> {
        Box::pin(
            self.lookup_https(domain)
                .map_err(ErrorExt::into_opaque_error),
        )
    }
}

/// A boxed [`DnsServiceBindingResolver`] mapping errors into [`OpaqueError`].
pub struct BoxDnsServiceBindingResolver {
    inner: Arc<dyn DynDnsServiceBindingResolver + Send + Sync + 'static>,
}

impl Clone for BoxDnsServiceBindingResolver {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl BoxDnsServiceBindingResolver {
    /// Create a boxed resolver.
    #[inline]
    pub fn new<T>(resolver: T) -> Self
    where
        T: DnsServiceBindingResolver,
    {
        Self {
            inner: Arc::new(resolver),
        }
    }
}

impl std::fmt::Debug for BoxDnsServiceBindingResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoxDnsServiceBindingResolver").finish()
    }
}

impl DnsServiceBindingResolver for BoxDnsServiceBindingResolver {
    type Error = OpaqueError;

    #[inline(always)]
    fn lookup_svcb(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
        self.inner.dyn_lookup_svcb(domain)
    }

    #[inline(always)]
    fn lookup_https(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
        self.inner.dyn_lookup_https(domain)
    }

    fn into_box_dns_service_binding_resolver(self) -> BoxDnsServiceBindingResolver {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use rama_core::{bytes::Bytes, futures::StreamExt as _};

    use super::*;

    #[derive(Clone)]
    struct StaticResolver {
        svcb: ServiceBinding,
        https: ServiceBinding,
    }

    impl StaticResolver {
        fn new() -> Self {
            Self {
                svcb: binding(8443),
                https: binding(443),
            }
        }
    }

    impl DnsServiceBindingResolver for StaticResolver {
        type Error = Infallible;

        fn lookup_svcb(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
            stream::once(std::future::ready(Ok(self.svcb.clone())))
        }

        fn lookup_https(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
            stream::once(std::future::ready(Ok(self.https.clone())))
        }
    }

    fn binding(port: u16) -> ServiceBinding {
        let mut rdata = vec![0, 1, 0, 0, 3, 0, 2];
        rdata.extend_from_slice(&port.to_be_bytes());
        ServiceBinding::parse_rdata_bytes(&Bytes::from(rdata)).expect("valid service binding")
    }

    async fn first_port<S, E>(stream: S) -> u16
    where
        S: Stream<Item = Result<ServiceBinding, E>>,
        E: std::fmt::Debug,
    {
        std::pin::pin!(stream)
            .next()
            .await
            .expect("one record")
            .expect("successful record")
            .port()
            .expect("port parameter")
    }

    #[tokio::test]
    async fn arc_option_and_box_preserve_both_record_families() {
        let resolver = Arc::new(StaticResolver::new());
        assert_eq!(
            first_port(resolver.lookup_svcb(Domain::example())).await,
            8443
        );
        assert_eq!(
            first_port(resolver.lookup_https(Domain::example())).await,
            443
        );

        let resolver = Some(resolver.as_ref().clone());
        assert_eq!(
            first_port(resolver.lookup_svcb(Domain::example())).await,
            8443
        );
        assert_eq!(
            first_port(resolver.lookup_https(Domain::example())).await,
            443
        );

        let resolver = resolver.into_box_dns_service_binding_resolver();
        assert_eq!(format!("{resolver:?}"), "BoxDnsServiceBindingResolver");
        assert_eq!(
            first_port(resolver.lookup_svcb(Domain::example())).await,
            8443
        );
        assert_eq!(
            first_port(resolver.lookup_https(Domain::example())).await,
            443
        );
        let same_resolver = resolver.clone().into_box_dns_service_binding_resolver();
        assert_eq!(
            first_port(same_resolver.lookup_https(Domain::example())).await,
            443
        );
    }

    #[tokio::test]
    async fn absent_optional_resolver_is_empty() {
        let resolver: Option<StaticResolver> = None;
        assert!(
            std::pin::pin!(resolver.lookup_svcb(Domain::example()))
                .next()
                .await
                .is_none()
        );
        assert!(
            std::pin::pin!(resolver.lookup_https(Domain::example()))
                .next()
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn domain_trie_resolves_only_exact_entries() {
        let resolver = DomainTrie::new().with_insert_domain("example.com", StaticResolver::new());
        assert_eq!(
            first_port(resolver.lookup_svcb(Domain::example())).await,
            8443
        );
        assert!(
            std::pin::pin!(resolver.lookup_https(Domain::from_static("www.example.com")))
                .next()
                .await
                .is_none()
        );
    }
}
