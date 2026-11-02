use super::{
    DnsAddressResolver, DnsCnameResolver, DnsResolver, DnsServiceBindingResolver, DnsTxtResolver,
};
use crate::wire::{Name, ServiceBinding, Txt};
use rama_core::{error::BoxError, futures::Stream};
use rama_net::address::Domain;
use rama_utils::macros::generate_set_and_with;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll, ready},
};

/// Bound raw results from each DNS lookup, before deduplication.
///
/// Implements each resolver trait supported by the wrapped resolver. Each lookup
/// has its own allowance; duplicates and errors both count as raw results.
/// An additional result produces [`DnsAnswerLimitReached`] and ends that stream.
/// Limits do not aggregate across lookups, types, clones or callers.
///
/// Pending lookups still require a caller-owned deadline. This adapter bounds
/// stream consumption, not the wrapped resolver's internal allocation or work.
/// It does not cache, deduplicate, authorize, or validate records. In particular,
/// service-binding RRset validation remains the inner resolver's responsibility;
/// a consumer requiring a complete RRset must reject it on a limit error.
#[derive(Debug, Clone)]
pub struct BoundedDnsResolver<R> {
    inner: R,
    ipv4_limit: NonZeroUsize,
    ipv6_limit: NonZeroUsize,
    cname_limit: NonZeroUsize,
    txt_limit: NonZeroUsize,
    svcb_limit: NonZeroUsize,
    https_limit: NonZeroUsize,
}

impl<R> BoundedDnsResolver<R> {
    /// Wrap a resolver with the same positive raw-result limit for every type.
    /// Override individual types or categories with the builder methods.
    pub const fn new(inner: R, max_answers: NonZeroUsize) -> Self {
        Self {
            inner,
            ipv4_limit: max_answers,
            ipv6_limit: max_answers,
            cname_limit: max_answers,
            txt_limit: max_answers,
            svcb_limit: max_answers,
            https_limit: max_answers,
        }
    }

    /// Access the wrapped resolver.
    pub fn inner(&self) -> &R {
        &self.inner
    }

    generate_set_and_with! {
        /// Maximum raw results from each A lookup.
        pub fn ipv4_limit(mut self, limit: NonZeroUsize) -> Self {
            self.ipv4_limit = limit;
            self
        }
    }

    generate_set_and_with! {
        /// Maximum raw results from each AAAA lookup.
        pub fn ipv6_limit(mut self, limit: NonZeroUsize) -> Self {
            self.ipv6_limit = limit;
            self
        }
    }

    generate_set_and_with! {
        /// Maximum raw results from each CNAME lookup.
        pub fn cname_limit(mut self, limit: NonZeroUsize) -> Self {
            self.cname_limit = limit;
            self
        }
    }

    generate_set_and_with! {
        /// Maximum raw results from each TXT lookup.
        pub fn txt_limit(mut self, limit: NonZeroUsize) -> Self {
            self.txt_limit = limit;
            self
        }
    }

    generate_set_and_with! {
        /// Maximum raw results from each SVCB lookup.
        pub fn svcb_limit(mut self, limit: NonZeroUsize) -> Self {
            self.svcb_limit = limit;
            self
        }
    }

    generate_set_and_with! {
        /// Maximum raw results from each HTTPS lookup.
        pub fn https_limit(mut self, limit: NonZeroUsize) -> Self {
            self.https_limit = limit;
            self
        }
    }

    generate_set_and_with! {
        /// Set the A and AAAA limits together; each lookup retains its own allowance.
        /// Later individual or category settings replace the affected limits.
        pub fn address_limit(mut self, limit: NonZeroUsize) -> Self {
            self.ipv4_limit = limit;
            self.ipv6_limit = limit;
            self
        }
    }

    generate_set_and_with! {
        /// Set the SVCB and HTTPS limits together; each lookup retains its own allowance.
        /// Later individual or category settings replace the affected limits.
        pub fn service_binding_limit(mut self, limit: NonZeroUsize) -> Self {
            self.svcb_limit = limit;
            self.https_limit = limit;
            self
        }
    }
}

/// A resolver produced more raw results than the caller permits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsAnswerLimitReached;

impl std::fmt::Display for DnsAnswerLimitReached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DNS answer limit reached")
    }
}

impl std::error::Error for DnsAnswerLimitReached {}

impl<R: DnsAddressResolver> DnsAddressResolver for BoundedDnsResolver<R> {
    type Error = BoxError;

    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        bounded(self.inner.lookup_ipv4(domain), self.ipv4_limit.get())
    }

    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        bounded(self.inner.lookup_ipv6(domain), self.ipv6_limit.get())
    }
}

impl<R: DnsCnameResolver> DnsCnameResolver for BoundedDnsResolver<R> {
    type Error = BoxError;

    fn lookup_cname(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Name, Self::Error>> + Send + '_ {
        bounded(self.inner.lookup_cname(domain), self.cname_limit.get())
    }
}

impl<R: DnsTxtResolver> DnsTxtResolver for BoundedDnsResolver<R> {
    type Error = BoxError;

    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Txt, Self::Error>> + Send + '_ {
        bounded(self.inner.lookup_txt(domain), self.txt_limit.get())
    }
}

impl<R: DnsServiceBindingResolver> DnsServiceBindingResolver for BoundedDnsResolver<R> {
    type Error = BoxError;

    fn lookup_svcb(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
        bounded(self.inner.lookup_svcb(domain), self.svcb_limit.get())
    }

    fn lookup_https(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
        bounded(self.inner.lookup_https(domain), self.https_limit.get())
    }
}

impl<R: DnsResolver> DnsResolver for BoundedDnsResolver<R> {}

fn bounded<S>(stream: S, max: usize) -> BoundedAnswers<S> {
    BoundedAnswers {
        stream,
        remaining: max,
        done: false,
    }
}

pin_project_lite::pin_project! {
    struct BoundedAnswers<S> {
        #[pin]
        stream: S,
        remaining: usize,
        done: bool,
    }
}

impl<S, T, E> Stream for BoundedAnswers<S>
where
    S: Stream<Item = Result<T, E>>,
    E: Into<BoxError>,
{
    type Item = Result<T, BoxError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        if *this.done {
            return Poll::Ready(None);
        }
        let Some(item) = ready!(this.stream.poll_next(cx)) else {
            *this.done = true;
            return Poll::Ready(None);
        };
        if *this.remaining == 0 {
            *this.done = true;
            Poll::Ready(Some(Err(DnsAnswerLimitReached.into())))
        } else {
            *this.remaining -= 1;
            Poll::Ready(Some(item.map_err(Into::into)))
        }
    }
}

#[cfg(test)]
mod tests;
