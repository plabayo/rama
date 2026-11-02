use super::{
    DnsAddressResolver, DnsCnameResolver, DnsResolver, DnsServiceBindingResolver, DnsTxtResolver,
};
use crate::wire::{Name, ServiceBinding, Txt};
use rama_core::{error::BoxError, futures::Stream};
use rama_net::address::Domain;
use rama_utils::macros::{error::static_str_error, generate_set_and_with};
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
/// For a bounded type, an additional result produces [`DnsAnswerLimitReached`]
/// and ends that stream. Unbounded types impose no result-count limit.
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
    ipv4_limit: Option<NonZeroUsize>,
    ipv6_limit: Option<NonZeroUsize>,
    cname_limit: Option<NonZeroUsize>,
    txt_limit: Option<NonZeroUsize>,
    svcb_limit: Option<NonZeroUsize>,
    https_limit: Option<NonZeroUsize>,
}

impl<R> BoundedDnsResolver<R> {
    /// Start without result-count limits. Bound selected types or categories
    /// with the builder methods.
    pub const fn unbounded(inner: R) -> Self {
        Self {
            inner,
            ipv4_limit: None,
            ipv6_limit: None,
            cname_limit: None,
            txt_limit: None,
            svcb_limit: None,
            https_limit: None,
        }
    }

    /// Start with the same positive raw-result limit for every type.
    /// Override or remove individual/category limits with the builder methods.
    pub const fn bounded(inner: R, max_answers: NonZeroUsize) -> Self {
        Self {
            inner,
            ipv4_limit: Some(max_answers),
            ipv6_limit: Some(max_answers),
            cname_limit: Some(max_answers),
            txt_limit: Some(max_answers),
            svcb_limit: Some(max_answers),
            https_limit: Some(max_answers),
        }
    }

    /// Access the wrapped resolver.
    pub fn inner(&self) -> &R {
        &self.inner
    }

    generate_set_and_with! {
        /// Set all per-type limits together. `None` makes every type unbounded.
        /// Later individual or category settings replace the affected limits.
        pub fn limit(mut self, limit: Option<NonZeroUsize>) -> Self {
            self.ipv4_limit = limit;
            self.ipv6_limit = limit;
            self.cname_limit = limit;
            self.txt_limit = limit;
            self.svcb_limit = limit;
            self.https_limit = limit;
            self
        }
    }

    generate_set_and_with! {
        /// Maximum raw results from each A lookup; `None` leaves it unbounded.
        pub fn ipv4_limit(mut self, limit: Option<NonZeroUsize>) -> Self {
            self.ipv4_limit = limit;
            self
        }
    }

    generate_set_and_with! {
        /// Maximum raw results from each AAAA lookup; `None` leaves it unbounded.
        pub fn ipv6_limit(mut self, limit: Option<NonZeroUsize>) -> Self {
            self.ipv6_limit = limit;
            self
        }
    }

    generate_set_and_with! {
        /// Maximum raw results from each CNAME lookup; `None` leaves it unbounded.
        pub fn cname_limit(mut self, limit: Option<NonZeroUsize>) -> Self {
            self.cname_limit = limit;
            self
        }
    }

    generate_set_and_with! {
        /// Maximum raw results from each TXT lookup; `None` leaves it unbounded.
        pub fn txt_limit(mut self, limit: Option<NonZeroUsize>) -> Self {
            self.txt_limit = limit;
            self
        }
    }

    generate_set_and_with! {
        /// Maximum raw results from each SVCB lookup; `None` leaves it unbounded.
        pub fn svcb_limit(mut self, limit: Option<NonZeroUsize>) -> Self {
            self.svcb_limit = limit;
            self
        }
    }

    generate_set_and_with! {
        /// Maximum raw results from each HTTPS lookup; `None` leaves it unbounded.
        pub fn https_limit(mut self, limit: Option<NonZeroUsize>) -> Self {
            self.https_limit = limit;
            self
        }
    }

    generate_set_and_with! {
        /// Set the A and AAAA limits together; each lookup retains its own allowance.
        /// `None` removes both limits; later settings replace the affected limits.
        pub fn ip_limit(mut self, limit: Option<NonZeroUsize>) -> Self {
            self.ipv4_limit = limit;
            self.ipv6_limit = limit;
            self
        }
    }

    generate_set_and_with! {
        /// Set the SVCB and HTTPS limits together; each lookup retains its own allowance.
        /// `None` removes both limits; later settings replace the affected limits.
        pub fn service_binding_limit(mut self, limit: Option<NonZeroUsize>) -> Self {
            self.svcb_limit = limit;
            self.https_limit = limit;
            self
        }
    }
}

static_str_error! {
    #[doc = "DNS answer limit reached"]
    #[derive(Copy)]
    pub struct DnsAnswerLimitReached;
}

impl<R: DnsAddressResolver> DnsAddressResolver for BoundedDnsResolver<R> {
    type Error = BoxError;

    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        bounded(self.inner.lookup_ipv4(domain), self.ipv4_limit)
    }

    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        bounded(self.inner.lookup_ipv6(domain), self.ipv6_limit)
    }
}

impl<R: DnsCnameResolver> DnsCnameResolver for BoundedDnsResolver<R> {
    type Error = BoxError;

    fn lookup_cname(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Name, Self::Error>> + Send + '_ {
        bounded(self.inner.lookup_cname(domain), self.cname_limit)
    }
}

impl<R: DnsTxtResolver> DnsTxtResolver for BoundedDnsResolver<R> {
    type Error = BoxError;

    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Txt, Self::Error>> + Send + '_ {
        bounded(self.inner.lookup_txt(domain), self.txt_limit)
    }
}

impl<R: DnsServiceBindingResolver> DnsServiceBindingResolver for BoundedDnsResolver<R> {
    type Error = BoxError;

    fn lookup_svcb(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
        bounded(self.inner.lookup_svcb(domain), self.svcb_limit)
    }

    fn lookup_https(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
        bounded(self.inner.lookup_https(domain), self.https_limit)
    }
}

impl<R: DnsResolver> DnsResolver for BoundedDnsResolver<R> {}

fn bounded<S>(stream: S, max: Option<NonZeroUsize>) -> BoundedAnswers<S> {
    BoundedAnswers {
        stream,
        remaining: max.map(NonZeroUsize::get),
        done: false,
    }
}

pin_project_lite::pin_project! {
    struct BoundedAnswers<S> {
        #[pin]
        stream: S,
        remaining: Option<usize>,
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
        if let Some(remaining) = this.remaining {
            if *remaining == 0 {
                *this.done = true;
                return Poll::Ready(Some(Err(DnsAnswerLimitReached.into())));
            }
            *remaining -= 1;
        }
        Poll::Ready(Some(item.map_err(Into::into)))
    }
}

#[cfg(test)]
mod tests;
