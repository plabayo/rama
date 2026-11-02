use super::DnsAddressResolver;
use rama_core::{
    error::BoxError,
    futures::{Stream, StreamExt as _},
};
use rama_net::address::Domain;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroUsize,
};

/// Bound raw answers from each address-family lookup, before deduplication.
///
/// This bounds polling work even if a resolver repeatedly yields one address.
/// An additional answer produces [`DnsAnswerLimitReached`] and ends the stream.
/// Pending lookups still require a caller-owned deadline. This adapter does not
/// perform DNS caching, deduplication or authorization.
#[derive(Debug, Clone)]
pub struct BoundedDnsAddressResolver<R> {
    inner: R,
    max_answers: NonZeroUsize,
}

impl<R> BoundedDnsAddressResolver<R> {
    /// Wrap a resolver with a positive per-family answer limit.
    pub const fn new(inner: R, max_answers: NonZeroUsize) -> Self {
        Self { inner, max_answers }
    }

    /// Access the wrapped resolver.
    pub fn inner(&self) -> &R {
        &self.inner
    }
}

/// A resolver produced more raw answers than the caller permits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsAnswerLimitReached;

impl std::fmt::Display for DnsAnswerLimitReached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DNS answer limit reached")
    }
}

impl std::error::Error for DnsAnswerLimitReached {}

impl<R: DnsAddressResolver> DnsAddressResolver for BoundedDnsAddressResolver<R> {
    type Error = BoxError;

    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        bounded(self.inner.lookup_ipv4(domain), self.max_answers.get())
    }

    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        bounded(self.inner.lookup_ipv6(domain), self.max_answers.get())
    }
}

fn bounded<T, E: Into<BoxError>>(
    stream: impl Stream<Item = Result<T, E>>,
    max: usize,
) -> impl Stream<Item = Result<T, BoxError>> {
    stream
        .take(max.saturating_add(1))
        .enumerate()
        .map(move |(index, item)| {
            if index == max {
                Err(DnsAnswerLimitReached.into())
            } else {
                item.map_err(Into::into)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::futures::stream;
    use std::convert::Infallible;

    #[tokio::test]
    async fn duplicate_answers_are_counted_and_overflow_ends_the_stream() {
        let answers = stream::repeat(Ok::<_, Infallible>(Ipv4Addr::LOCALHOST));
        let mut answers = std::pin::pin!(bounded(answers, 2));
        assert_eq!(answers.next().await.unwrap().unwrap(), Ipv4Addr::LOCALHOST);
        assert_eq!(answers.next().await.unwrap().unwrap(), Ipv4Addr::LOCALHOST);
        assert!(
            answers
                .next()
                .await
                .unwrap()
                .unwrap_err()
                .is::<DnsAnswerLimitReached>()
        );
        assert!(answers.next().await.is_none());
    }

    #[tokio::test]
    async fn exactly_the_limit_and_empty_answers_end_cleanly() {
        for count in [0, 2] {
            let source = stream::iter((0..count).map(|_| Ok::<_, Infallible>(Ipv4Addr::LOCALHOST)));
            let results = bounded(source, 2).collect::<Vec<_>>().await;
            assert_eq!(results.len(), count);
            assert!(results.iter().all(Result::is_ok));
        }
    }
}
