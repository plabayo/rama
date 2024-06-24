use super::{DnsResolver, DnsService};
use crate::net::address::Authority;
use std::future::Future;
use std::pin::Pin;
use std::{fmt, net::SocketAddr};

/// A service that is driven by a function.
pub struct DnsServiceFn<F>(F);

/// Create a new [`DnsServiceFn`] from the given function.
pub fn dns_service_fn<F>(f: F) -> DnsServiceFn<F> {
    DnsServiceFn::new(f)
}

impl<F> DnsServiceFn<F> {
    pub(crate) fn new(f: F) -> Self {
        Self(f)
    }
}

impl<F: fmt::Debug> fmt::Debug for DnsServiceFn<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsServiceFn")
            .field("function", &format_args!("{}", std::any::type_name::<F>()))
            .finish()
    }
}

impl<F: Clone> Clone for DnsServiceFn<F> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<F, Fut, R> DnsService for DnsServiceFn<F>
where
    F: Fn(Authority) -> Fut,
    Fut: Future<Output = R> + Send + 'static,
    R: DnsResolver,
{
    type Resolver = DnsServiceFnResolver<Fut, R>;
    fn lookup(&self, authority: Authority) -> Self::Resolver {
        let fut = self.0(authority);
        DnsServiceFnResolver {
            state: DnsServiceFnResolverState::Init(Box::pin(fut)),
        }
    }
}

struct DnsServiceFnResolver<Fut, R> {
    state: DnsServiceFnResolverState<Fut, R>,
}

enum DnsServiceFnResolverState<Fut, R> {
    Init(Pin<Box<Fut>>),
    Resolve(R),
}

impl<Fut, R> DnsResolver for DnsServiceFnResolver<Fut, R>
where
    Fut: Future<Output = R> + Send + 'static,
    R: DnsResolver,
{
    async fn next_addr(&mut self) -> Option<SocketAddr> {
        match &mut self.state {
            DnsServiceFnResolverState::Init(fut) => {
                let mut iter = fut.await;
                let next = iter.next_addr().await;
                self.state = DnsServiceFnResolverState::Resolve(iter);
                next
            }
            DnsServiceFnResolverState::Resolve(iter) => iter.next_addr().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::service::util::combinators::Either;

    use super::*;

    #[tokio::test]
    async fn test_dns_service_fn() {
        let service = dns_service_fn(|_| async move {
            vec![SocketAddr::from(([127, 0, 0, 1], 8080))].into_iter()
        });
        let mut resolver = service.lookup("localhost:8080".parse().unwrap());
        assert_eq!(
            resolver.next_addr().await,
            Some(SocketAddr::from(([127, 0, 0, 1], 8080)))
        );
        assert_eq!(resolver.next_addr().await, None);
    }

    #[test]
    fn test_tokio_net_lookup() {
        fn assert_dns_service<T: DnsService>(_: T) {}
        assert_dns_service(dns_service_fn(|authority: Authority| async move {
            match tokio::net::lookup_host(authority.to_string()).await {
                Ok(iter) => Either::A(iter),
                Err(err) => {
                    tracing::trace!("tokio::net::lookup_host error: {:?}", err);
                    Either::B(std::iter::empty())
                }
            }
        }));
    }
}
