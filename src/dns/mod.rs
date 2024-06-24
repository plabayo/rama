//! DNS module for Rama.

use crate::{
    net::address::Authority,
    service::{util::combinators::Either, Context},
};
use std::{future::Future, iter::empty, net::SocketAddr, sync::Arc};

pub mod layer;

mod map;
#[doc(inline)]
pub use map::DnsMap;

/// Generator-like trait that resolves a [`Authority`] to a list of [`SocketAddr`]esses.
pub trait DnsResolver: Send + 'static {
    /// Returns the next [`SocketAddr`] in the list of resolved addresses.
    ///
    /// If there are no more addresses to resolve, it should return `None`.
    ///
    /// Errors should be handled by the resolver itself, and not propagated to the caller.
    /// The result of an error should be the same as if no more addresses were found.
    fn next_addr(&mut self) -> impl Future<Output = Option<SocketAddr>> + Send + '_;
}

impl<I> DnsResolver for I
where
    I: Iterator<Item = SocketAddr> + Send + 'static,
{
    async fn next_addr(&mut self) -> Option<SocketAddr> {
        self.next()
    }
}

/// A DNS service that resolves an [`Authority`] to a list of [`SocketAddr`]esses.
pub trait DnsService<State>: Send + Sync + 'static {
    /// Returns a [`DnsResolver`] used to resolve the given [`Authority`] to a list of [`SocketAddr`]esses.
    ///
    /// Errors should be handled by the service itself, and not propagated to the caller.
    /// It is expected that the output is the same for the scenarios where no addresses are found.
    fn lookup(&self, ctx: &Context<State>, authority: Authority) -> impl DnsResolver;
}

impl<S> DnsService<S> for ()
where
    S: Send + Sync + 'static,
{
    fn lookup(&self, _ctx: &Context<S>, _authority: Authority) -> impl DnsResolver {
        empty()
    }
}

impl<S> DnsService<S> for SocketAddr {
    fn lookup(&self, _ctx: &Context<S>, _authority: Authority) -> impl DnsResolver {
        std::iter::once(*self)
    }
}

impl<S, Service> DnsService<S> for Option<Service>
where
    S: Send + Sync + 'static,
    Service: DnsService<S>,
{
    fn lookup(&self, ctx: &Context<S>, authority: Authority) -> impl DnsResolver {
        match self {
            Some(service) => Either::A(service.lookup(ctx, authority)),
            None => Either::B(empty()),
        }
    }
}

impl<S, Service> DnsService<S> for Arc<Service>
where
    S: Send + Sync + 'static,
    Service: DnsService<S>,
{
    fn lookup(&self, ctx: &Context<S>, authority: Authority) -> impl DnsResolver {
        self.as_ref().lookup(ctx, authority)
    }
}

impl<S, Service> DnsService<S> for Box<Service>
where
    S: Send + Sync + 'static,
    Service: DnsService<S>,
{
    fn lookup(&self, ctx: &Context<S>, authority: Authority) -> impl DnsResolver {
        self.as_ref().lookup(ctx, authority)
    }
}

// TODO:
// - Add DnsServiceFn (to allow usage of functions)
// - Add DnsServiceStack (to allow stacking of services)
//     ==> internally it will use a vec of <Box<dyn DnsService>>, and will fallback to tokio::net::lookup_host (rama edition)
//     ==> Has default implementation of just empty vec :)
// - Add Tests...
// - Add Documentation...
// - Use the new code everywhere, instead of the dns::layer (which can be removed)
