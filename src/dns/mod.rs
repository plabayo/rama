//! DNS module for Rama.

use crate::{
    net::address::Authority,
    service::{util::combinators::Either, Context},
};
use std::{iter::empty, net::SocketAddr, sync::Arc};

pub mod layer;

mod resolver;
#[doc(inline)]
pub use resolver::DnsResolver;

mod map;
#[doc(inline)]
pub use map::DnsMap;

mod svc_fn;
#[doc(inline)]
pub use svc_fn::{dns_service_fn, DnsServiceFn};

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
