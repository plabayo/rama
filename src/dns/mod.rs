//! DNS module for Rama.

use crate::{net::address::Authority, service::util::combinators::Either};
use std::{
    iter::{empty, Empty, Once},
    net::SocketAddr,
    sync::Arc,
};

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

mod stack;
#[doc(inline)]
pub use stack::Dns;

/// A DNS service that resolves an [`Authority`] to a list of [`SocketAddr`]esses.
pub trait DnsService {
    type Resolver: DnsResolver;

    /// Returns a [`DnsResolver`] used to resolve the given [`Authority`] to a list of [`SocketAddr`]esses.
    ///
    /// Errors should be handled by the service itself, and not propagated to the caller.
    /// It is expected that the output is the same for the scenarios where no addresses are found.
    fn lookup(&self, authority: Authority) -> Self::Resolver;
}

impl DnsService for () {
    type Resolver = Empty<SocketAddr>;

    fn lookup(&self, _authority: Authority) -> Self::Resolver {
        empty()
    }
}

impl DnsService for SocketAddr {
    type Resolver = Once<SocketAddr>;

    fn lookup(&self, _authority: Authority) -> Self::Resolver {
        std::iter::once(*self)
    }
}

impl<Service> DnsService for Option<Service>
where
    Service: DnsService,
{
    type Resolver = Either<Service::Resolver, Empty<SocketAddr>>;

    fn lookup(&self, authority: Authority) -> Self::Resolver {
        match self {
            Some(service) => Either::A(service.lookup(authority)),
            None => Either::B(empty()),
        }
    }
}

impl<Service> DnsService for Arc<Service>
where
    Service: DnsService,
{
    type Resolver = Service::Resolver;

    fn lookup(&self, authority: Authority) -> Self::Resolver {
        self.as_ref().lookup(authority)
    }
}

impl<Service> DnsService for Box<Service>
where
    Service: DnsService,
{
    type Resolver = Service::Resolver;

    fn lookup(&self, authority: Authority) -> Self::Resolver {
        self.as_ref().lookup(authority)
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
