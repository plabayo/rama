//! DNS support for Rama.
//!
//! # Rama
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

use rama_core::error::BoxError;
use rama_net::address::Domain;
use std::{
    future::Future,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

/// A resolver of domains into IP addresses.
pub trait DnsResolver: Send + Sync + 'static {
    /// Error returned by the [`DnsResolver`]
    type Error;

    /// Resolve the 'A' records accessible by this resolver for the given [`Domain`] into [`Ipv4Addr`]esses.
    fn ipv4_lookup(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Result<Vec<Ipv4Addr>, Self::Error>> + Send + '_;

    /// Resolve the 'AAAA' records accessible by this resolver for the given [`Domain`] into [`Ipv6Addr`]esses.
    fn ipv6_lookup(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Result<Vec<Ipv6Addr>, Self::Error>> + Send + '_;
}

impl<R: DnsResolver> DnsResolver for Arc<R> {
    type Error = R::Error;

    fn ipv4_lookup(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Result<Vec<Ipv4Addr>, Self::Error>> + Send + '_ {
        (**self).ipv4_lookup(domain)
    }

    fn ipv6_lookup(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Result<Vec<Ipv6Addr>, Self::Error>> + Send + '_ {
        (**self).ipv6_lookup(domain)
    }
}

impl<R: DnsResolver<Error: Into<BoxError>>> DnsResolver for Option<R> {
    type Error = BoxError;

    async fn ipv4_lookup(&self, domain: Domain) -> Result<Vec<Ipv4Addr>, Self::Error> {
        match self {
            Some(d) => d.ipv4_lookup(domain).await.map_err(Into::into),
            None => Err(DomainNotMappedErr.into()),
        }
    }

    async fn ipv6_lookup(&self, domain: Domain) -> Result<Vec<Ipv6Addr>, Self::Error> {
        match self {
            Some(d) => d.ipv6_lookup(domain).await.map_err(Into::into),
            None => Err(DomainNotMappedErr.into()),
        }
    }
}

#[derive(Debug)]
pub struct DnsChainDomainResolveErr<E: 'static> {
    errors: Vec<E>,
}

impl<E: std::fmt::Debug> std::fmt::Display for DnsChainDomainResolveErr<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "domain resolver chain resulted in errors: {:?}",
            self.errors
        )
    }
}

impl<E: std::fmt::Debug + Send + std::error::Error> std::error::Error
    for DnsChainDomainResolveErr<E>
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.errors.last().map(|e| e as &dyn std::error::Error)
    }
}

impl<R, E> DnsResolver for Vec<R>
where
    R: DnsResolver<Error = E> + Send,
    E: Send + 'static,
{
    type Error = DnsChainDomainResolveErr<E>;

    async fn ipv4_lookup(&self, domain: Domain) -> Result<Vec<Ipv4Addr>, Self::Error> {
        let mut errors = Vec::new();
        for resolver in self {
            match resolver.ipv4_lookup(domain.clone()).await {
                Ok(ipv4s) => return Ok(ipv4s),
                Err(err) => errors.push(err),
            }
        }
        Err(DnsChainDomainResolveErr { errors })
    }

    async fn ipv6_lookup(&self, domain: Domain) -> Result<Vec<Ipv6Addr>, Self::Error> {
        let mut errors = Vec::new();
        for resolver in self {
            match resolver.ipv6_lookup(domain.clone()).await {
                Ok(ipv6s) => return Ok(ipv6s),
                Err(err) => errors.push(err),
            }
        }
        Err(DnsChainDomainResolveErr { errors })
    }
}

impl<R, E, const N: usize> DnsResolver for [R; N]
where
    R: DnsResolver<Error = E> + Send,
    E: Send + 'static,
{
    type Error = DnsChainDomainResolveErr<E>;

    async fn ipv4_lookup(&self, domain: Domain) -> Result<Vec<Ipv4Addr>, Self::Error> {
        let mut errors = Vec::new();
        for resolver in self {
            match resolver.ipv4_lookup(domain.clone()).await {
                Ok(ipv4s) => return Ok(ipv4s),
                Err(err) => errors.push(err),
            }
        }
        Err(DnsChainDomainResolveErr { errors })
    }

    async fn ipv6_lookup(&self, domain: Domain) -> Result<Vec<Ipv6Addr>, Self::Error> {
        let mut errors = Vec::new();
        for resolver in self {
            match resolver.ipv6_lookup(domain.clone()).await {
                Ok(ipv6s) => return Ok(ipv6s),
                Err(err) => errors.push(err),
            }
        }
        Err(DnsChainDomainResolveErr { errors })
    }
}

macro_rules! impl_dns_resolver_either_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+> DnsResolver for ::rama_core::combinators::$id<$($param),+>
        where
            $($param: DnsResolver<Error: Into<::rama_core::error::BoxError>>),+,
        {
            type Error = ::rama_core::error::BoxError;

            async fn ipv4_lookup(
                &self,
                domain: Domain,
            ) -> Result<Vec<Ipv4Addr>, Self::Error>{
                match self {
                    $(
                        ::rama_core::combinators::$id::$param(d) => d.ipv4_lookup(domain)
                            .await
                            .map_err(Into::into),
                    )+
                }
            }

            async fn ipv6_lookup(
                &self,
                domain: Domain,
            ) -> Result<Vec<Ipv6Addr>, Self::Error> {
                match self {
                    $(
                        ::rama_core::combinators::$id::$param(d) => d.ipv6_lookup(domain)
                            .await
                            .map_err(Into::into),
                    )+
                }
            }
        }
    };
}

rama_core::combinators::impl_either!(impl_dns_resolver_either_either);

pub mod hickory;
#[doc(inline)]
pub use hickory::HickoryDns;

mod in_memory;
#[doc(inline)]
pub use in_memory::{DnsOverwrite, DomainNotMappedErr, InMemoryDns};

mod deny_all;
#[doc(inline)]
pub use deny_all::{DenyAllDns, DnsDeniedError};
