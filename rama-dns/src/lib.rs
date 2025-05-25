//! DNS support for Rama.
//!
//! # Hickory Dns
//!
//! Hickory Dns is a Rust based DNS client, server, and resolver, built to be safe and secure from the ground up.
//! It is the default (and only) dns provider for Rama.
//!
//! By implementing the [`DnsResolver`] and optionally also using [`try_init_global_dns_resolver`]
//! you can set however any kind of [`DnsResolver`] you wish.
//!
//! More info about hickory dns can be found at <https://github.com/hickory-dns/hickory-dns>.
//!
//! ## Global DNS resolver
//!
//! Rama uses by default a global and shared dns resolver.
//! The default one for this is the [`Default`] [`HickoryDns`] value,
//! which on unix and windows platforms is pulled from the system if possible,
//! and as a fallback or on all other platforms the default cloudflare config is used.
//!
//! Thank you cloudflare.
//!
//! Use [`try_init_global_dns_resolver`] or [`init_global_dns_resolver`] to
//! set the global [`DnsResolver`] as early as possible (e.g. at the top of your _main_ function).
//!
//! Use [`global_dns_resolver`] should you have a need for this global [`DnsResolver`] yourself.
//!
//! The global dns resolver can be lazily fetched by making use of [`GlobalDnsResolver`]
//! which allows you to create it _only_ when actually using it. Great in case
//! you need to have a [`DnsResolver`] value that you do not wish to do _any_ work for,
//! until you "really" need it.
//!
//! ## Rama
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
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

/// A resolver of domains into IP addresses.
pub trait DnsResolver: Sized + Send + Sync + 'static {
    /// Error returned by the [`DnsResolver`]
    type Error: Into<BoxError> + Send + 'static;

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

    /// Box this resolver to allow for dynamic dispatch.
    fn boxed(self) -> BoxDnsResolver {
        BoxDnsResolver::new(self)
    }
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

impl<R: DnsResolver> DnsResolver for Option<R> {
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

mod global;
#[doc(inline)]
pub use global::{
    GlobalDnsResolver, global_dns_resolver, init_global_dns_resolver, try_init_global_dns_resolver,
};

pub mod hickory;
#[doc(inline)]
pub use hickory::HickoryDns;

mod in_memory;
#[doc(inline)]
pub use in_memory::{DnsOverwrite, DomainNotMappedErr, InMemoryDns};

mod deny_all;
#[doc(inline)]
pub use deny_all::{DenyAllDns, DnsDeniedError};

pub mod chain;

mod variant;

mod boxed;
#[doc(inline)]
pub use boxed::BoxDnsResolver;
