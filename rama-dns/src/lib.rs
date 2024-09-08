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
#![warn(
    clippy::all,
    clippy::todo,
    clippy::empty_enum,
    clippy::enum_glob_use,
    clippy::mem_forget,
    clippy::unused_self,
    clippy::filter_map_next,
    clippy::needless_continue,
    clippy::needless_borrow,
    clippy::match_wildcard_for_single_variants,
    clippy::if_let_mutex,
    clippy::await_holding_lock,
    clippy::match_on_vec_items,
    clippy::imprecise_flops,
    clippy::suboptimal_flops,
    clippy::lossy_float_literal,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::fn_params_excessive_bools,
    clippy::exit,
    clippy::inefficient_to_string,
    clippy::linkedlist,
    clippy::macro_use_imports,
    clippy::option_option,
    clippy::verbose_file_reads,
    clippy::unnested_or_patterns,
    clippy::str_to_string,
    rust_2018_idioms,
    future_incompatible,
    nonstandard_style,
    missing_debug_implementations,
    missing_docs
)]
#![deny(unreachable_pub)]
#![allow(elided_lifetimes_in_paths, clippy::type_complexity)]
#![forbid(unsafe_code)]
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
    ) -> impl Future<Output = Result<impl Iterator<Item = Ipv4Addr>, Self::Error>> + Send + '_;

    /// Resolve the 'AAAA' records accessible by this resolver for the given [`Domain`] into [`Ipv6Addr`]esses.
    fn ipv6_lookup(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Result<impl Iterator<Item = Ipv6Addr>, Self::Error>> + Send + '_;
}

impl<R: DnsResolver> DnsResolver for Arc<R> {
    type Error = R::Error;

    fn ipv4_lookup(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Result<impl Iterator<Item = Ipv4Addr>, Self::Error>> + Send + '_ {
        (**self).ipv4_lookup(domain)
    }

    fn ipv6_lookup(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Result<impl Iterator<Item = Ipv6Addr>, Self::Error>> + Send + '_ {
        (**self).ipv6_lookup(domain)
    }
}

impl<R: DnsResolver<Error: Into<BoxError>>> DnsResolver for Option<R> {
    type Error = BoxError;

    async fn ipv4_lookup(
        &self,
        domain: Domain,
    ) -> Result<impl Iterator<Item = Ipv4Addr>, Self::Error> {
        match self {
            Some(d) => d.ipv4_lookup(domain).await.map_err(Into::into),
            None => Err(DomainNotMappedErr.into()),
        }
    }

    async fn ipv6_lookup(
        &self,
        domain: Domain,
    ) -> Result<impl Iterator<Item = Ipv6Addr>, Self::Error> {
        match self {
            Some(d) => d.ipv6_lookup(domain).await.map_err(Into::into),
            None => Err(DomainNotMappedErr.into()),
        }
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
            ) -> Result<impl Iterator<Item = Ipv4Addr>, Self::Error>{
                match self {
                    $(
                        ::rama_core::combinators::$id::$param(d) => d.ipv4_lookup(domain)
                            .await
                            .map_err(Into::into)
                            .map(::rama_core::combinators::$id::$param),
                    )+
                }
            }

            async fn ipv6_lookup(
                &self,
                domain: Domain,
            ) -> Result<impl Iterator<Item = Ipv6Addr>, Self::Error> {
                match self {
                    $(
                        ::rama_core::combinators::$id::$param(d) => d.ipv6_lookup(domain)
                            .await
                            .map_err(Into::into)
                            .map(::rama_core::combinators::$id::$param),
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
