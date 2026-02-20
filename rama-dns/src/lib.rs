//! DNS support for Rama.
//!
//! # Hickory Dns
//!
//! Hickory Dns is a Rust based DNS client, server, and resolver, built to be safe and secure from the ground up.
//! It is the default (and only) dns provider for Rama.
//!
//! By implementing the [`client::resolver::DnsResolver`] and optionally also
//! using [`client::try_init_global_dns_resolver`]
//! you can set however any kind of [`client::resolver::DnsResolver`] you wish.
//!
//! More info about hickory dns can be found at <https://github.com/hickory-dns/hickory-dns>.
//!
//! ## Global DNS resolver
//!
//! Rama uses by default a global and shared dns resolver.
//! The default one for this is the [`Default`] [`client::HickoryDnsResolver`] value,
//! which on unix and windows platforms is pulled from the system if possible,
//! and as a fallback or on all other platforms the default cloudflare config is used.
//!
//! Thank you cloudflare.
//!
//! Use [`client::try_init_global_dns_resolver`] or [`client::init_global_dns_resolver`] to
//! set the global [`client::resolver::DnsResolver`] as early as possible (e.g. at the top of your _main_ function).
//!
//! The global dns resolver can be lazily fetched by making use of [`client::GlobalDnsResolver`]
//! which allows you to create it _only_ when actually using it. Great in case
//! you need to have a [`client::resolver::DnsResolver`] value that you do not wish to do _any_ work for,
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
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]

pub mod client;
