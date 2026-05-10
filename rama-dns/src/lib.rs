//! DNS support for Rama.
//!
//! # Resolvers
//!
//! Rama ships with several [`client::resolver::DnsResolver`] implementations.
//! The most commonly used ones are re-exported from [`client`]:
//!
//! - [`client::NativeDnsResolver`] — alias for the platform-native resolver:
//!   `AppleDnsResolver` on Apple platforms, `WindowsDnsResolver` on
//!   Windows, `LinuxDnsResolver` on Linux, and [`client::TokioDnsResolver`]
//!   (host-backed via tokio) elsewhere. Each is exposed under
//!   [`client`] when the corresponding target is active.
//! - [`client::TokioDnsResolver`] — host-backed resolver that uses the
//!   blocking system getaddrinfo via tokio's threadpool.
//! - `client::HickoryDnsResolver` — pure-Rust resolver from the
//!   Hickory DNS project (<https://github.com/hickory-dns/hickory-dns>);
//!   gated behind the `hickory` feature.
//! - [`client::DenyAllDnsResolver`] — fails every lookup with
//!   [`client::DnsDeniedError`]; useful when DNS must be disabled.
//! - [`client::EmptyDnsResolver`] — returns no addresses for every lookup.
//!
//! Implement [`client::resolver::DnsResolver`] yourself to plug in any
//! other resolver, and combine resolvers with the chain / tuple / variant
//! adapters under [`client`].
//!
//! ## Global DNS resolver
//!
//! Rama uses a process-wide shared DNS resolver by default. If nothing is
//! installed explicitly, it lazily initialises to [`client::NativeDnsResolver`]
//! on first use — i.e. the best native resolver for the current platform.
//!
//! Use [`client::try_init_global_dns_resolver`] or
//! [`client::init_global_dns_resolver`] to install a different resolver
//! (e.g. `client::HickoryDnsResolver` under the `hickory` feature, or
//! your own implementation). This
//! has to happen before the first lookup; both initialisers fail / panic
//! if the global resolver has already been initialised.
//!
//! [`client::GlobalDnsResolver`] is a thin handle that defers fetching the
//! global resolver until it's actually used — handy when you want to pass
//! a resolver around without forcing it to be constructed yet.
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

#[cfg(feature = "dial9")]
#[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
pub mod dial9;

pub mod client;
