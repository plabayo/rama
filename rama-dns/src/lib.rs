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
//!   blocking system getaddrinfo via tokio's threadpool; it supports address
//!   records only and returns typed errors for CNAME, TXT, SVCB, and HTTPS lookups.
//! - `client::HickoryDnsResolver` — pure-Rust resolver from the
//!   Hickory DNS project (<https://github.com/hickory-dns/hickory-dns>);
//!   gated behind the `hickory` feature.
//! - [`client::DenyAllDnsResolver`] — fails every lookup with
//!   [`client::DnsDeniedError`]; useful when DNS must be disabled.
//! - [`client::EmptyDnsResolver`] — returns no records for every lookup.
//!
//! [`client::resolver::DnsResolver`] is the aggregate of the address, CNAME,
//! TXT, and SVCB/HTTPS resolver traits. Implement those traits yourself to plug in
//! another resolver, and combine resolvers with the chain / tuple / variant
//! adapters under [`client`].
//! [`client::resolver::DnsTxtResolver`] yields one [`wire::Txt`] per DNS TXT
//! resource record; each value preserves that record's character-string
//! boundaries.
//!
//! ### Picking a resolver for high-QPS workloads
//!
//! On Apple platforms (`AppleDnsResolver`, via `DNSServiceQueryRecord`) and
//! Windows (`WindowsDnsResolver`, via `DnsQueryEx` with a completion callback
//! on the system thread pool), the native resolvers are asynchronous: no
//! tokio blocking-pool traffic. `AppleDnsResolver` is still bounded like the
//! others below, at 64 lookups at once as each holds a file descriptor;
//! `WindowsDnsResolver` is unbounded by default, as the DNS Client service
//! queues lookups itself, and takes the same bounds on request.
//!
//! On Linux hosts whose NSS configuration selects `nss-resolve`,
//! `LinuxDnsResolver` first tries systemd-resolved's varlink socket, which is
//! likewise fully asynchronous. This path can also be enabled or disabled
//! explicitly through `LinuxDnsResolver::builder()`. Where the daemon is not
//! selected or available it falls back to `res_nsearch` / `getaddrinfo`, and
//! there — as with [`client::TokioDnsResolver`] (via `getaddrinfo`) — each
//! lookup occupies a tokio blocking-pool thread for the duration of the libc
//! call. Those resolvers bound how many such calls run at once (384 by
//! default, 64 on Apple platforms) and how many queries a burst may leave
//! unanswered (128 per 20ms; `TokioDnsResolver` counts 64 calls, as each asks
//! for A and AAAA), so a burst of distinct names neither floods the pool nor
//! overflows a local stub resolver; a slow upstream answer frees its burst
//! place after the window but keeps its call slot. Bounds are shared by a
//! resolver and the clones made after its last limit setter. Under sustained
//! high-concurrency DNS load (typical for forward proxies) prefer the
//! pure-Rust `client::HickoryDnsResolver` (gated behind the `hickory`
//! feature), which speaks DNS directly over async UDP/TCP and gives finer
//! control over caching and upstream selection.
//!
//! The native resolvers (and hickory, internally) let concurrent lookups of
//! the same name and record type share one query, so a burst of connections
//! to one host costs one lookup rather than one per connection. A lookup is
//! shared within the tokio runtime that started it, between clones with the
//! same timeout.
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
//! ## DNS wire data
//!
//! The [`wire`] module provides provider-neutral DNS wire vocabulary. It
//! decodes A, AAAA, CNAME, and TXT RDATA as well as the shared RDATA used by
//! SVCB and HTTPS records. DNS names, TXT string boundaries, and unknown
//! service parameters are preserved.
//!
//! [`wire::Message`] parses an RFC 1035 message on top of that vocabulary:
//! header flags including [`wire::ResponseCode`], the question section, and
//! the answer section, with compression resolved and RDATA decoded into typed
//! values. Parsing stops after the answer section, keeps whatever decoded
//! before a malformed record unless the strict constructors are used, and
//! leaves normalisation policy to the caller.
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
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]

#[cfg(feature = "dial9")]
#[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
pub mod dial9;

pub mod client;
pub mod wire;
