use rama_core::error::{BoxError, BoxErrorExt as _};
use std::{
    net::IpAddr,
    pin::Pin,
    task::{self, Poll},
    time::Duration,
};

use pin_project_lite::pin_project;
use rama_core::{
    error::{ErrorExt, extra::OpaqueError},
    extensions::Extensions,
    futures::{DelayStream, Stream, stream},
    stream::{StreamExt as _, adapters::Merge},
};
use rama_net::{
    address::{Host, ip::IntoCanonicalIpAddr as _},
    mode::{ConnectIpMode, DnsResolveIpMode},
};

use super::DnsAddresssResolverOverwrite;
use crate::client::resolver::DnsAddressResolver;

/// Extension trait to easily stream IP lookups using the Happy Eyeball algorithm
pub trait HappyEyeballAddressResolverExt: private::HappyEyeballAddressResolverExtSeal {
    /// Build a happy eyeballs address resolver using
    /// a reference to the current address resolver.
    fn happy_eyeballs_resolver(
        &self,
        host: impl Into<Host>,
    ) -> HappyEyeballAddressResolver<'_, Self>;
}

impl<R: crate::client::resolver::DnsAddressResolver> HappyEyeballAddressResolverExt for R {
    fn happy_eyeballs_resolver(
        &self,
        host: impl Into<Host>,
    ) -> HappyEyeballAddressResolver<'_, Self> {
        HappyEyeballAddressResolver {
            host: host.into(),
            resolver: self,
            extensions: None,
        }
    }
}

mod private {
    pub trait HappyEyeballAddressResolverExtSeal:
        crate::client::resolver::DnsAddressResolver
    {
    }
    impl<R: crate::client::resolver::DnsAddressResolver> HappyEyeballAddressResolverExtSeal for R {}
}

/// Happy eyeball address resolver, respecting the IP preferences and DNS modes.
pub struct HappyEyeballAddressResolver<'a, R> {
    host: Host,
    resolver: &'a R,
    extensions: Option<&'a Extensions>,
}

impl<'a, R> HappyEyeballAddressResolver<'a, R> {
    rama_utils::macros::generate_set_and_with! {
        pub fn extensions(mut self, extensions: Option<&'a Extensions>) -> Self {
            self.extensions = extensions;
            self
        }
    }
}

impl<'a, R: crate::client::resolver::DnsAddressResolver> HappyEyeballAddressResolver<'a, R> {
    /// Stream the resolved IP addresses for the configured host,
    /// in happy-eyeballs order, respecting the IP connect/resolve modes.
    ///
    /// IPv4-mapped IPv6 addresses ([RFC 4291, Section 2.5.5.2]) — as IP
    /// literal host or in AAAA records — canonicalize to the embedded
    /// IPv4 address and classify as IPv4 for the IP modes.
    ///
    /// [RFC 4291, Section 2.5.5.2]: https://datatracker.ietf.org/doc/html/rfc4291#section-2.5.5.2
    pub fn lookup_ip(self) -> impl Stream<Item = Result<IpAddr, OpaqueError>> + Send + 'a {
        let ip_mode = self
            .extensions
            .as_ref()
            .and_then(|ext| ext.get_ref().copied())
            .unwrap_or_default();
        let dns_mode = self
            .extensions
            .as_ref()
            .and_then(|ext| ext.get_ref().copied())
            .unwrap_or_default();

        // Try as IP first (most common path — no DNS roundtrip); fall
        // through to Domain otherwise. `Uninterpreted` bridges through
        // both via pct-decode + IDN. Non-promotable hosts (sub-delim
        // reg-name, IPvFuture) error — DNS can't resolve them.
        if let Ok(ip) = self.host.try_as_ip() {
            // fold v4-mapped down to IPv4 (RFC 4291, Section 2.5.5.2)
            // before the family checks below
            let ip = ip.into_canonical_ip_addr();
            return HappyEyeballIpStream::Once {
                stream: rama_core::stream::once(match (ip, ip_mode) {
                    (IpAddr::V4(_), ConnectIpMode::Ipv6) => {
                        Err(BoxError::from_static_str("IPv4 address is not allowed")
                            .into_opaque_error())
                    }
                    (IpAddr::V6(_), ConnectIpMode::Ipv4) => {
                        Err(BoxError::from_static_str("IPv6 address is not allowed")
                            .into_opaque_error())
                    }
                    _ => Ok(ip),
                }),
            };
        }
        let Ok(domain) = self.host.try_into_domain() else {
            return HappyEyeballIpStream::Once {
                stream: rama_core::stream::once(Err(BoxError::from_static_str(
                    "host is not resolvable as a domain",
                )
                .into_opaque_error())),
            };
        };

        let maybe_dns_overwrite = self
            .extensions
            .as_ref()
            .and_then(|ext| ext.get_ref::<DnsAddresssResolverOverwrite>());

        let make_ipv4_stream = || {
            stream::StreamExt::flatten(stream::iter(
                maybe_dns_overwrite
                    .as_ref()
                    .map(|resolver| resolver.lookup_ipv4(domain.clone())),
            ))
            .chain(
                self.resolver
                    .lookup_ipv4(domain.clone())
                    .map(|result| result.map_err(ErrorExt::into_opaque_error)),
            )
            .map(|result| result.map(IpAddr::V4))
        };

        let make_ipv6_stream = || {
            stream::StreamExt::flatten(stream::iter(
                maybe_dns_overwrite
                    .as_ref()
                    .map(|resolver| resolver.lookup_ipv6(domain.clone())),
            ))
            .chain(
                self.resolver
                    .lookup_ipv6(domain.clone())
                    .map(|result| result.map_err(ErrorExt::into_opaque_error)),
            )
            // AAAA records can carry v4-mapped addresses too — same fold-down
            .map(|result| result.map(|ip| IpAddr::V6(ip).into_canonical_ip_addr()))
        };

        match dns_mode {
            DnsResolveIpMode::Dual => {
                let ipv6_stream = make_ipv6_stream();
                let ipv4_stream = make_ipv4_stream();

                HappyEyeballIpStream::Dual {
                    stream: ipv6_stream
                        .merge(DelayStream::new(Duration::from_micros(42), ipv4_stream)),
                }
            }
            DnsResolveIpMode::DualPreferIpV4 => {
                let ipv4_stream = make_ipv4_stream();
                let ipv6_stream = make_ipv6_stream();

                HappyEyeballIpStream::DualPreferIpV4 {
                    stream: ipv4_stream
                        .merge(DelayStream::new(Duration::from_micros(42), ipv6_stream)),
                }
            }
            DnsResolveIpMode::SingleIpV4 => HappyEyeballIpStream::SingleIpV4 {
                stream: make_ipv4_stream(),
            },
            DnsResolveIpMode::SingleIpV6 => HappyEyeballIpStream::SingleIpV6 {
                stream: make_ipv6_stream(),
            },
        }
    }
}

pin_project! {
    #[project = HappyEyeballIpStreamProj]
    enum HappyEyeballIpStream<V4, V6> {
        Dual {
            #[pin]
            stream: Merge<V6, DelayStream<V4>>,
        },
        DualPreferIpV4 {
            #[pin]
            stream: Merge<V4, DelayStream<V6>>,
        },
        Once {
            #[pin]
            stream: rama_core::stream::Once<Result<IpAddr,OpaqueError>>,
        },
        SingleIpV4 {
            #[pin]
            stream: V4,
        },
        SingleIpV6 {
            #[pin]
            stream: V6,
        }
    }
}

impl<V4: Stream<Item = Result<IpAddr, OpaqueError>>, V6: Stream<Item = Result<IpAddr, OpaqueError>>>
    Stream for HappyEyeballIpStream<V4, V6>
{
    type Item = Result<IpAddr, OpaqueError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        match self.project() {
            HappyEyeballIpStreamProj::Dual { stream } => stream.poll_next(cx),
            HappyEyeballIpStreamProj::DualPreferIpV4 { stream } => stream.poll_next(cx),
            HappyEyeballIpStreamProj::Once { stream } => stream.poll_next(cx),
            HappyEyeballIpStreamProj::SingleIpV4 { stream } => stream.poll_next(cx),
            HappyEyeballIpStreamProj::SingleIpV6 { stream } => stream.poll_next(cx),
        }
    }

    #[inline(always)]
    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Dual { stream } => stream.size_hint(),
            Self::DualPreferIpV4 { stream } => stream.size_hint(),
            Self::Once { stream } => stream.size_hint(),
            Self::SingleIpV4 { stream } => stream.size_hint(),
            Self::SingleIpV6 { stream } => stream.size_hint(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::EmptyDnsResolver;
    use rama_net::address::Host;

    #[tokio::test]
    async fn ip_host_returns_directly_without_dns_lookup() {
        // IP-first path: an IP-shaped host short-circuits and emits the
        // address directly without consulting the DNS resolver. Use the
        // empty resolver to prove it: if the code fell through to the
        // domain path, the stream would be empty.
        let host: Host = "127.0.0.1".parse::<std::net::IpAddr>().unwrap().into();
        let mut stream = std::pin::pin!(EmptyDnsResolver.happy_eyeballs_resolver(host).lookup_ip());
        let first = rama_core::futures::StreamExt::next(&mut stream)
            .await
            .expect("should emit the IP directly");
        assert_eq!(
            first.unwrap(),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn pct_encoded_ip_host_bridges_via_try_as_ip() {
        // `%31%32%37.0.0.1` lives in `Host::Uninterpreted` but decodes
        // to `127.0.0.1`. The IP-first early-return must catch it
        // BEFORE attempting DNS resolution as a Domain.
        let host = rama_net::uri::Uri::parse("http://%31%32%37.0.0.1/")
            .unwrap()
            .host()
            .unwrap()
            .into_owned();
        let mut stream = std::pin::pin!(EmptyDnsResolver.happy_eyeballs_resolver(host).lookup_ip());
        let first = stream
            .next()
            .await
            .expect("pct-encoded IP must short-circuit to direct emit");
        assert_eq!(
            first.unwrap(),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn v4_mapped_ip_literal_host_canonicalizes_to_ipv4() {
        // `::ffff:127.0.0.1` identifies IPv4 wire traffic (dual-stack
        // socket form, e.g. WFP redirect targets on Windows) — the
        // resolver must emit the embedded IPv4 address.
        let host: Host = "::ffff:127.0.0.1"
            .parse::<std::net::IpAddr>()
            .unwrap()
            .into();
        let mut stream = std::pin::pin!(EmptyDnsResolver.happy_eyeballs_resolver(host).lookup_ip());
        let first = stream.next().await.expect("should emit the canonical IP");
        assert_eq!(
            first.unwrap(),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn real_ipv6_literal_host_passes_through_unchanged() {
        let host: Host = "2001:db8::1".parse::<std::net::IpAddr>().unwrap().into();
        let mut stream = std::pin::pin!(EmptyDnsResolver.happy_eyeballs_resolver(host).lookup_ip());
        let first = stream.next().await.expect("should emit the IP directly");
        assert_eq!(
            first.unwrap(),
            "2001:db8::1".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn v4_mapped_ip_literal_host_counts_as_ipv4_for_connect_ip_mode() {
        use rama_core::extensions::Extensions;
        use rama_net::mode::ConnectIpMode;

        // allowed under IPv4-only connect mode (it IS IPv4 traffic)...
        let ext = Extensions::new();
        ext.insert(ConnectIpMode::Ipv4);
        let host: Host = "::ffff:127.0.0.1"
            .parse::<std::net::IpAddr>()
            .unwrap()
            .into();
        let mut stream = std::pin::pin!(
            EmptyDnsResolver
                .happy_eyeballs_resolver(host)
                .with_extensions(&ext)
                .lookup_ip()
        );
        let first = stream.next().await.expect("should emit the canonical IP");
        assert_eq!(
            first.unwrap(),
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );

        // ...and rejected under IPv6-only connect mode.
        let ext = Extensions::new();
        ext.insert(ConnectIpMode::Ipv6);
        let host: Host = "::ffff:127.0.0.1"
            .parse::<std::net::IpAddr>()
            .unwrap()
            .into();
        let mut stream = std::pin::pin!(
            EmptyDnsResolver
                .happy_eyeballs_resolver(host)
                .with_extensions(&ext)
                .lookup_ip()
        );
        let first = stream.next().await.expect("should emit a result");
        first.expect_err("v4-mapped (= IPv4 wire traffic) must be rejected in IPv6-only mode");
    }

    #[tokio::test]
    async fn v4_mapped_aaaa_record_canonicalizes_to_ipv4() {
        // an `Ipv6Addr` acts as a stub resolver yielding itself as the
        // sole AAAA record for any domain.
        let mapped: std::net::Ipv6Addr = "::ffff:192.0.2.1".parse().unwrap();
        let host = Host::Name(rama_net::address::Domain::from_static("example.com"));
        let mut stream = std::pin::pin!(mapped.happy_eyeballs_resolver(host).lookup_ip());
        let first = stream.next().await.expect("should emit the canonical IP");
        assert_eq!(
            first.unwrap(),
            "192.0.2.1".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn non_promotable_host_errors() {
        // Sub-delim reg-name promotes to neither IP nor Domain — the
        // resolver emits a single Err.
        let host = rama_net::uri::Uri::parse("http://tag,with,commas/")
            .unwrap()
            .host()
            .unwrap()
            .into_owned();
        let mut stream = std::pin::pin!(EmptyDnsResolver.happy_eyeballs_resolver(host).lookup_ip());
        let first = rama_core::futures::StreamExt::next(&mut stream)
            .await
            .expect("should emit an error");
        first.expect_err("non-promotable host must surface an Err");
    }
}
