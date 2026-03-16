use std::{
    net::IpAddr,
    pin::Pin,
    task::{self, Poll},
    time::Duration,
};

use pin_project_lite::pin_project;
use rama_core::{
    error::{BoxError, ErrorExt, extra::OpaqueError},
    extensions::Extensions,
    futures::{DelayStream, Stream, stream},
    stream::{StreamExt as _, adapters::Merge},
};
use rama_net::{
    address::Host,
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
    pub fn lookup_ip(self) -> impl Stream<Item = Result<IpAddr, OpaqueError>> + Send + 'a {
        let ip_mode = self
            .extensions
            .as_ref()
            .and_then(|ext| ext.get().copied())
            .unwrap_or_default();
        let dns_mode = self
            .extensions
            .as_ref()
            .and_then(|ext| ext.get().copied())
            .unwrap_or_default();

        let domain = match self.host {
            Host::Name(domain) => domain,
            Host::Address(ip) => {
                //check if IP Version is allowed
                return HappyEyeballIpStream::Once {
                    stream: rama_core::stream::once(match (ip, ip_mode) {
                        (IpAddr::V4(_), ConnectIpMode::Ipv6) => {
                            Err(BoxError::from("IPv4 address is not allowed").into_opaque_error())
                        }
                        (IpAddr::V6(_), ConnectIpMode::Ipv4) => {
                            Err(BoxError::from("IPv6 address is not allowed").into_opaque_error())
                        }
                        _ => {
                            // if the host is already defined as an allowed IP address
                            // we can directly connect to it
                            Ok(ip)
                        }
                    }),
                };
            }
        };

        let maybe_dns_overwrite = self
            .extensions
            .as_ref()
            .and_then(|ext| ext.get::<DnsAddresssResolverOverwrite>());

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
            .map(|result| result.map(IpAddr::V6))
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
