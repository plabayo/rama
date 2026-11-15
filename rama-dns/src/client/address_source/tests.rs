use super::*;
use crate::client::{
    EmptyDnsResolver,
    resolver::{BoundedDnsResolver, DnsAddresssResolverOverwrite, DnsAnswerLimitReached},
};
use rama_core::futures::{FutureExt as _, Stream, stream};
use rama_net::mode::{ConnectIpMode, DnsResolveIpMode};
use std::{
    convert::Infallible,
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroUsize,
    sync::atomic::{AtomicUsize, Ordering},
};

#[derive(Clone, Default)]
struct Resolver {
    calls: Arc<AtomicUsize>,
    count: u16,
}

impl DnsAddressResolver for Resolver {
    type Error = Infallible;

    fn lookup_ipv4(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Infallible>> + Send + '_ {
        self.calls.fetch_add(1, Ordering::SeqCst);
        stream::iter((1..=self.count).map(|i| Ok(Ipv4Addr::new(192, 0, (i >> 8) as u8, i as u8))))
    }

    fn lookup_ipv6(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Infallible>> + Send + '_ {
        self.calls.fetch_add(1, Ordering::SeqCst);
        stream::iter((1..=self.count).map(|i| Ok(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i))))
    }
}

fn domain() -> Domain {
    Domain::from_static("target.example")
}

#[tokio::test]
async fn sources_and_streams_are_lazy_and_do_not_truncate_dns() {
    let resolver = Resolver {
        count: 150,
        ..Default::default()
    };
    let source = DnsAddressSource::new(resolver.clone(), domain());
    let unused = source.clone();
    let extensions = Extensions::new();
    let mut first = source.stream(&extensions);
    let mut second = source.stream(&extensions);
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);

    for consumer in [&mut first, &mut second] {
        let answers: Vec<_> = consumer.map(Result::unwrap).collect().await;
        assert_eq!(answers.len(), 300);
        assert_eq!(answers.iter().filter(|ip| ip.is_ipv4()).count(), 150);
        assert!(answers.contains(&IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 150
        ))));
        assert!(answers.contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 0, 150))));
    }
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 4);
    drop(unused);
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn hints_are_complete_candidate_specific_and_use_current_policy() {
    let hints: Arc<[IpAddr]> = (1..=150)
        .map(|i| IpAddr::V4(Ipv4Addr::new(192, 0, 2, i)))
        .collect();
    let source = DnsAddressSource::new(EmptyDnsResolver::new(), domain()).with_hints(hints.clone());
    let other = source.clone().with_hints([IpAddr::V6(Ipv6Addr::LOCALHOST)]);
    let extensions = Extensions::new();
    let values: Vec<_> = source
        .stream(&extensions)
        .map(Result::unwrap)
        .collect()
        .await;
    assert_eq!(values.as_slice(), hints.as_ref());
    let values: Vec<_> = other
        .stream(&extensions)
        .map(Result::unwrap)
        .collect()
        .await;
    assert_eq!(values, [IpAddr::V6(Ipv6Addr::LOCALHOST)]);

    extensions.insert(DnsResolveIpMode::SingleIpV6);
    assert!(source.stream(&extensions).next().await.is_none());
    extensions.insert(ConnectIpMode::Ipv4);
    assert!(other.stream(&extensions).next().await.is_none());
}

#[tokio::test]
async fn explicit_bounds_preserve_per_family_limits_and_errors() {
    for (count, limit) in [(150, 100), (100, 100), (10, 3)] {
        let resolver = BoundedDnsResolver::bounded(
            Resolver {
                count,
                ..Default::default()
            },
            NonZeroUsize::new(limit).unwrap(),
        );
        let source = DnsAddressSource::new(resolver, domain());
        let answers: Vec<_> = source.stream(&Extensions::new()).collect().await;
        assert_eq!(
            answers.iter().filter(|answer| answer.is_ok()).count(),
            2 * usize::from(count).min(limit)
        );
        let errors: Vec<_> = answers.into_iter().filter_map(Result::err).collect();
        assert_eq!(errors.len(), if usize::from(count) > limit { 2 } else { 0 });
        for error in errors {
            let mut cause: &(dyn std::error::Error + 'static) = error.as_ref();
            while !cause.is::<DnsAnswerLimitReached>() {
                cause = cause
                    .source()
                    .expect("bound error must survive the address source");
            }
        }
    }
}

#[derive(Clone)]
struct DelayedResolver(Arc<tokio::sync::Notify>);

impl DnsAddressResolver for DelayedResolver {
    type Error = Infallible;

    fn lookup_ipv4(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Infallible>> + Send + '_ {
        stream::once(async {
            self.0.notified().await;
            Ok(Ipv4Addr::LOCALHOST)
        })
    }

    fn lookup_ipv6(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Infallible>> + Send + '_ {
        stream::empty()
    }
}

#[tokio::test]
async fn pending_dns_uses_hints_then_continues_without_duplicates() {
    let ready = Arc::new(tokio::sync::Notify::new());
    let source = DnsAddressSource::new(DelayedResolver(ready.clone()), domain()).with_hints([
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    ]);
    let extensions = Extensions::new();
    extensions.insert(DnsResolveIpMode::SingleIpV4);
    let mut addresses = source.stream(&extensions);
    assert_eq!(
        addresses.next().now_or_never().unwrap().unwrap().unwrap(),
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    );
    ready.notify_one();
    assert!(addresses.next().await.is_none());
}

#[tokio::test]
async fn ready_dns_and_request_overrides_do_not_use_hints() {
    let source = DnsAddressSource::new(
        Resolver {
            count: 1,
            ..Default::default()
        },
        domain(),
    )
    .with_hints([IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    let extensions = Extensions::new();
    extensions.insert(DnsResolveIpMode::SingleIpV4);
    let values: Vec<_> = source
        .stream(&extensions)
        .map(Result::unwrap)
        .collect()
        .await;
    assert_eq!(values, [IpAddr::V4(Ipv4Addr::new(192, 0, 0, 1))]);

    let empty = DnsAddressSource::new(EmptyDnsResolver::new(), domain())
        .with_hints([IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    extensions.insert(DnsAddresssResolverOverwrite::new(
        BoundedDnsResolver::bounded(
            Resolver {
                count: 100,
                ..Default::default()
            },
            NonZeroUsize::new(70).unwrap(),
        ),
    ));
    let values: Vec<_> = empty.stream(&extensions).collect().await;
    assert_eq!(values.iter().filter(|value| value.is_ok()).count(), 70);
    assert!(values.last().unwrap().is_err());
    assert!(
        !values
            .iter()
            .any(|value| value.as_ref().is_ok_and(|ip| ip.is_loopback()))
    );
}

#[tokio::test]
async fn cached_other_family_wins_over_hints_before_family_delay() {
    // IPv6 finishes empty while IPv4 is immediately available. The ordinary
    // family delay must not make the hint look fresher than the ready A record.
    let extensions = Extensions::new();
    let source = DnsAddressSource::new(Ipv4Addr::LOCALHOST, domain())
        .with_hints([IpAddr::V6(Ipv6Addr::LOCALHOST)]);
    let values: Vec<_> = source
        .stream(&extensions)
        .map(Result::unwrap)
        .collect()
        .await;
    assert_eq!(values, [IpAddr::V4(Ipv4Addr::LOCALHOST)]);
}

#[tokio::test]
async fn newly_ready_dns_supersedes_remaining_hints() {
    let ready = Arc::new(tokio::sync::Notify::new());
    let source = DnsAddressSource::new(DelayedResolver(ready.clone()), domain()).with_hints([
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
    ]);
    let extensions = Extensions::new();
    extensions.insert(DnsResolveIpMode::SingleIpV4);
    let mut addresses = source.stream(&extensions);
    assert_eq!(
        addresses.next().await.unwrap().unwrap(),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
    );
    ready.notify_one();
    assert_eq!(
        addresses.next().await.unwrap().unwrap(),
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    );
    assert!(addresses.next().await.is_none());
}

#[derive(Clone)]
struct RepeatingResolver;

impl DnsAddressResolver for RepeatingResolver {
    type Error = Infallible;

    fn lookup_ipv4(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Infallible>> + Send + '_ {
        stream::repeat(Ok(Ipv4Addr::LOCALHOST))
    }

    fn lookup_ipv6(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Infallible>> + Send + '_ {
        stream::empty()
    }
}

#[tokio::test]
async fn explicit_bound_counts_duplicates_before_deduplication() {
    let source = DnsAddressSource::new(
        BoundedDnsResolver::bounded(RepeatingResolver, NonZeroUsize::new(3).unwrap()),
        domain(),
    );
    let values: Vec<_> = source.stream(&Extensions::new()).collect().await;
    assert_eq!(values.len(), 2);
    assert_eq!(
        *values[0].as_ref().unwrap(),
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    );
    values.into_iter().nth(1).unwrap().unwrap_err();
}

#[derive(Clone)]
struct PendingResolver(Arc<AtomicUsize>);

impl DnsAddressResolver for PendingResolver {
    type Error = Infallible;

    fn lookup_ipv4(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Infallible>> + Send + '_ {
        struct Guard(Arc<AtomicUsize>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let guard = Guard(self.0.clone());
        stream::once(async move {
            let _guard = guard;
            std::future::pending().await
        })
    }

    fn lookup_ipv6(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Infallible>> + Send + '_ {
        stream::empty()
    }
}

#[tokio::test]
async fn dropping_stream_cancels_pending_dns_without_dropping_source() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let source = DnsAddressSource::new(PendingResolver(dropped.clone()), domain())
        .with_hints([IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    let extensions = Extensions::new();
    let mut addresses = source.stream(&extensions);
    addresses.next().await.unwrap().unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    drop(addresses);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    let _still_usable = source;
}

#[derive(Clone)]
struct ErrorThenPendingResolver;

impl DnsAddressResolver for ErrorThenPendingResolver {
    type Error = std::io::Error;

    fn lookup_ipv4(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        stream::pending()
    }

    fn lookup_ipv6(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        stream::iter([Err(std::io::Error::other("test DNS failure"))])
    }
}

#[tokio::test]
async fn immediate_dns_error_does_not_suppress_hints() {
    let hints = [
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
    ];
    let source = DnsAddressSource::new(ErrorThenPendingResolver, domain()).with_hints(hints);
    let extensions = Extensions::new();
    let mut addresses = source.stream(&extensions);

    addresses
        .next()
        .now_or_never()
        .unwrap()
        .unwrap()
        .unwrap_err();
    for hint in hints {
        assert_eq!(
            addresses.next().now_or_never().unwrap().unwrap().unwrap(),
            hint
        );
    }
    assert!(addresses.next().now_or_never().is_none());
}

#[tokio::test]
async fn mapped_ipv6_hints_follow_ipv4_policy_and_deduplicate_dns() {
    let ip = Ipv4Addr::new(192, 0, 2, 1);
    let hint = IpAddr::V6(ip.to_ipv6_mapped());
    let source = DnsAddressSource::new(EmptyDnsResolver::new(), domain()).with_hints([hint]);
    let extensions = Extensions::new();
    let values: Vec<_> = source
        .stream(&extensions)
        .map(Result::unwrap)
        .collect()
        .await;
    assert_eq!(values, [IpAddr::V4(ip)]);

    extensions.insert(DnsResolveIpMode::SingleIpV6);
    assert!(source.stream(&extensions).next().await.is_none());

    // Let the mapped hint win first, then supply the same address through A.
    // This exercises shared deduplication rather than suppression of all hints.
    let ready = Arc::new(tokio::sync::Notify::new());
    let source = DnsAddressSource::new(DelayedResolver(ready.clone()), domain())
        .with_hints([IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped())]);
    extensions.insert(DnsResolveIpMode::SingleIpV4);
    let mut addresses = source.stream(&extensions);
    assert_eq!(
        addresses.next().now_or_never().unwrap().unwrap().unwrap(),
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    );
    ready.notify_one();
    assert!(addresses.next().await.is_none());
}

#[tokio::test]
async fn loopback_names_and_ip_literals_ignore_hints_and_dns() {
    let resolver = Resolver {
        count: 1,
        ..Default::default()
    };
    let hints = [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))];
    let extensions = Extensions::new();
    for name in ["localhost", "service.localhost"] {
        let source =
            DnsAddressSource::new(resolver.clone(), Domain::from_static(name)).with_hints(hints);
        let values: Vec<_> = source
            .stream(&extensions)
            .map(Result::unwrap)
            .collect()
            .await;
        assert_eq!(
            values,
            [
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            ]
        );
    }

    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let values: Vec<_> = resolver
            .happy_eyeballs_resolver(Host::Address(ip))
            .with_extensions(&extensions)
            .with_hints(&hints)
            .lookup_ip()
            .map(Result::unwrap)
            .collect()
            .await;
        assert_eq!(values, [ip]);
    }
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
}
