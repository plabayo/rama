//! Request-lifetime address prefetch shared by discovery and transport selection.
use super::resolver::{
    DnsAddressResolver, DnsAddresssResolverOverwrite, HappyEyeballAddressResolverExt as _,
};
use rama_core::{
    error::{ArcError, BoxError, BoxErrorExt as _, ErrorContext as _},
    extensions::Extensions,
    futures::{StreamExt as _, async_stream::stream_fn, stream::BoxStream},
    rt,
};
use rama_net::{
    address::{Domain, Host},
    client::AddressCandidates,
    mode::{ConnectIpMode, DnsResolveIpMode},
};
use std::{net::IpAddr, sync::Arc};

const MAX_ADDRESSES: usize = 64;

/// A bounded A/AAAA lookup started before service discovery finishes.
///
/// Each consumer gets an independent stream. This retains only one request's
/// answers, adds no DNS cache, and aborts unfinished work when its last clone is
/// dropped. Bind it to a physical endpoint using `ConnectorTargetStream`.
/// Caller resolver overrides suppress hints. Changed request resolution policy
/// starts a fresh ordinary lookup instead of consuming the prefetched answer.
#[derive(Clone)]
pub struct PrefetchedAddressCandidates<R> {
    resolver: R,
    domain: Domain,
    policy: Policy,
    flight: Arc<Flight>,
    hints: Arc<[IpAddr]>,
}

#[derive(Clone)]
struct Policy {
    resolve: DnsResolveIpMode,
    connect: ConnectIpMode,
    resolver: Option<Arc<DnsAddresssResolverOverwrite>>,
}

impl Policy {
    fn of(extensions: &Extensions) -> Self {
        Self {
            resolve: extensions.get_ref().copied().unwrap_or_default(),
            connect: extensions.get_ref().copied().unwrap_or_default(),
            resolver: extensions.get_arc(),
        }
    }

    fn matches(&self, other: &Self) -> bool {
        self.resolve == other.resolve
            && self.connect == other.connect
            && match (&self.resolver, &other.resolver) {
                (None, None) => true,
                (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                _ => false,
            }
    }

    fn extensions(&self) -> Extensions {
        let extensions = Extensions::new();
        extensions.insert(self.resolve);
        extensions.insert(self.connect);
        if let Some(resolver) = &self.resolver {
            extensions.insert_arc(resolver.clone());
        }
        extensions
    }

    fn allows(&self, ip: IpAddr) -> Option<IpAddr> {
        let ip = self.connect.validate_ip(ip).ok()?;
        ((ip.is_ipv4() && self.resolve.ipv4_supported())
            || (ip.is_ipv6() && self.resolve.ipv6_supported()))
        .then_some(ip)
    }
}

struct Flight {
    answers: tokio::sync::watch::Receiver<Vec<Result<IpAddr, ArcError>>>,
    abort: tokio::task::AbortHandle,
}

impl Drop for Flight {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

impl<R: DnsAddressResolver + Clone> PrefetchedAddressCandidates<R> {
    /// Begin a policy-aware lookup now, without waiting for HTTPS discovery.
    ///
    /// Construction immediately starts DNS I/O. Do not construct this for a
    /// route that delegates destination resolution to a proxy unless the caller
    /// has approved this resolver for that privacy context.
    ///
    /// # Panics
    ///
    /// Panics when called outside a Tokio runtime.
    pub fn new(resolver: R, domain: Domain, extensions: &Extensions) -> Self {
        let policy = Policy::of(extensions);
        let request = policy.extensions();
        let query_resolver = resolver.clone();
        let query_domain = domain.clone();
        let (sender, answers) = tokio::sync::watch::channel(Vec::new());
        let task = rt::spawn(async move {
            let addresses = query_resolver
                .happy_eyeballs_resolver(Host::Name(query_domain))
                .with_extensions(&request)
                .lookup_ip();
            let mut addresses = std::pin::pin!(addresses);
            for _ in 0..MAX_ADDRESSES {
                let Some(answer) = addresses.next().await else {
                    return;
                };
                sender.send_modify(|answers| {
                    answers.push(
                        answer.map_err(|error| ArcError::from_box_error(error.into_box_error())),
                    )
                });
            }
        });
        Self {
            resolver,
            domain,
            policy,
            flight: Arc::new(Flight {
                answers,
                abort: task.abort_handle(),
            }),
            hints: Arc::from([]),
        }
    }

    /// Add bounded service-record hints, used if no A/AAAA address is known
    /// when a consumer starts. That consumer finishes its hint batch even if
    /// DNS answers arrive while it is consuming those hints.
    #[must_use]
    pub fn with_hints(mut self, hints: impl IntoIterator<Item = IpAddr>) -> Self {
        self.hints = hints.into_iter().take(MAX_ADDRESSES).collect();
        self
    }
}

impl<R> std::fmt::Debug for PrefetchedAddressCandidates<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrefetchedAddressCandidates")
            .field("domain", &self.domain)
            .field("hint_count", &self.hints.len())
            .finish_non_exhaustive()
    }
}

impl<R: DnsAddressResolver + Clone> AddressCandidates for PrefetchedAddressCandidates<R> {
    fn domain(&self) -> &Domain {
        &self.domain
    }

    fn stream<'a>(&'a self, extensions: &'a Extensions) -> BoxStream<'a, Result<IpAddr, BoxError>> {
        let policy = Policy::of(extensions);
        if !self.policy.matches(&policy) {
            return self
                .resolver
                .happy_eyeballs_resolver(Host::Name(self.domain.clone()))
                .with_extensions(extensions)
                .lookup_ip()
                .map(|result| result.into_box_error())
                .boxed();
        }
        stream_fn(async move |mut yielder| {
            let mut answers = self.flight.answers.clone();
            let mut seen = Vec::new();
            let mut offset = 0;
            if policy.resolver.is_none() && !answers.borrow().iter().any(Result::is_ok) {
                let mut hints: Vec<_> = self
                    .hints
                    .iter()
                    .filter_map(|ip| policy.allows(*ip))
                    .collect();
                hints.sort_by_key(|ip| {
                    if policy.resolve == DnsResolveIpMode::DualPreferIpV4 {
                        ip.is_ipv6()
                    } else {
                        ip.is_ipv4()
                    }
                });
                for ip in hints {
                    if !seen.contains(&ip) {
                        seen.push(ip);
                        yielder.yield_item(Ok(ip)).await;
                    }
                }
            }
            loop {
                let snapshot = answers.borrow_and_update().clone();
                for answer in snapshot.iter().skip(offset) {
                    match answer {
                        Ok(ip) if !seen.contains(ip) => {
                            seen.push(*ip);
                            yielder.yield_item(Ok(*ip)).await;
                        }
                        Ok(_) => {}
                        Err(error) => {
                            yielder
                                .yield_item(Err(Box::new(error.clone()) as BoxError))
                                .await;
                        }
                    }
                }
                offset = snapshot.len();
                if answers.changed().await.is_err() {
                    break;
                }
            }
            if seen.is_empty() {
                yielder
                    .yield_item(Err(BoxError::from_static_str(
                        "DNS address lookup returned no candidates",
                    )))
                    .await;
            }
        })
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::futures::{Stream, stream};
    use std::net::{Ipv4Addr, Ipv6Addr};
    #[derive(Clone, Default)]
    struct Resolver {
        started: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        dropped: Arc<tokio::sync::Notify>,
    }
    struct Dropped(Arc<tokio::sync::Notify>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.notify_one();
        }
    }
    impl DnsAddressResolver for Resolver {
        type Error = BoxError;
        fn lookup_ipv4(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Ipv4Addr, BoxError>> + Send + '_ {
            stream::once(async {
                let _guard = Dropped(self.dropped.clone());
                self.started.notify_one();
                self.release.notified().await;
                Ok(Ipv4Addr::new(192, 0, 2, 1))
            })
        }
        fn lookup_ipv6(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Ipv6Addr, BoxError>> + Send + '_ {
            stream::empty()
        }
    }

    fn domain() -> Domain {
        Domain::from_static("target.example")
    }

    #[tokio::test]
    async fn prefetch_starts_without_a_consumer_and_cancels_with_last_owner() {
        let resolver = Resolver::default();
        let source =
            PrefetchedAddressCandidates::new(resolver.clone(), domain(), &Extensions::new());
        resolver.started.notified().await;
        let clone = source.clone();
        drop(source);
        assert!(!clone.flight.abort.is_finished());
        drop(clone);
        resolver.dropped.notified().await;
    }

    #[tokio::test]
    async fn hints_do_not_wait_for_dns_and_each_consumer_gets_independent_answers() {
        let resolver = Resolver::default();
        let extensions = Extensions::new();
        let ip: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
        let source = PrefetchedAddressCandidates::new(resolver.clone(), domain(), &extensions)
            .with_hints([ip, ip]);
        resolver.started.notified().await;
        let mut first = source.stream(&extensions);
        let mut second = source.stream(&extensions);
        assert_eq!(first.next().await.unwrap().unwrap(), ip);
        assert_eq!(second.next().await.unwrap().unwrap(), ip);
        resolver.release.notify_one();
        assert!(first.next().await.is_none());
        assert!(second.next().await.is_none());
    }

    #[tokio::test]
    async fn completed_dns_answer_wins_over_hints_and_caller_override_suppresses_them() {
        let resolver = Resolver::default();
        let extensions = Extensions::new();
        let source = PrefetchedAddressCandidates::new(resolver.clone(), domain(), &extensions)
            .with_hints([Ipv4Addr::LOCALHOST.into()]);
        let mut answers = source.flight.answers.clone();
        resolver.release.notify_one();
        answers.changed().await.unwrap();
        let values: Vec<_> = source
            .stream(&extensions)
            .map(Result::unwrap)
            .collect()
            .await;
        assert_eq!(values, [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]);
        extensions.insert(DnsAddresssResolverOverwrite::new(
            super::super::DenyAllDnsResolver,
        ));
        source
            .stream(&extensions)
            .next()
            .await
            .unwrap()
            .unwrap_err();
    }

    #[tokio::test]
    async fn hint_families_are_canonicalized_filtered_and_ordered() {
        let extensions = Extensions::new();
        extensions.insert(ConnectIpMode::Ipv6);
        extensions.insert(DnsResolveIpMode::SingleIpV6);
        let resolver = Resolver::default();
        let source =
            PrefetchedAddressCandidates::new(resolver, domain(), &extensions).with_hints([
                Ipv4Addr::LOCALHOST.into(),
                Ipv4Addr::LOCALHOST.to_ipv6_mapped().into(),
                Ipv6Addr::LOCALHOST.into(),
            ]);
        let values: Vec<_> = source
            .stream(&extensions)
            .filter_map(async |value| value.ok())
            .collect()
            .await;
        assert_eq!(values, [IpAddr::V6(Ipv6Addr::LOCALHOST)]);
    }

    #[tokio::test]
    async fn empty_answers_and_hints_are_bounded() {
        let extensions = Extensions::new();
        let source = PrefetchedAddressCandidates::new(
            super::super::EmptyDnsResolver::new(),
            domain(),
            &extensions,
        );
        let values: Vec<_> = source.stream(&extensions).collect().await;
        assert_eq!(values.len(), 1);
        values.into_iter().next().unwrap().unwrap_err();
        let source = source.with_hints((1..=100).map(|last| Ipv4Addr::new(192, 0, 2, last).into()));
        let values: Vec<_> = source
            .stream(&extensions)
            .map(Result::unwrap)
            .collect()
            .await;
        assert_eq!(values.len(), MAX_ADDRESSES);
    }
}
