use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs as _},
    time::Duration,
};

use rama_core::{
    error::{BoxError, ErrorExt as _},
    futures::{Stream, StreamExt as _, async_stream::stream_fn, future::Either, stream},
    telemetry::tracing,
};
use rama_net::address::Domain;
use rama_utils::{
    macros::{error::static_str_error, generate_set_and_with},
    str::arcstr::ArcStr,
};

use super::{
    in_flight::{InFlight, coalesced_stream, leading_dot_refusal},
    limit::{DnsTimeoutError, Limits, LookupLimit, deadline_after},
    resolver::{
        DnsAddressResolver, DnsCnameResolver, DnsResolver, DnsServiceBindingResolver,
        DnsTxtResolver,
    },
};
use crate::wire::{Name, ServiceBinding, Txt};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Portable DNS resolver backed by the host's `getaddrinfo`, run on tokio's
/// blocking pool.
///
/// This relies on the host resolver for address lookups and does not support
/// CNAME, TXT, SVCB, or HTTPS record resolution. Concurrent lookups of one
/// name share a single `getaddrinfo` call.
pub struct TokioDnsResolver {
    timeout: Duration,
    limit: LookupLimit,
    // rooted flag: `Domain` equality ignores the trailing dot getaddrinfo honours
    in_flight: InFlight<(Domain, bool)>,
}

/// Each call asks for A and AAAA at once.
#[cfg(not(target_vendor = "apple"))]
const LIMITS: Limits = Limits::TWO_QUERIES;
#[cfg(target_vendor = "apple")]
const LIMITS: Limits = Limits::TWO_QUERIES.with_apple_descriptors();

impl Default for TokioDnsResolver {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            limit: LookupLimit::new(LIMITS),
            in_flight: InFlight::default(),
        }
    }
}

impl TokioDnsResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    generate_set_and_with! {
        /// Concurrent lookups are only shared between resolvers with the
        /// same timeout.
        pub fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self.in_flight = InFlight::default();
            self
        }
    }

    #[must_use]
    pub fn max_concurrency(&self) -> Option<usize> {
        self.limit.limits().max_concurrency
    }

    generate_set_and_with! {
        /// Maximum concurrent `getaddrinfo` calls (default 384, 64 on Apple
        /// platforms). Each holds a blocking-pool thread until libc returns,
        /// which a timeout cannot cancel, and on Apple platforms an
        /// mDNSResponder connection of launchd's default 256 descriptors.
        pub fn max_concurrency(mut self, max: Option<usize>) -> Self {
            self.limit = self.limit.with(|limits| limits.max_concurrency = max);
            self
        }
    }

    #[must_use]
    pub fn burst_limit(&self) -> Option<usize> {
        self.limit.limits().burst_limit
    }

    generate_set_and_with! {
        /// Maximum `getaddrinfo` calls started within one
        /// [burst window](Self::burst_window) and still unanswered (default
        /// 64, as each asks for A and AAAA). A local stub such as
        /// systemd-resolved drops queries that arrive faster than it reads
        /// them; an answer frees its place at once, a query waiting on a slow
        /// upstream once the window has passed.
        pub fn burst_limit(mut self, max: Option<usize>) -> Self {
            self.limit = self.limit.with(|limits| limits.burst_limit = max);
            self
        }
    }

    #[must_use]
    pub fn burst_window(&self) -> Duration {
        self.limit.limits().burst_window
    }

    generate_set_and_with! {
        /// The window of [`Self::burst_limit`] (default 20ms).
        pub fn burst_window(mut self, window: Duration) -> Self {
            self.limit = self.limit.with(|limits| limits.burst_window = window);
            self
        }
    }

    fn lookup_addresses(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<IpAddr, BoxError>> + Send {
        if let Some(err) = leading_dot_refusal(&domain) {
            return Either::Left(stream::once(std::future::ready(Err(err))));
        }
        let (timeout, limit) = (self.timeout, self.limit.clone());
        let key = (domain.clone(), domain.is_fqdn());
        Either::Right(coalesced_stream(
            self.in_flight.clone(),
            key,
            timeout,
            move || lookup_host_stream(domain, timeout, limit),
        ))
    }
}

impl DnsAddressResolver for TokioDnsResolver {
    type Error = BoxError;

    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        self.lookup_addresses(domain).filter_map(|result| {
            std::future::ready(match result {
                Ok(IpAddr::V4(addr)) => Some(Ok(addr)),
                Ok(IpAddr::V6(_)) => None,
                Err(err) => Some(Err(err)),
            })
        })
    }

    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        self.lookup_addresses(domain).filter_map(|result| {
            std::future::ready(match result {
                Ok(IpAddr::V6(addr)) => Some(Ok(addr)),
                Ok(IpAddr::V4(_)) => None,
                Err(err) => Some(Err(err)),
            })
        })
    }
}

impl DnsTxtResolver for TokioDnsResolver {
    type Error = TokioDnsTxtUnsupportedError;

    fn lookup_txt(
        &self,
        _domain: Domain,
    ) -> impl Stream<Item = Result<Txt, Self::Error>> + Send + '_ {
        stream::once(std::future::ready(Err(TokioDnsTxtUnsupportedError)))
    }
}

impl DnsCnameResolver for TokioDnsResolver {
    type Error = TokioDnsCnameUnsupportedError;

    fn lookup_cname(
        &self,
        _domain: Domain,
    ) -> impl Stream<Item = Result<Name, Self::Error>> + Send + '_ {
        stream::once(std::future::ready(Err(TokioDnsCnameUnsupportedError)))
    }
}

impl DnsServiceBindingResolver for TokioDnsResolver {
    type Error = TokioDnsServiceBindingUnsupportedError;

    fn lookup_svcb(
        &self,
        _domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
        stream::once(std::future::ready(Err(
            TokioDnsServiceBindingUnsupportedError,
        )))
    }

    fn lookup_https(
        &self,
        _domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
        stream::once(std::future::ready(Err(
            TokioDnsServiceBindingUnsupportedError,
        )))
    }
}

impl DnsResolver for TokioDnsResolver {}

fn lookup_host_stream(
    domain: Domain,
    timeout: Duration,
    limit: LookupLimit,
) -> impl Stream<Item = Result<IpAddr, BoxError>> + Send {
    stream_fn(async move |mut yielder| {
        tracing::debug!(?timeout, %domain, "dns::tokio: getaddrinfo");

        let deadline = deadline_after(timeout);
        let task = limit.spawn_blocking(deadline, move |budget| {
            // `None`: the caller already gave up
            (!budget.is_zero()).then(|| {
                (domain.as_str(), 0)
                    .to_socket_addrs()
                    .map(|addrs| addrs.map(|addr| addr.ip()).collect::<Vec<_>>())
            })
        });
        let lookup = async move { tokio::time::timeout_at(deadline, task.await?).await.ok() };

        match lookup.await {
            Some(Ok(Some(Ok(addrs)))) => {
                for addr in addrs {
                    yielder.yield_item(Ok(addr)).await;
                }
            }
            Some(Ok(Some(Err(err)))) => {
                yielder
                    .yield_item(Err(TokioDnsResolverError::message(format!(
                        "tokio dns lookup_host failed: {err}"
                    ))
                    .into()))
                    .await;
            }
            Some(Err(err)) => {
                yielder
                    .yield_item(Err(err.context("tokio dns lookup task failed")))
                    .await;
            }
            Some(Ok(None)) | None => {
                tracing::debug!(?timeout, "dns::tokio: lookup timed out");
                yielder
                    .yield_item(Err(DnsTimeoutError::new(timeout).into()))
                    .await;
            }
        }
    })
}

#[derive(Debug)]
struct TokioDnsResolverError(ArcStr);

impl TokioDnsResolverError {
    fn message(message: impl Into<ArcStr>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for TokioDnsResolverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TokioDnsResolverError {}

static_str_error! {
    #[doc = "Tokio DNS resolver does not support TXT lookups"]
    pub struct TokioDnsTxtUnsupportedError;
}

static_str_error! {
    #[doc = "Tokio DNS resolver does not support CNAME lookups"]
    pub struct TokioDnsCnameUnsupportedError;
}

static_str_error! {
    #[doc = "Tokio DNS resolver does not support SVCB or HTTPS lookups; boxed dispatch preserves this type for downcasting"]
    pub struct TokioDnsServiceBindingUnsupportedError;
}

#[cfg(test)]
mod tests {
    use rama_core::{error::error_chain, futures::future::join_all};

    use super::*;

    #[test]
    fn default_bounds_fit_the_platform() {
        let resolver = TokioDnsResolver::new();
        // getaddrinfo holds an mDNSResponder descriptor per call on Apple
        let max = if cfg!(target_vendor = "apple") {
            64
        } else {
            384
        };
        assert_eq!(resolver.max_concurrency(), Some(max));
        assert_eq!(resolver.burst_limit(), Some(64));
        assert_eq!(resolver.without_max_concurrency().max_concurrency(), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rooted_and_relative_names_do_not_share() {
        // both time out waiting for the busy slot, so no query leaves the host
        let resolver = TokioDnsResolver::new()
            .with_max_concurrency(1)
            .with_timeout(Duration::from_millis(300));
        let (release, held) = std::sync::mpsc::channel::<()>();
        let busy = resolver
            .limit
            .spawn_blocking(
                tokio::time::Instant::now() + Duration::from_secs(10),
                move |_budget| held.recv_timeout(Duration::from_secs(3)).ok(),
            )
            .await
            .expect("the only slot");

        // both queue for the busy slot, each in a run of its own
        let lookups: Vec<_> = ["localhost", "localhost."]
            .map(|name| {
                let resolver = resolver.clone();
                let domain: Domain = name.try_into().expect("valid domain");
                tokio::spawn(async move { resolver.lookup_ipv4(domain).count().await })
            })
            .into();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while resolver.in_flight.running() != 2 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(resolver.in_flight.running(), 2);

        drop(release);
        busy.await.expect("busy lookup ends");
        for lookup in lookups {
            lookup.await.expect("lookup task");
        }
    }

    #[tokio::test]
    async fn leading_dot_name_is_refused_before_sharing() {
        let resolver = TokioDnsResolver::new();
        let (bare, dotted) = tokio::join!(
            resolver
                .lookup_ipv4(Domain::from_static("localhost"))
                .collect::<Vec<_>>(),
            resolver
                .lookup_ipv4(Domain::from_static(".localhost"))
                .collect::<Vec<_>>(),
        );
        assert!(bare.iter().any(Result::is_ok), "{bare:?}");
        assert!(
            matches!(dotted.as_slice(), [Err(err)] if err.to_string().contains("starts with a dot")),
            "{dotted:?}"
        );
    }

    #[test]
    fn only_resolvers_with_the_same_timeout_share_lookups() {
        let resolver = TokioDnsResolver::new();
        assert!(resolver.clone().in_flight.shares_with(&resolver.in_flight));
        let hasty = resolver.clone().with_timeout(Duration::from_millis(100));
        assert!(!hasty.in_flight.shares_with(&resolver.in_flight));
    }

    #[tokio::test]
    async fn huge_timeout_does_not_overflow() {
        let resolver = TokioDnsResolver::new().with_timeout(Duration::MAX);
        let addrs: Vec<_> = resolver
            .lookup_ipv4(Domain::from_static("localhost"))
            .collect()
            .await;
        assert!(addrs.iter().all(Result::is_ok), "{addrs:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn burst_of_lookups_for_one_name_all_resolve() {
        let resolver = TokioDnsResolver::new().with_max_concurrency(2);
        let domain = Domain::from_static("localhost");

        let lookups = (0..256).map(|_| async {
            let v4: Vec<_> = resolver.lookup_ipv4(domain.clone()).collect().await;
            let v6: Vec<_> = resolver.lookup_ipv6(domain.clone()).collect().await;
            (v4, v6)
        });
        for (v4, v6) in join_all(lookups).await {
            assert!(
                v4.iter()
                    .all(|addr| addr.as_ref().is_ok_and(Ipv4Addr::is_loopback))
            );
            assert!(
                v6.iter()
                    .all(|addr| addr.as_ref().is_ok_and(Ipv6Addr::is_loopback))
            );
            assert!(!v4.is_empty() || !v6.is_empty(), "localhost resolves");
        }
        assert_eq!(resolver.max_concurrency(), Some(2));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lookup_waiting_for_a_busy_slot_times_out() {
        let resolver = TokioDnsResolver::new()
            .with_max_concurrency(1)
            .with_timeout(Duration::from_millis(100));
        let (release, held) = std::sync::mpsc::channel::<()>();
        let busy = resolver
            .limit
            .spawn_blocking(
                tokio::time::Instant::now() + Duration::from_secs(10),
                move |_budget| held.recv_timeout(Duration::from_secs(3)).ok(),
            )
            .await
            .expect("the only slot");

        let started = tokio::time::Instant::now();
        let items: Vec<_> = resolver
            .lookup_ipv4(Domain::from_static("localhost"))
            .collect()
            .await;
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(matches!(
            items.as_slice(),
            [Err(err)] if error_chain(err.as_ref()).any(|cause| cause.is::<DnsTimeoutError>())
        ));

        drop(release);
        busy.await.expect("busy lookup ends");
    }

    #[tokio::test]
    async fn named_record_lookups_return_typed_unsupported_errors() {
        let resolver = TokioDnsResolver::new();

        let cname = std::pin::pin!(resolver.lookup_cname(Domain::example()))
            .next()
            .await
            .expect("one error")
            .expect_err("unsupported");
        assert_eq!(cname, TokioDnsCnameUnsupportedError);

        let svcb = std::pin::pin!(resolver.lookup_svcb(Domain::example()))
            .next()
            .await
            .expect("one error")
            .expect_err("unsupported");
        assert_eq!(svcb, TokioDnsServiceBindingUnsupportedError);

        let https = std::pin::pin!(resolver.lookup_https(Domain::example()))
            .next()
            .await
            .expect("one error")
            .expect_err("unsupported");
        assert_eq!(https, TokioDnsServiceBindingUnsupportedError);
    }
}
