use super::*;
use rama_core::futures::{StreamExt as _, TryStreamExt as _, stream};
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

#[derive(Debug, Default)]
struct RepeatingResolver {
    polls: [AtomicUsize; 6],
}

impl RepeatingResolver {
    fn answers<T>(
        &self,
        slot: usize,
        domain: Domain,
        value: T,
    ) -> impl Stream<Item = Result<T, Infallible>> + Send + '_
    where
        T: Clone + Send + 'static,
    {
        stream::repeat_with(move || {
            assert_eq!(domain, Domain::from_static("example.com"));
            self.polls[slot].fetch_add(1, Ordering::Relaxed);
            Ok(value.clone())
        })
    }
}

impl DnsAddressResolver for RepeatingResolver {
    type Error = Infallible;

    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        self.answers(0, domain, Ipv4Addr::LOCALHOST)
    }

    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        self.answers(1, domain, Ipv6Addr::LOCALHOST)
    }
}

impl DnsCnameResolver for RepeatingResolver {
    type Error = Infallible;

    fn lookup_cname(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Name, Self::Error>> + Send + '_ {
        self.answers(2, domain, Name::root())
    }
}

impl DnsTxtResolver for RepeatingResolver {
    type Error = Infallible;

    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Txt, Self::Error>> + Send + '_ {
        self.answers(3, domain, Txt::parse_rdata(&[1, b'x']).unwrap())
    }
}

impl DnsServiceBindingResolver for RepeatingResolver {
    type Error = Infallible;

    fn lookup_svcb(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
        self.answers(4, domain, ServiceBinding::parse_rdata(&[0, 1, 0]).unwrap())
    }

    fn lookup_https(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
        self.answers(5, domain, ServiceBinding::parse_rdata(&[0, 1, 0]).unwrap())
    }
}

impl DnsResolver for RepeatingResolver {}

fn limit(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).unwrap()
}

async fn expect_limit<T>(answers: impl Stream<Item = Result<T, BoxError>>, allowed: usize) {
    let mut answers = std::pin::pin!(answers);
    for _ in 0..allowed {
        _ = answers.next().await.unwrap().unwrap();
    }
    assert!(
        answers
            .next()
            .await
            .unwrap()
            .err()
            .unwrap()
            .is::<DnsAnswerLimitReached>()
    );
    for _ in 0..3 {
        assert!(answers.next().await.is_none());
    }
}

async fn expect_limits(
    resolver: &BoundedDnsResolver<Arc<RepeatingResolver>>,
    expected: [usize; 6],
) {
    let domain = || Domain::from_static("example.com");
    expect_limit(resolver.lookup_ipv4(domain()), expected[0]).await;
    expect_limit(resolver.lookup_ipv6(domain()), expected[1]).await;
    expect_limit(resolver.lookup_cname(domain()), expected[2]).await;
    expect_limit(resolver.lookup_txt(domain()), expected[3]).await;
    expect_limit(resolver.lookup_svcb(domain()), expected[4]).await;
    expect_limit(resolver.lookup_https(domain()), expected[5]).await;
    for (counter, allowed) in resolver.inner().polls.iter().zip(expected) {
        assert_eq!(counter.load(Ordering::Relaxed), allowed + 1);
    }
}

#[tokio::test]
async fn individual_limits_cover_every_resolver_trait_and_stop_polling() {
    let resolver = BoundedDnsResolver::bounded(Arc::new(RepeatingResolver::default()), limit(20))
        .with_ipv4_limit(limit(1))
        .with_ipv6_limit(limit(2))
        .with_cname_limit(limit(3))
        .with_txt_limit(limit(4))
        .with_svcb_limit(limit(5))
        .with_https_limit(limit(6));
    expect_limits(&resolver, [1, 2, 3, 4, 5, 6]).await;
    // Each fresh lookup (including on a clone or boxed aggregate) gets its own allowance.
    expect_limit(
        resolver
            .clone()
            .lookup_ipv6(Domain::from_static("example.com")),
        2,
    )
    .await;
    expect_limit(
        resolver
            .into_box_dns_resolver()
            .lookup_txt(Domain::from_static("example.com"))
            .map_err(|error| error.into_box_error()),
        4,
    )
    .await;
}

#[tokio::test]
async fn category_settings_replace_only_their_members_and_allow_overrides() {
    let resolver = BoundedDnsResolver::bounded(Arc::new(RepeatingResolver::default()), limit(1))
        .with_ip_limit(limit(2))
        .with_service_binding_limit(limit(3));
    expect_limits(&resolver, [2, 2, 1, 1, 3, 3]).await;
    let resolver = BoundedDnsResolver::bounded(Arc::new(RepeatingResolver::default()), limit(1))
        .with_ip_limit(limit(2))
        .with_ipv6_limit(limit(4))
        .with_service_binding_limit(limit(3))
        .with_https_limit(limit(5));
    expect_limits(&resolver, [2, 4, 1, 1, 3, 5]).await;
}

#[tokio::test]
async fn partial_resolvers_and_first_address_helpers_stay_supported() {
    let resolver = BoundedDnsResolver::bounded(Ipv6Addr::LOCALHOST, NonZeroUsize::MIN);
    let domain = || Domain::from_static("example.com");
    assert!(resolver.lookup_ipv4_first(domain()).await.is_none());
    assert_eq!(
        resolver.lookup_ipv6_first(domain()).await.unwrap().unwrap(),
        Ipv6Addr::LOCALHOST
    );
    assert_eq!(
        resolver.lookup_ipv6_rand(domain()).await.unwrap().unwrap(),
        Ipv6Addr::LOCALHOST
    );
}

#[tokio::test]
async fn exact_limit_empty_stream_and_largest_limit_end_cleanly() {
    for max in [1, 2, usize::MAX] {
        for count in [0, max.min(2)] {
            let source = stream::iter((0..count).map(Ok::<_, Infallible>));
            let results = bounded(source, Some(limit(max))).collect::<Vec<_>>().await;
            assert_eq!(results.len(), count);
            assert!(results.iter().all(Result::is_ok));
        }
    }
}

#[tokio::test]
async fn errors_count_and_keep_the_original_error_until_the_limit() {
    let source = stream::iter([
        Err(std::io::Error::new(std::io::ErrorKind::NotFound, "missing")),
        Ok(42),
        Ok(43),
    ]);
    let mut answers = std::pin::pin!(bounded(source, Some(limit(2))));
    let error = answers.next().await.unwrap().unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(answers.next().await.unwrap().unwrap(), 42);
    assert!(
        answers
            .next()
            .await
            .unwrap()
            .unwrap_err()
            .is::<DnsAnswerLimitReached>()
    );
    assert!(answers.next().await.is_none());
}

#[test]
fn pending_does_not_spend_an_answer_and_end_is_fused() {
    let mut step = 0;
    let source = stream::poll_fn(move |_cx| {
        step += 1;
        match step {
            1 => Poll::Pending,
            2 => Poll::Ready(Some(Ok::<_, Infallible>(42))),
            3 => Poll::Ready(None),
            _ => panic!("polled after end"),
        }
    });
    let mut answers = std::pin::pin!(bounded(source, Some(limit(1))));
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(answers.as_mut().poll_next(&mut cx).is_pending());
    assert!(matches!(
        answers.as_mut().poll_next(&mut cx),
        Poll::Ready(Some(Ok(42)))
    ));
    assert!(matches!(
        answers.as_mut().poll_next(&mut cx),
        Poll::Ready(None)
    ));
    assert!(matches!(
        answers.as_mut().poll_next(&mut cx),
        Poll::Ready(None)
    ));
}

async fn expect_optional_limit<T>(
    answers: impl Stream<Item = Result<T, BoxError>>,
    allowed: Option<usize>,
) {
    if let Some(allowed) = allowed {
        expect_limit(answers, allowed).await;
    } else {
        // Sample a repeating source past every finite bound used in these tests.
        let mut answers = std::pin::pin!(answers);
        for _ in 0..16 {
            _ = answers.next().await.unwrap().unwrap();
        }
    }
}

async fn expect_optional_limits(
    resolver: &BoundedDnsResolver<Arc<RepeatingResolver>>,
    expected: [Option<usize>; 6],
) {
    let domain = || Domain::from_static("example.com");
    expect_optional_limit(resolver.lookup_ipv4(domain()), expected[0]).await;
    expect_optional_limit(resolver.lookup_ipv6(domain()), expected[1]).await;
    expect_optional_limit(resolver.lookup_cname(domain()), expected[2]).await;
    expect_optional_limit(resolver.lookup_txt(domain()), expected[3]).await;
    expect_optional_limit(resolver.lookup_svcb(domain()), expected[4]).await;
    expect_optional_limit(resolver.lookup_https(domain()), expected[5]).await;
    for (counter, allowed) in resolver.inner().polls.iter().zip(expected) {
        assert_eq!(
            counter.load(Ordering::Relaxed),
            allowed.map_or(16, |n| n + 1)
        );
    }
}

#[tokio::test]
async fn unbounded_constructor_and_selective_type_limits() {
    let resolver = BoundedDnsResolver::unbounded(Arc::new(RepeatingResolver::default()));
    expect_optional_limits(&resolver, [None; 6]).await;
    let resolver = BoundedDnsResolver::unbounded(Arc::new(RepeatingResolver::default()))
        .with_ip_limit(limit(2))
        .with_txt_limit(limit(3))
        .maybe_with_ipv6_limit(None);
    expect_optional_limits(&resolver, [Some(2), None, None, Some(3), None, None]).await;
}

#[tokio::test]
async fn every_type_limit_can_be_removed_independently() {
    for slot in 0..6 {
        let mut resolver =
            BoundedDnsResolver::bounded(Arc::new(RepeatingResolver::default()), limit(1));
        match slot {
            0 => {
                resolver.maybe_set_ipv4_limit(None);
            }
            1 => {
                resolver.maybe_set_ipv6_limit(None);
            }
            2 => {
                resolver.maybe_set_cname_limit(None);
            }
            3 => {
                resolver.maybe_set_txt_limit(None);
            }
            4 => {
                resolver.maybe_set_svcb_limit(None);
            }
            _ => {
                resolver.maybe_set_https_limit(None);
            }
        }
        let mut expected = [Some(1); 6];
        expected[slot] = None;
        expect_optional_limits(&resolver, expected).await;
    }
}

#[tokio::test]
async fn aggregate_setters_can_bound_and_unbound_their_categories() {
    let mut resolver = BoundedDnsResolver::unbounded(Arc::new(RepeatingResolver::default()));
    resolver.set_limit(limit(2));
    expect_optional_limits(&resolver, [Some(2); 6]).await;

    let resolver = BoundedDnsResolver::bounded(Arc::new(RepeatingResolver::default()), limit(1))
        .maybe_with_limit(None);
    expect_optional_limits(&resolver, [None; 6]).await;

    let mut resolver =
        BoundedDnsResolver::bounded(Arc::new(RepeatingResolver::default()), limit(1));
    resolver.maybe_set_ip_limit(None);
    resolver.maybe_set_service_binding_limit(None);
    expect_optional_limits(&resolver, [None, None, Some(1), Some(1), None, None]).await;

    let mut resolver = BoundedDnsResolver::unbounded(Arc::new(RepeatingResolver::default()));
    resolver.set_ip_limit(limit(2));
    resolver.set_service_binding_limit(limit(3));
    resolver.maybe_set_limit(None);
    resolver.set_ipv6_limit(limit(4));
    expect_optional_limits(&resolver, [None, Some(4), None, None, None, None]).await;
}

#[tokio::test]
async fn unbounded_stream_preserves_errors_and_finite_end() {
    let source = stream::iter([
        Err(std::io::Error::new(std::io::ErrorKind::NotFound, "missing")),
        Ok(42),
    ]);
    let mut answers = std::pin::pin!(bounded(source, None));
    let error = answers.next().await.unwrap().unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(answers.next().await.unwrap().unwrap(), 42);
    assert!(answers.next().await.is_none());
    assert!(answers.next().await.is_none());
}
