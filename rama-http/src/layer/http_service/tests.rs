use super::*;
use parking_lot::Mutex;
use rama_core::extensions::{Extension, Extensions};
use rama_net::{ConnectorTargetInputExt as _, address::HostWithPort};
use std::{collections::VecDeque, sync::atomic::AtomicUsize};

#[derive(Debug, Clone, Extension)]
struct AttemptMarker;

#[derive(Debug)]
struct Record {
    target: HostWithPort,
    origin: HostWithPort,
    required: Option<Version>,
    prior_attempt_marker: bool,
    proxy: Option<String>,
}

#[derive(Clone, Debug)]
enum Outcome {
    Success(ApplicationProtocol),
    #[cfg(feature = "tls")]
    Failure(ConnectionErrorDomain, ConnectionErrorKind),
    #[cfg(feature = "tls")]
    Pending(bool),
    #[cfg(feature = "tls")]
    RejectedAvailability,
    #[cfg(feature = "tls")]
    WrongIdentity,
    #[cfg(feature = "tls")]
    WrongAlpn,
}

#[derive(Clone, Debug)]
struct FakeConnector {
    outcomes: Arc<Mutex<VecDeque<Outcome>>>,
    records: Arc<Mutex<Vec<Record>>>,
    dispatched: Arc<AtomicUsize>,
    health: Arc<Mutex<Vec<Arc<rama_net::conn::ConnectionHealthWatcher>>>>,
}

impl FakeConnector {
    fn new(outcomes: impl IntoIterator<Item = Outcome>) -> Self {
        Self {
            outcomes: Arc::new(Mutex::new(outcomes.into_iter().collect())),
            records: Arc::default(),
            dispatched: Arc::default(),
            health: Arc::default(),
        }
    }
}

#[derive(Debug)]
struct FakeConnection {
    extensions: Extensions,
    dispatched: Arc<AtomicUsize>,
    expected_alt_used: Option<String>,
}

impl ExtensionsRef for FakeConnection {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl Service<crate::Request> for FakeConnection {
    type Output = crate::Response;
    type Error = std::convert::Infallible;

    async fn serve(&self, request: crate::Request) -> Result<Self::Output, Self::Error> {
        use crate::body::util::BodyExt as _;
        assert_eq!(
            request
                .headers()
                .get(crate::header::ALT_USED)
                .map(|value| value.to_str().unwrap()),
            self.expected_alt_used.as_deref()
        );
        assert_eq!(
            request.into_body().collect().await.unwrap().to_bytes(),
            "dispatch once"
        );
        self.dispatched.fetch_add(1, Ordering::SeqCst);
        Ok(crate::Response::new(crate::Body::empty()))
    }
}

impl Service<ConnectRequest> for FakeConnector {
    type Output = EstablishedClientConnection<FakeConnection, ConnectRequest>;
    type Error = ConnectionError;

    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        let expected_alt_used = input
            .extensions()
            .get_ref::<SelectedHttpService>()
            .filter(|selected| selected.candidate.source == HttpServiceSource::AltSvc)
            .map(|selected| selected.candidate.target.to_string());
        if input.extensions().contains::<SelectedHttpService>() {
            assert!(input.extensions().contains::<HttpServiceCandidates>());
        }
        self.records.lock().push(Record {
            target: input.connector_target().unwrap(),
            origin: input.authority.clone(),
            required: input
                .extensions()
                .get_ref::<TargetHttpVersion>()
                .map(|version| version.0),
            prior_attempt_marker: input.extensions().contains::<AttemptMarker>(),
            proxy: input
                .extensions()
                .get_ref::<rama_net::client::ProxyRoute>()
                .and_then(|route| route.proxy_address())
                .map(|proxy| proxy.address.to_string()),
        });
        input.extensions().insert(AttemptMarker);
        let outcome = self
            .outcomes
            .lock()
            .pop_front()
            .expect("unexpected extra attempt");
        #[cfg(not(feature = "tls"))]
        let Outcome::Success(protocol) = outcome;
        #[cfg(feature = "tls")]
        let protocol = match outcome.clone() {
            #[cfg(feature = "tls")]
            Outcome::Failure(domain, kind) => {
                return Err(ConnectionError::new(
                    BoxError::from_static_str("scripted failure"),
                    domain,
                    kind,
                ));
            }
            #[cfg(feature = "tls")]
            Outcome::Pending(reject) => {
                if reject {
                    input
                        .extensions()
                        .get_ref::<HttpServiceAttempt>()
                        .unwrap()
                        .reject();
                }
                return std::future::pending().await;
            }
            #[cfg(feature = "tls")]
            Outcome::RejectedAvailability => {
                input
                    .extensions()
                    .get_ref::<HttpServiceAttempt>()
                    .unwrap()
                    .reject();
                return Err(ConnectionError::transport(
                    BoxError::from_static_str("later address unavailable"),
                    ConnectionErrorKind::Unavailable,
                ));
            }
            Outcome::Success(protocol) => protocol,
            #[cfg(feature = "tls")]
            Outcome::WrongIdentity | Outcome::WrongAlpn => ApplicationProtocol::HTTP_2,
        };
        let extensions = Extensions::new();
        let health = Arc::new(rama_net::conn::ConnectionHealthWatcher::default());
        self.health.lock().push(health.clone());
        extensions.insert_arc(health);
        extensions.insert(TargetHttpVersion(Version::try_from(&protocol).unwrap()));
        #[cfg(feature = "tls")]
        {
            let identity = if matches!(outcome, Outcome::WrongIdentity) {
                "wrong.example".parse().unwrap()
            } else {
                input.authority.host.clone()
            };
            extensions.insert(rama_tls::client::TlsServerAuthentication(Some(identity)));
            extensions.insert(rama_tls::client::NegotiatedTlsParameters {
                protocol_version: rama_tls::ProtocolVersion::TLSv1_3,
                application_layer_protocol: Some(if matches!(outcome, Outcome::WrongAlpn) {
                    ApplicationProtocol::HTTP_11
                } else {
                    protocol
                }),
                peer_certificate_chain: None,
                server_name: None,
                resumed: None,
            });
        }
        Ok(EstablishedClientConnection {
            input,
            conn: FakeConnection {
                extensions,
                dispatched: self.dispatched.clone(),
                expected_alt_used,
            },
        })
    }
}

fn input() -> ConnectRequest {
    ConnectRequest::new("origin.example:443".parse().unwrap())
        .with_application_protocol(Protocol::HTTPS)
}

fn capabilities<S>(inner: S) -> HttpServiceConnector<S> {
    HttpServiceConnector::new(inner).with_protocols([
        ApplicationProtocol::HTTP_11,
        ApplicationProtocol::HTTP_2,
        ApplicationProtocol::HTTP_3,
    ])
}

#[cfg(feature = "tls")]
fn advertise(input: &ConnectRequest, candidates: &[(ApplicationProtocol, &'static str)]) {
    let origin = HttpOrigin::new(
        input.application_protocol.clone().unwrap(),
        input.authority.clone(),
    )
    .unwrap();
    input.extensions().insert(HttpServiceCandidates::new(
        origin,
        candidates
            .iter()
            .map(|(protocol, target)| {
                HttpServiceCandidate::new(protocol.clone(), target.parse().unwrap())
            })
            .collect::<Vec<_>>(),
    ));
}

#[tokio::test]
async fn frame_learning_is_opt_in_and_preserves_custom_observers() {
    for enabled in [false, true] {
        let connector = capabilities(FakeConnector::new([Outcome::Success(
            ApplicationProtocol::HTTP_2,
        )]))
        .maybe_with_cache(enabled.then(AltSvcCache::default));
        let established = connector.serve(input()).await.unwrap();
        assert_eq!(
            established
                .input
                .extensions()
                .contains::<AltSvcObserverExtension>(),
            enabled
        );
    }

    let request = input();
    let custom = Arc::new(AltSvcCache::default().frame_observer(origin(&request).unwrap()));
    request.extensions().insert_arc(custom.clone());
    let established = capabilities(FakeConnector::new([Outcome::Success(
        ApplicationProtocol::HTTP_2,
    )]))
    .with_cache(AltSvcCache::default())
    .serve(request)
    .await
    .unwrap();
    assert!(Arc::ptr_eq(
        &custom,
        &established
            .input
            .extensions()
            .get_arc::<AltSvcObserverExtension>()
            .unwrap()
    ));
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn candidates_wrap_proxy_routes_and_preserve_origin_and_attempt_isolation() {
    use rama_net::client::{ProxyRoute, ProxyRoutes, ProxyRoutesConnector};
    let input = input();
    advertise(
        &input,
        &[
            (ApplicationProtocol::HTTP_3, "first.example:8443"),
            (ApplicationProtocol::HTTP_2, "second.example:9443"),
        ],
    );
    input.extensions().insert(ProxyRoutes::new([
        ProxyRoute::Proxy("http://proxy-a.example:3128".parse().unwrap()),
        ProxyRoute::Proxy("http://proxy-b.example:3128".parse().unwrap()),
    ]));
    let fake = FakeConnector::new([
        Outcome::Failure(
            ConnectionErrorDomain::Transport,
            ConnectionErrorKind::Unavailable,
        ),
        Outcome::Failure(
            ConnectionErrorDomain::Transport,
            ConnectionErrorKind::Unavailable,
        ),
        Outcome::Success(ApplicationProtocol::HTTP_2),
    ]);
    let established = capabilities(ProxyRoutesConnector::new(fake.clone()))
        .serve(input.fork())
        .await
        .unwrap();
    assert!(!input.extensions().contains::<AttemptMarker>());
    assert!(!input.extensions().contains::<SelectedHttpService>());
    let records = fake.records.lock();
    assert_eq!(
        records
            .iter()
            .map(|record| (record.target.to_string(), record.proxy.as_deref()))
            .collect::<Vec<_>>(),
        [
            (
                "first.example:8443".to_owned(),
                Some("proxy-a.example:3128")
            ),
            (
                "first.example:8443".to_owned(),
                Some("proxy-b.example:3128")
            ),
            (
                "second.example:9443".to_owned(),
                Some("proxy-a.example:3128")
            ),
        ]
    );
    assert!(
        records
            .iter()
            .all(|record| !record.prior_attempt_marker && record.origin == input.authority)
    );
    assert_eq!(
        established
            .conn
            .extensions()
            .get_ref::<EstablishedHttpService>()
            .unwrap()
            .candidate
            .target
            .to_string(),
        "second.example:9443"
    );
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn fallback_keeps_original_input_and_dispatches_body_once() {
    let input = input();
    advertise(&input, &[(ApplicationProtocol::HTTP_2, "alt.example:8443")]);
    let fake = FakeConnector::new([
        Outcome::Failure(
            ConnectionErrorDomain::Transport,
            ConnectionErrorKind::Unavailable,
        ),
        Outcome::Success(ApplicationProtocol::HTTP_11),
    ]);
    let established = capabilities(fake.clone()).serve(input).await.unwrap();
    assert_eq!(fake.dispatched.load(Ordering::SeqCst), 0);
    {
        let records = fake.records.lock();
        assert_eq!(records[1].target.to_string(), "origin.example:443");
        assert_eq!(records[1].required, None);
        assert!(!records[1].prior_attempt_marker);
    }
    established
        .conn
        .serve(crate::Request::new(crate::Body::from("dispatch once")))
        .await
        .unwrap();
    assert_eq!(fake.dispatched.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn authentication_alpn_and_policy_failures_never_fall_back() {
    for outcome in [
        Outcome::WrongIdentity,
        Outcome::WrongAlpn,
        Outcome::Failure(
            ConnectionErrorDomain::Application,
            ConnectionErrorKind::Authentication,
        ),
        Outcome::Failure(
            ConnectionErrorDomain::Local,
            ConnectionErrorKind::InvalidInput,
        ),
        Outcome::Failure(
            ConnectionErrorDomain::Transport,
            ConnectionErrorKind::Protocol,
        ),
    ] {
        let input = input();
        advertise(&input, &[(ApplicationProtocol::HTTP_2, "alt.example:8443")]);
        let fake = FakeConnector::new([outcome]);
        drop(capabilities(fake.clone()).serve(input).await.unwrap_err());
        assert_eq!(fake.records.lock().len(), 1);
        for health in fake.health.lock().iter() {
            assert_eq!(health.health(), rama_net::conn::ConnectionHealth::Broken);
        }
    }
}

#[tokio::test]
async fn required_h3_works_without_discovery_and_http11_input_does_not_pin() {
    for (version, required) in [
        (Version::HTTP_3, Some(Version::HTTP_3)),
        (Version::HTTP_11, None),
    ] {
        let input = input();
        input.extensions().insert(HttpRequestVersion(version));
        let fake = FakeConnector::new([Outcome::Success(
            ApplicationProtocol::try_from(version).unwrap(),
        )]);
        capabilities(fake.clone()).serve(input).await.unwrap();
        assert_eq!(fake.records.lock()[0].required, required);
    }
}

#[tokio::test]
async fn explicit_target_remains_authoritative() {
    let input = input();
    input
        .extensions()
        .insert(ConnectorTarget("forced.example:443".parse().unwrap()));
    #[cfg(feature = "tls")]
    advertise(
        &input,
        &[(ApplicationProtocol::HTTP_3, "ignored.example:8443")],
    );
    let fake = FakeConnector::new([Outcome::Success(ApplicationProtocol::HTTP_2)]);
    capabilities(fake.clone()).serve(input).await.unwrap();
    assert_eq!(
        fake.records.lock()[0].target.to_string(),
        "forced.example:443"
    );
}

#[cfg(feature = "tls")]
fn advertised_input() -> ConnectRequest {
    let input = input();
    advertise(&input, &[(ApplicationProtocol::HTTP_3, "alt.example:8443")]);
    input
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn terminal_failure_latch_survives_timeout_or_later_unavailability() {
    for outcome in [Outcome::Pending(true), Outcome::RejectedAvailability] {
        let fake = FakeConnector::new([outcome]);
        let error = capabilities(fake.clone())
            .with_attempt_timeout(Duration::from_millis(5))
            .serve(advertised_input())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ConnectionErrorKind::Authentication);
        assert_eq!(fake.records.lock().len(), 1);
    }
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn speculative_timeout_allows_fallback_but_overall_timeout_does_not() {
    let fake = FakeConnector::new([
        Outcome::Pending(false),
        Outcome::Success(ApplicationProtocol::HTTP_2),
    ]);
    capabilities(fake.clone())
        .with_attempt_timeout(Duration::from_millis(5))
        .serve(advertised_input())
        .await
        .unwrap();
    assert_eq!(fake.records.lock().len(), 2);

    let fake = FakeConnector::new([Outcome::Pending(false)]);
    let error = capabilities(fake.clone())
        .with_timeout(Duration::from_millis(5))
        .serve(advertised_input())
        .await
        .unwrap_err();
    assert_eq!(error.domain(), ConnectionErrorDomain::Local);
    assert_eq!(error.kind(), ConnectionErrorKind::Timeout);
    assert_eq!(fake.records.lock().len(), 1);
}

#[tokio::test]
async fn unknown_and_websocket_protocols_keep_baseline_behavior() {
    for protocol in [
        None,
        Some(Protocol::WS),
        Some(Protocol::WSS),
        Some("custom".parse().unwrap()),
    ] {
        let mut input = input();
        input.application_protocol = protocol;
        let fake = FakeConnector::new([Outcome::Success(ApplicationProtocol::HTTP_11)]);
        capabilities(fake.clone()).serve(input).await.unwrap();
        let records = fake.records.lock();
        assert_eq!(records[0].required, None);
        assert_eq!(records[0].target, records[0].origin);

        assert_eq!(records[0].proxy, None);
    }
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn plaintext_hints_do_not_authorize_opportunistic_tls() {
    let input = ConnectRequest::new("origin.example:80".parse().unwrap())
        .with_application_protocol(Protocol::HTTP);
    advertise(&input, &[(ApplicationProtocol::HTTP_2, "alt.example:443")]);
    let fake = FakeConnector::new([Outcome::Success(ApplicationProtocol::HTTP_11)]);
    capabilities(fake.clone()).serve(input).await.unwrap();
    let records = fake.records.lock();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].target.to_string(), "origin.example:80");

    assert_eq!(records[0].required, None);
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn capabilities_and_required_version_filter_before_dialing() {
    let input = input();
    advertise(
        &input,
        &[
            (ApplicationProtocol::HTTP_2_TCP, "cleartext.example:80"),
            (ApplicationProtocol::HTTP_3, "h3.example:443"),
            (ApplicationProtocol::HTTP_2, "h2.example:443"),
        ],
    );
    input
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));
    let fake = FakeConnector::new([Outcome::Success(ApplicationProtocol::HTTP_2)]);
    capabilities(fake.clone()).serve(input).await.unwrap();
    let records = fake.records.lock();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].target.to_string(), "h2.example:443");
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn maximum_attempts_reserves_origin_fallback() {
    let input = input();
    advertise(
        &input,
        &[
            (ApplicationProtocol::HTTP_2, "first.example:443"),
            (ApplicationProtocol::HTTP_2, "second.example:443"),
        ],
    );
    let fake = FakeConnector::new([
        Outcome::Failure(
            ConnectionErrorDomain::Transport,
            ConnectionErrorKind::Unavailable,
        ),
        Outcome::Success(ApplicationProtocol::HTTP_11),
    ]);
    capabilities(fake.clone())
        .with_max_attempts(2)
        .serve(input)
        .await
        .unwrap();
    let records = fake.records.lock();
    assert_eq!(records.len(), 2);
    assert_eq!(records[1].target.to_string(), "origin.example:443");
}

#[tokio::test]
async fn zero_budget_or_attempt_limit_does_not_dial() {
    for (timeout, attempts, kind) in [
        (Duration::ZERO, 1, ConnectionErrorKind::Timeout),
        (Duration::from_secs(1), 0, ConnectionErrorKind::InvalidInput),
    ] {
        let fake = FakeConnector::new([]);
        let error = capabilities(fake.clone())
            .with_timeout(timeout)
            .with_max_attempts(attempts)
            .serve(input())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), kind);
        assert!(fake.records.lock().is_empty());
    }
}

#[tokio::test]
async fn explicit_version_must_be_established() {
    let input = input();
    input
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));
    let fake = FakeConnector::new([Outcome::Success(ApplicationProtocol::HTTP_11)]);
    let error = capabilities(fake.clone()).serve(input).await.unwrap_err();
    assert_eq!(error.kind(), ConnectionErrorKind::Protocol);
    assert_eq!(fake.records.lock().len(), 1);
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn only_alt_svc_discovery_adds_alt_used() {
    for source in [HttpServiceSource::Configured, HttpServiceSource::AltSvc] {
        let input = input();
        input.extensions().insert(HttpServiceCandidates::new(
            origin(&input).unwrap(),
            vec![
                HttpServiceCandidate::new(
                    ApplicationProtocol::HTTP_2,
                    "alt.example:443".parse().unwrap(),
                )
                .with_source(source),
            ],
        ));
        let fake = FakeConnector::new([Outcome::Success(ApplicationProtocol::HTTP_2)]);
        let established = capabilities(fake.clone()).serve(input).await.unwrap();
        assert_eq!(
            established
                .conn
                .extensions()
                .get_ref::<EstablishedHttpService>()
                .unwrap()
                .candidate
                .source,
            source
        );
        established
            .conn
            .serve(crate::Request::new(crate::Body::from("dispatch once")))
            .await
            .unwrap();
        assert_eq!(fake.dispatched.load(Ordering::SeqCst), 1);
    }
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn baseline_pool_hit_retains_established_alternative_provenance() {
    let inner = rama_core::service::service_fn(async |input: ConnectRequest| {
        let origin = origin(&input).unwrap();
        let mut established = FakeConnector::new([Outcome::Success(ApplicationProtocol::HTTP_2)])
            .serve(input)
            .await?;
        let target = origin.authority().clone();
        established.conn.expected_alt_used = Some(target.to_string());
        established
            .conn
            .extensions()
            .insert(EstablishedHttpService::new(
                origin,
                HttpServiceCandidate::new(ApplicationProtocol::HTTP_2, target)
                    .with_source(HttpServiceSource::AltSvc),
            ));
        Ok::<_, ConnectionError>(established)
    });
    let established = capabilities(inner).serve(input()).await.unwrap();
    established
        .conn
        .serve(crate::Request::new(crate::Body::from("dispatch once")))
        .await
        .unwrap();
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn latest_cache_snapshot_is_used_and_proxies_ignore_direct_backoff() {
    let cache = AltSvcCache::default();
    let input = input();
    let origin = origin(&input).unwrap();
    let mut headers = crate::HeaderMap::new();
    headers.insert(
        crate::header::ALT_SVC,
        crate::HeaderValue::from_static("h2=\"first.example:443\""),
    );
    cache.record_authenticated(&origin, &headers, Duration::ZERO);
    headers.insert(
        crate::header::ALT_SVC,
        crate::HeaderValue::from_static("h2=\"second.example:443\""),
    );
    cache.record_authenticated(&origin, &headers, Duration::ZERO);
    let fake = FakeConnector::new([Outcome::Success(ApplicationProtocol::HTTP_2)]);
    capabilities(fake.clone())
        .with_cache(cache.clone())
        .serve(input)
        .await
        .unwrap();
    assert_eq!(
        fake.records.lock()[0].target.to_string(),
        "second.example:443"
    );

    let fresh = cache.lookup(&origin).unwrap();
    cache.failed(&fresh, 0);
    let input = self::input();
    input
        .extensions()
        .insert(rama_net::client::ProxyRoute::Proxy(
            "http://proxy.example:3128".parse().unwrap(),
        ));
    let fake = FakeConnector::new([Outcome::Success(ApplicationProtocol::HTTP_2)]);
    capabilities(fake.clone())
        .with_cache(cache)
        .serve(input)
        .await
        .unwrap();
    assert_eq!(
        fake.records.lock()[0].target.to_string(),
        "second.example:443"
    );
}

#[cfg(not(feature = "tls"))]
#[tokio::test]
async fn alternatives_without_tls_verification_support_are_not_attempted() {
    let input = input();
    input.extensions().insert(HttpServiceCandidates::new(
        origin(&input).unwrap(),
        vec![HttpServiceCandidate::new(
            ApplicationProtocol::HTTP_2,
            "alt.example:443".parse().unwrap(),
        )],
    ));
    let fake = FakeConnector::new([Outcome::Success(ApplicationProtocol::HTTP_11)]);
    capabilities(fake.clone()).serve(input).await.unwrap();
    let records = fake.records.lock();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].target.to_string(), "origin.example:443");
    assert!(!records[0].prior_attempt_marker);
}

#[test]
fn retry_requires_explicit_transport_availability() {
    for domain in [
        ConnectionErrorDomain::Transport,
        ConnectionErrorDomain::Application,
        ConnectionErrorDomain::Local,
        ConnectionErrorDomain::Unknown,
    ] {
        for kind in [
            ConnectionErrorKind::Unavailable,
            ConnectionErrorKind::Timeout,
            ConnectionErrorKind::Authentication,
            ConnectionErrorKind::Protocol,
            ConnectionErrorKind::Rejected,
            ConnectionErrorKind::InvalidInput,
            ConnectionErrorKind::Internal,
            ConnectionErrorKind::Other,
        ] {
            let error = ConnectionError::new(BoxError::from_static_str("test"), domain, kind);
            assert_eq!(
                availability(&error),
                domain == ConnectionErrorDomain::Transport
                    && matches!(
                        kind,
                        ConnectionErrorKind::Unavailable | ConnectionErrorKind::Timeout
                    )
            );
        }
    }
}

#[cfg(feature = "tls")]
#[tokio::test]
async fn retries_fork_original_request_and_use_current_cache() {
    let cache = AltSvcCache::default();
    let origin = origin(&input()).unwrap();
    let mut headers = crate::HeaderMap::new();
    headers.insert(
        crate::header::ALT_SVC,
        crate::HeaderValue::from_static("h2=\"first.example:443\""),
    );
    cache.record_authenticated(&origin, &headers, Duration::ZERO);
    let fake = FakeConnector::new([
        Outcome::Success(ApplicationProtocol::HTTP_2),
        Outcome::Success(ApplicationProtocol::HTTP_2),
        Outcome::Success(ApplicationProtocol::HTTP_11),
        Outcome::Success(ApplicationProtocol::HTTP_11),
    ]);
    let connector = capabilities(fake.clone()).with_cache(cache.clone());
    let original = input();
    connector.serve(original.fork()).await.unwrap();
    headers.insert(
        crate::header::ALT_SVC,
        crate::HeaderValue::from_static("h2=\"second.example:443\""),
    );
    cache.record_authenticated(&origin, &headers, Duration::ZERO);
    let pins = Arc::new(rama_tls::client::TlsServerCertPins::new(
        rama_tls::client::TlsServerCertPin::SpkiSha256([7; 32]),
    ));
    original.extensions().insert_arc(pins.clone());
    original
        .extensions()
        .insert(rama_net::client::ProxyRoute::Proxy(
            "http://new-proxy.example:3128".parse().unwrap(),
        ));
    let second = connector.serve(original.fork()).await.unwrap();
    assert!(Arc::ptr_eq(
        &pins,
        &second
            .input
            .extensions()
            .get_arc::<rama_tls::client::TlsServerCertPins>()
            .unwrap()
    ));
    cache.clear(&origin);
    let third = connector.serve(original.fork()).await.unwrap();
    assert!(Arc::ptr_eq(
        &pins,
        &third
            .input
            .extensions()
            .get_arc::<rama_tls::client::TlsServerCertPins>()
            .unwrap()
    ));
    original
        .extensions()
        .insert(ConnectorTarget("explicit.example:8443".parse().unwrap()));
    original
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_11));
    connector.serve(original.fork()).await.unwrap();
    let records = fake.records.lock();
    assert_eq!(
        records
            .iter()
            .map(|record| record.target.to_string())
            .collect::<Vec<_>>(),
        [
            "first.example:443",
            "second.example:443",
            "origin.example:443",
            "explicit.example:8443"
        ]
    );
    assert!(!records[1].prior_attempt_marker);
    assert_eq!(records[1].proxy.as_deref(), Some("new-proxy.example:3128"));
    assert_eq!(records[2].proxy.as_deref(), Some("new-proxy.example:3128"));
    assert_eq!(records[2].required, None);

    assert_eq!(records[3].required, Some(Version::HTTP_11));
}
