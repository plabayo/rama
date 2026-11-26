use super::*;
use ahash::HashMap;
use parking_lot::Mutex;
use rama_core::futures::StreamExt as _;
use rama_core::futures::{Stream, stream};
use rama_dns::{
    client::resolver::ServiceBindingRecord,
    wire::{Name, ServiceBinding},
};
use rama_net::address::Domain;
use rama_net::{ConnectorTargetInputExt as _, client::EstablishedClientConnection};
use rama_tls::client::{
    ServerVerifyMode, TlsEncryptedClientHello, TlsServerVerify, resolve_target_ech,
    target_ech_required,
};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Default)]
struct Resolver {
    records: HashMap<Domain, Vec<ServiceBindingRecord>>,
    queries: Arc<Mutex<Vec<String>>>,
    pending: Option<Domain>,
    failure: Option<Domain>,
    delay_address: bool,
}

impl DnsServiceBindingResolver for Resolver {
    type Error = BoxError;

    fn lookup_https(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBindingRecord, BoxError>> + Send + '_ {
        self.queries.lock().push(format!("HTTPS {domain}"));
        let records = self.records.get(&domain).cloned().unwrap_or_default();
        let pending = self.pending.as_ref() == Some(&domain);
        let fail = self.failure.as_ref() == Some(&domain);
        rama_core::futures::StreamExt::flatten(stream::once(async move {
            if pending {
                std::future::pending::<()>().await;
            }
            // Append errors after records to exercise atomic RRset rejection.
            stream::iter(
                records.into_iter().map(Ok).chain(
                    fail.then(|| Err(std::io::Error::other("test resolver failure").into())),
                ),
            )
        }))
    }

    fn lookup_svcb(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<ServiceBindingRecord, BoxError>> + Send + '_ {
        stream::empty()
    }
}

impl DnsAddressResolver for Resolver {
    type Error = BoxError;

    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, BoxError>> + Send + '_ {
        self.queries.lock().push(format!("A {domain}"));
        let delayed = self.delay_address;
        stream::once(async move {
            if delayed {
                tokio::task::yield_now().await;
            }
            Ok(Ipv4Addr::new(192, 0, 2, 1))
        })
    }

    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, BoxError>> + Send + '_ {
        self.queries.lock().push(format!("AAAA {domain}"));
        stream::empty()
    }
}

fn record(owner: &str, target: &str, params: &[(u16, &[u8])]) -> ServiceBindingRecord {
    let mut wire = vec![0, 1];
    wire.extend_from_slice(Name::from_presentation(target).unwrap().as_wire());
    for (key, value) in params {
        wire.extend_from_slice(&key.to_be_bytes());
        wire.extend_from_slice(&(value.len() as u16).to_be_bytes());
        wire.extend_from_slice(value);
    }
    ServiceBindingRecord {
        owner: Name::from_presentation(owner).unwrap(),
        binding: ServiceBinding::parse_rdata(&wire).unwrap(),
    }
}

fn input() -> ConnectRequest {
    ConnectRequest::new("origin.example:443".parse().unwrap())
        .with_application_protocol(Protocol::HTTPS)
}

fn setup(ech: bool) -> HttpsServiceLayer<Resolver> {
    let mut params: Vec<(u16, &[u8])> = vec![(1, b"\x02h2"), (3, b"\x24\xe3")];
    if ech {
        params.push((5, b"\x00\x05\xfe\x0d\x00\x01\x00"));
    }
    let resolver = Resolver {
        records: HashMap::from_iter([(
            Domain::from_static("origin.example"),
            vec![record("origin.example", "physical.example", &params)],
        )]),
        ..Default::default()
    };
    HttpsServiceLayer::new()
        .with_resolver(resolver)
        .with_ech_capable(true)
}

#[tokio::test]
async fn dns_produces_endpoint_facts_without_changing_origin() {
    let layer = setup(false);
    let request = input();
    layer.discover(&request).await.unwrap();
    let snapshot = request
        .extensions()
        .get_ref::<HttpServiceCandidates>()
        .unwrap();
    assert!(snapshot.allows_origin_fallback());
    assert_eq!(
        snapshot.get(0).unwrap().target.to_string(),
        "physical.example.:9443"
    );
    assert_eq!(snapshot.get(0).unwrap().source, HttpServiceSource::Https);
    assert_eq!(request.authority.to_string(), "origin.example:443");
    assert!(
        snapshot
            .candidate_extensions(0)
            .unwrap()
            .contains::<ConnectorTargetStream>()
    );
}

/// A `wss` origin is its `https` origin's server (RFC 9460 section 9.6): its records'
/// endpoint, address hints and ECH apply; plaintext `ws` is not discovered.
#[tokio::test]
async fn wss_uses_the_https_records_of_its_origin() {
    for (protocol, discovered) in [
        (Protocol::HTTPS, true),
        (Protocol::WSS, true),
        (Protocol::WS, false),
        (Protocol::HTTP, false),
    ] {
        let layer = setup(true);
        let request = ConnectRequest::new("origin.example:443".parse().unwrap())
            .with_application_protocol(protocol.clone());
        layer.discover(&request).await.unwrap();
        let Some(snapshot) = request.extensions().get_ref::<HttpServiceCandidates>() else {
            assert!(!discovered, "{protocol:?}");
            continue;
        };
        assert!(discovered, "{protocol:?}");
        assert_eq!(
            snapshot.get(0).unwrap().target.to_string(),
            "physical.example.:9443",
            "{protocol:?}"
        );
        let extensions = snapshot.candidate_extensions(0).unwrap();
        assert!(
            extensions.contains::<ConnectorTargetStream>(),
            "{protocol:?}"
        );
        assert!(
            extensions
                .get_ref::<TargetEchConfig>()
                .unwrap()
                .matches_target(&snapshot.get(0).unwrap().target),
            "{protocol:?}"
        );
    }
}

#[tokio::test]
async fn intent_and_required_ech_control_reliance() {
    for (intent, required, reliant) in [
        (Some(true), false, true),
        (Some(false), false, false),
        (None, true, true),
        (None, false, true),
    ] {
        let layer = setup(true);
        let request = input();
        if let Some(intent) = intent {
            request.extensions().insert(TlsEncryptedClientHello(intent));
        }
        if required {
            request.extensions().insert(EchRequirement::Required);
        }
        layer.discover(&request).await.unwrap();
        let snapshot = request
            .extensions()
            .get_ref::<HttpServiceCandidates>()
            .unwrap();
        assert_eq!(snapshot.allows_origin_fallback(), !required);
        let extensions = snapshot.candidate_extensions(0).unwrap();
        assert!(!extensions.contains::<EchRequirement>());
        assert!(
            extensions
                .get_ref::<TargetEchServiceBinding>()
                .unwrap()
                .reliant
        );
        let effective = request.extensions().fork();
        effective.extend(extensions);
        assert_eq!(
            target_ech_required(&effective, &snapshot.get(0).unwrap().target, true).unwrap(),
            reliant
        );
        assert!(
            extensions
                .get_ref::<TargetEchConfig>()
                .unwrap()
                .matches_target(&snapshot.get(0).unwrap().target)
        );
    }
}

#[tokio::test]
async fn caller_constraints_filter_protocols_before_reliance() {
    let layer = setup(true);
    let request = input();
    request.extensions().insert(TlsEncryptedClientHello(true));
    request
        .extensions()
        .insert(TlsAlpn(vec![ApplicationProtocol::HTTP_3].into()));
    layer.discover(&request).await.unwrap();
    assert!(!request.extensions().contains::<HttpServiceCandidates>());
}

#[tokio::test]
async fn explicit_target_and_ech_knowledge_bypass_dns() {
    for target in [true, false] {
        let layer = setup(true);
        let request = input();
        if target {
            request
                .extensions()
                .insert(ConnectorTarget("elsewhere.example:443".parse().unwrap()));
        } else {
            request.extensions().insert(TargetEchConfig::new(
                request.authority.clone(),
                vec![0, 1, 2],
            ));
        }
        layer.discover(&request).await.unwrap();
        assert!(layer.resolver.queries.lock().is_empty());
        assert!(!request.extensions().contains::<HttpServiceCandidates>());
    }
}

#[tokio::test]
async fn named_proxy_discovery_requires_permission_and_never_prefetches_addresses() {
    for permitted in [false, true] {
        let layer = setup(true).with_proxy_discovery(permitted);
        let request = input();
        request
            .extensions()
            .insert(rama_net::client::ProxyRoute::Proxy(
                "socks5h://proxy.example:1080".parse().unwrap(),
            ));
        layer.discover(&request).await.unwrap();
        assert!(!request.extensions().contains::<ConnectorTargetStream>());
        tokio::task::yield_now().await;
        let queries = layer.resolver.queries.lock();
        assert_eq!(queries.len(), usize::from(permitted));
        assert!(queries.iter().all(|query| query.starts_with("HTTPS ")));
        if permitted {
            let snapshot = request
                .extensions()
                .get_ref::<HttpServiceCandidates>()
                .unwrap();
            assert!(
                !snapshot
                    .candidate_extensions(0)
                    .unwrap()
                    .contains::<ConnectorTargetStream>()
            );
        }
    }
}

#[tokio::test]
async fn alt_svc_and_https_intersect_protocols_and_preserve_advertisements() {
    let cache = AltSvcCache::default();
    let request = input();
    let origin = HttpOrigin::new(Protocol::HTTPS, request.authority.clone()).unwrap();
    cache.record_frame(
        &origin,
        rama_core::bytes::Bytes::from_static(
            b"h2=\"alt.example:443\", h2=\"alt2.example:443\", h3=\":8443\"",
        ),
        std::time::Instant::now(),
    );
    let resolver = Resolver {
        records: HashMap::from_iter([
            (
                Domain::from_static("alt.example"),
                vec![record("alt.example", ".", &[(1, b"\x02h2\x02h3")])],
            ),
            (
                Domain::from_static("alt2.example"),
                vec![record(
                    "alt2.example",
                    "alt2b.example",
                    &[(1, b"\x02h3"), (2, b"")],
                )],
            ),
            (
                Domain::from_static("_8443._https.origin.example"),
                vec![record(
                    "_8443._https.origin.example",
                    "alt3.example",
                    &[(1, b"\x02h3"), (3, b"\x24\xe3")],
                )],
            ),
        ]),
        ..Default::default()
    };
    let layer = HttpsServiceLayer::new()
        .with_resolver(resolver)
        .with_cache(cache.clone());
    layer.discover(&request).await.unwrap();
    let snapshot = request
        .extensions()
        .get_ref::<HttpServiceCandidates>()
        .unwrap();
    // RFC 9460 §9.3: HTTPS refines the endpoint, never the Alt-Svc protocol.
    let mut attempts = Vec::new();
    let mut redirected = false;
    for (index, candidate) in snapshot.iter().enumerate() {
        let extensions = snapshot.candidate_extensions(index).unwrap();
        let endpoint = extensions
            .get_ref::<ConnectorTarget>()
            .map_or(&candidate.target, |target| &target.0);
        attempts.push((
            candidate.protocol.to_string(),
            endpoint.host.to_string().trim_end_matches('.').to_owned(),
            endpoint.port,
        ));
        let selection = extensions.get_ref::<HttpServiceSelection>().unwrap();
        assert_eq!(selection.candidates.get(selection.index), Some(candidate));
        if let Some(target) = extensions.get_ref::<ConnectorTarget>() {
            assert!(!target.0.to_string().starts_with("alt2b"));
            if target.0.to_string() == "alt3.example.:9443" {
                redirected = true;
                assert_eq!(candidate.protocol, ApplicationProtocol::HTTP_3);
                assert_eq!(candidate.target.to_string(), "origin.example:8443");
                assert!(extensions.contains::<HttpServiceSelection>());
            }
        }
    }
    assert!(redirected);
    attempts.sort_unstable();
    attempts.dedup();
    let mut expected = [
        (ApplicationProtocol::HTTP_2, "alt.example", 443),
        // Bare authorities remain allowed for SVCB-optional fallback.
        (ApplicationProtocol::HTTP_2, "alt2.example", 443),
        (ApplicationProtocol::HTTP_3, "alt3.example", 9443),
        (ApplicationProtocol::HTTP_3, "origin.example", 8443),
    ]
    .map(|(protocol, host, port)| (protocol.to_string(), host.to_owned(), port));
    expected.sort_unstable();
    assert_eq!(attempts, expected);
}

#[tokio::test]
async fn insecure_optional_ech_does_not_become_required() {
    let layer = setup(true);
    let request = input();
    request.extensions().insert(TlsEncryptedClientHello(true));
    request
        .extensions()
        .insert(TlsServerVerify(ServerVerifyMode::Disable));
    layer.discover(&request).await.unwrap();
    let snapshot = request
        .extensions()
        .get_ref::<HttpServiceCandidates>()
        .unwrap();
    assert!(snapshot.allows_origin_fallback());
    let settings = snapshot.candidate_extensions(0).unwrap();
    assert!(settings.contains::<TargetEchConfig>());
    assert!(!settings.contains::<EchRequirement>());
}

#[tokio::test(start_paused = true)]
async fn timeout_falls_back_only_without_an_ech_requirement() {
    for required in [false, true] {
        let mut layer = setup(true).with_timeout(Duration::from_millis(100));
        layer.resolver.pending = Some(Domain::from_static("origin.example"));
        let request = input();
        if required {
            request.extensions().insert(EchRequirement::Required);
        }
        let result = layer.discover(&request).await;
        if required {
            assert_eq!(result.unwrap_err().kind(), ConnectionErrorKind::Timeout);
        } else {
            result.unwrap();
        }
        assert!(!request.extensions().contains::<HttpServiceCandidates>());
    }
}

#[tokio::test(start_paused = true)]
async fn later_timeout_does_not_erase_known_origin_reliance() {
    let mut layer = setup(true).with_timeout(Duration::from_millis(100));
    layer.resolver.pending = Some(Domain::from_static("alt.example"));
    let request = input();
    request.extensions().insert(TlsEncryptedClientHello(true));
    let cache = AltSvcCache::default();
    cache.record_frame(
        &HttpOrigin::new(Protocol::HTTPS, request.authority.clone()).unwrap(),
        rama_core::bytes::Bytes::from_static(b"h2=\"alt.example:443\""),
        std::time::Instant::now(),
    );
    layer.set_cache(cache);
    layer.discover(&request).await.unwrap();
    let candidates = request
        .extensions()
        .get_ref::<HttpServiceCandidates>()
        .unwrap();
    assert!(!candidates.is_empty());
    let facts = candidates.candidate_extensions(0).unwrap();
    assert!(facts.contains::<TargetEchConfig>());
    assert!(facts.get_ref::<TargetEchServiceBinding>().unwrap().reliant);
    resolve_target_ech(request.extensions(), &request.authority, true).unwrap_err();
    request.extensions().insert(TlsEncryptedClientHello(false));
    assert!(
        resolve_target_ech(request.extensions(), &request.authority, true)
            .unwrap()
            .config
            .is_none()
    );
}

#[tokio::test]
async fn empty_discovery_leaves_inner_advertisements_available() {
    let layer = HttpsServiceLayer::new().with_resolver(Resolver::default());
    let request = input();
    layer.discover(&request).await.unwrap();
    assert!(!request.extensions().contains::<HttpServiceCandidates>());
    // With no competing snapshot the selector retains its normal cache lookup.
    // Its cache-selection behavior is covered by the selector integration tests.
}

#[tokio::test]
async fn discovery_does_not_resolve_unused_candidates_or_origin() {
    let layer = setup(false);
    let request = input();
    layer.discover(&request).await.unwrap();
    assert_eq!(*layer.resolver.queries.lock(), ["HTTPS origin.example"]);

    let candidates = request
        .extensions()
        .get_ref::<HttpServiceCandidates>()
        .unwrap();
    let source = candidates
        .candidate_extensions(0)
        .unwrap()
        .get_ref::<ConnectorTargetStream>()
        .unwrap();
    let extensions = Extensions::new();
    extensions.insert(rama_net::mode::DnsResolveIpMode::SingleIpV4);
    let mut stream = source.stream(&extensions);
    assert_eq!(*layer.resolver.queries.lock(), ["HTTPS origin.example"]);
    assert_eq!(
        stream.next().await.unwrap().unwrap(),
        std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
    );
    assert_eq!(
        *layer.resolver.queries.lock(),
        ["HTTPS origin.example", "A physical.example."]
    );
}

#[tokio::test]
async fn empty_dns_composes_with_a_separately_configured_selector_cache() {
    let request = input();
    let cache = AltSvcCache::default();
    cache.record_frame(
        &HttpOrigin::new(Protocol::HTTPS, request.authority.clone()).unwrap(),
        rama_core::bytes::Bytes::from_static(b"h2=\"alt.example:443\""),
        std::time::Instant::now(),
    );
    let targets = Arc::new(Mutex::new(Vec::new()));
    let inner = rama_core::service::service_fn({
        let targets = targets.clone();
        move |input: ConnectRequest| {
            targets.lock().push(input.connector_target().unwrap());
            async {
                Err::<
                    rama_net::client::EstablishedClientConnection<
                        rama_core::ServiceInput<()>,
                        ConnectRequest,
                    >,
                    _,
                >(ConnectionError::transport(
                    BoxError::from_static_str("test endpoint unavailable"),
                    ConnectionErrorKind::Unavailable,
                ))
            }
        }
    });
    let selector = super::super::http_service::HttpServiceConnector::new(inner).with_cache(cache);
    let service = HttpsServiceLayer::new()
        .with_resolver(Resolver::default())
        .layer(selector);
    let error = service.serve(request).await.unwrap_err();
    assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
    let targets = targets.lock();
    assert_eq!(
        targets.iter().map(ToString::to_string).collect::<Vec<_>>(),
        ["alt.example:443", "origin.example:443"]
    );
}

#[tokio::test]
async fn stream_tls_defaults_do_not_hide_a_separate_h3_transport() {
    let mut layer = setup(false).with_tls(TlsClientConfig::default_http());
    layer.resolver.records.insert(
        Domain::from_static("origin.example"),
        vec![record("origin.example", ".", &[(1, b"\x02h3"), (2, b"")])],
    );
    let request = input();
    layer.discover(&request).await.unwrap();
    assert_eq!(
        request
            .extensions()
            .get_ref::<HttpServiceCandidates>()
            .unwrap()
            .get(0)
            .unwrap()
            .protocol,
        ApplicationProtocol::HTTP_3
    );
    let request = input();
    request.extensions().insert(TlsAlpn::http_2());
    layer.discover(&request).await.unwrap();
    assert!(!request.extensions().contains::<HttpServiceCandidates>());
}

#[tokio::test]
async fn final_profile_intent_controls_origin_fallback_without_extra_dials() {
    for ech in [None, Some(false), Some(true)] {
        let request = input();
        request.extensions().insert(TlsAlpn::http_2());
        let dials = Arc::new(Mutex::new(Vec::new()));
        let inner = rama_core::service::service_fn({
            let dials = dials.clone();
            move |request: ConnectRequest| {
                let dials = dials.clone();
                async move {
                    // A profile may override the default after discovery.
                    if let Some(ech) = ech {
                        request.extensions().insert(TlsEncryptedClientHello(ech));
                    }
                    let target = request.connector_target().unwrap();
                    resolve_target_ech(request.extensions(), &target, true).map_err(|error| {
                        ConnectionError::local(error, ConnectionErrorKind::Unavailable)
                    })?;
                    dials.lock().push(target);
                    Err::<EstablishedClientConnection<rama_core::ServiceInput<()>, ConnectRequest>, _>(
                        ConnectionError::transport(
                            BoxError::from_static_str("simulated unavailable endpoint"),
                            ConnectionErrorKind::Unavailable,
                        ),
                    )
                }
            }
        });
        let service =
            setup(true).layer(super::super::http_service::HttpServiceConnector::new(inner));
        let error = service.serve(request).await.unwrap_err();
        assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
        let dials = dials.lock();
        assert_eq!(dials.len(), if ech.unwrap_or(true) { 1 } else { 2 });
        assert_eq!(dials[0].to_string(), "physical.example.:9443");
        if ech == Some(false) {
            assert_eq!(dials[1].to_string(), "origin.example:443");
        }
    }
}

#[tokio::test]
async fn dns_alpn_selects_one_candidate_per_transport() {
    for alpn in [b"\x02h3".as_slice(), b"\x02h2\x08http/1.1", b"\x08http/1.1"] {
        let layer = HttpsServiceLayer::new().with_resolver(Resolver {
            records: HashMap::from_iter([(
                Domain::from_static("origin.example"),
                vec![record("origin.example", "physical.example", &[(1, alpn)])],
            )]),
            ..Default::default()
        });
        let request = input();
        layer.discover(&request).await.unwrap();
        let snapshot = request
            .extensions()
            .get_ref::<HttpServiceCandidates>()
            .unwrap();
        let candidates: Vec<_> = snapshot.iter().collect();
        assert_eq!(
            candidates
                .iter()
                .filter(|c| c.protocol != ApplicationProtocol::HTTP_3)
                .count(),
            1
        );
        assert_eq!(
            candidates.last().unwrap().protocol,
            ApplicationProtocol::HTTP_2
        );
        assert_eq!(candidates.len(), if alpn == b"\x02h3" { 2 } else { 1 });
    }
}

async fn consume_with_inner_resolver(input: ConnectRequest, resolver: Resolver) {
    let transport = rama_core::service::service_fn(async |input: ConnectRequest| {
        let source = input
            .extensions()
            .get_ref::<ConnectorTargetStream>()
            .unwrap();
        assert!(source.matches_target(&input.connector_target().unwrap()));
        assert_eq!(
            source
                .stream(input.extensions())
                .next()
                .await
                .unwrap()
                .unwrap(),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        );
        Ok::<_, ConnectionError>(EstablishedClientConnection {
            input,
            conn: rama_core::ServiceInput::new(()),
        })
    });
    rama_dns::client::DnsConnector::with_resolver(transport, resolver)
        .serve(input)
        .await
        .unwrap();
}

#[tokio::test]
async fn bare_alias_and_advertisement_keep_discovery_resolver_lazy() {
    let mut alias_wire = vec![0, 0];
    alias_wire.extend_from_slice(Name::from_presentation("alias.example").unwrap().as_wire());
    let alias = ServiceBindingRecord {
        owner: Name::from_presentation("origin.example").unwrap(),
        binding: ServiceBinding::parse_rdata(&alias_wire).unwrap(),
    };
    let resolver = Resolver {
        records: HashMap::from_iter([
            (Domain::from_static("origin.example"), vec![alias]),
            (
                Domain::from_static("alias.example"),
                vec![record(
                    "alias.example",
                    ".",
                    &[(1, b"\x02h2"), (4, &[203, 0, 113, 9])],
                )],
            ),
        ]),
        delay_address: true,
        ..Default::default()
    };
    let cache = AltSvcCache::default();
    let request = input();
    request
        .extensions()
        .insert(rama_net::mode::DnsResolveIpMode::SingleIpV4);
    cache.record_frame(
        &HttpOrigin::new(Protocol::HTTPS, request.authority.clone()).unwrap(),
        rama_core::bytes::Bytes::from_static(b"h2=\"alt.example:443\""),
        std::time::Instant::now(),
    );
    let layer = HttpsServiceLayer::new()
        .with_resolver(resolver.clone())
        .with_cache(cache);
    layer.discover(&request).await.unwrap();
    assert!(
        resolver
            .queries
            .lock()
            .iter()
            .all(|query| query.starts_with("HTTPS "))
    );
    let candidates = request
        .extensions()
        .get_ref::<HttpServiceCandidates>()
        .unwrap();
    let inner = Resolver::default();
    for target in ["alias.example.:443", "alt.example:443"] {
        let (index, candidate) = candidates
            .iter()
            .enumerate()
            .rfind(|(_, c)| c.target.to_string() == target)
            .unwrap();
        let attempt = input();
        attempt
            .extensions()
            .insert(rama_net::mode::DnsResolveIpMode::SingleIpV4);
        attempt
            .extensions()
            .insert(ConnectorTarget(candidate.target.clone()));
        attempt
            .extensions()
            .extend(candidates.candidate_extensions(index).unwrap());
        consume_with_inner_resolver(attempt, inner.clone()).await;
    }
    assert!(
        inner.queries.lock().is_empty(),
        "fallback endpoints must not switch resolver"
    );
    let queries = resolver.queries.lock();
    assert!(queries.iter().any(|query| query == "A alias.example."));
    assert!(queries.iter().any(|query| query == "A alt.example"));
    assert_eq!(
        queries
            .iter()
            .filter(|query| query.starts_with("A "))
            .count(),
        2
    );
}

#[tokio::test(start_paused = true)]
async fn discovery_timeout_retains_lazy_origin_resolver() {
    let resolver = Resolver {
        pending: Some(Domain::from_static("origin.example")),
        ..Default::default()
    };
    let layer = HttpsServiceLayer::new().with_resolver(resolver.clone());
    let request = input();
    request
        .extensions()
        .insert(rama_net::mode::DnsResolveIpMode::SingleIpV4);
    layer.discover(&request).await.unwrap();
    assert_eq!(*resolver.queries.lock(), ["HTTPS origin.example"]);
    let inner = Resolver::default();
    consume_with_inner_resolver(request, inner.clone()).await;
    assert!(inner.queries.lock().is_empty());
    assert_eq!(
        *resolver.queries.lock(),
        ["HTTPS origin.example", "A origin.example"]
    );
}

async fn serve_discovery<R>(layer: HttpsServiceLayer<R>) -> (Result<(), ConnectionError>, usize)
where
    R: DnsServiceBindingResolver + DnsAddressResolver + Clone,
{
    let calls = Arc::new(Mutex::new(0));
    let inner = rama_core::service::service_fn({
        let calls = calls.clone();
        move |_: ConnectRequest| {
            *calls.lock() += 1;
            async { Ok::<_, ConnectionError>(()) }
        }
    });
    let result = layer.layer(inner).serve(input()).await;
    let count = *calls.lock();
    (result, count)
}

fn with_test_advertisement(layer: HttpsServiceLayer<Resolver>) -> HttpsServiceLayer<Resolver> {
    let cache = AltSvcCache::default();
    cache.record_frame(
        &HttpOrigin::new(Protocol::HTTPS, input().authority).unwrap(),
        rama_core::bytes::Bytes::from_static(b"h2=\"alt.example:443\""),
        std::time::Instant::now(),
    );
    layer.with_cache(cache)
}

#[tokio::test]
async fn strict_discovery_rejects_origin_and_alternative_errors_before_inner() {
    for name in ["origin.example", "alt.example"] {
        for strict in [false, true] {
            let mut layer =
                with_test_advertisement(setup(false)).with_fail_on_discovery_error(strict);
            layer.resolver.failure = Some(Domain::from_static(name));
            let (result, calls) = serve_discovery(layer).await;
            assert_eq!(calls, usize::from(!strict));
            if strict {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), ConnectionErrorKind::Unavailable);
                let mut cause: &(dyn std::error::Error + 'static) = &error;
                while !cause.is::<std::io::Error>() {
                    cause = cause.source().expect("retain resolver failure cause");
                }
                assert_eq!(cause.to_string(), "test resolver failure");
            } else {
                result.unwrap();
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn strict_discovery_timeouts_do_not_use_primary_checkpoints() {
    for name in ["origin.example", "alt.example"] {
        for strict in [false, true] {
            let mut layer = with_test_advertisement(setup(false))
                .with_timeout(Duration::from_millis(10))
                .with_fail_on_discovery_error(strict);
            layer.resolver.pending = Some(Domain::from_static(name));
            let (result, calls) = serve_discovery(layer).await;
            assert_eq!(calls, usize::from(!strict));
            if strict {
                assert_eq!(result.unwrap_err().kind(), ConnectionErrorKind::Timeout);
            } else {
                result.unwrap();
            }
        }
    }
}

#[tokio::test]
async fn strict_discovery_accepts_empty_and_incompatible_answers() {
    for incompatible in [false, true] {
        let mut resolver = Resolver::default();
        if incompatible {
            resolver.records.insert(
                Domain::from_static("origin.example"),
                vec![record(
                    "origin.example",
                    ".",
                    &[(1, b"\x07unknown"), (2, b"")],
                )],
            );
        }
        // Changing the resolver must preserve the configured failure policy.
        let layer = HttpsServiceLayer::new()
            .with_fail_on_discovery_error(true)
            .with_resolver(resolver);
        assert!(layer.fail_on_discovery_error);
        let request = input();
        layer.discover(&request).await.unwrap();
        assert!(!request.extensions().contains::<HttpServiceCandidates>());
        let (result, calls) = serve_discovery(layer).await;
        result.unwrap();
        assert_eq!(calls, 1);
    }
}

#[tokio::test]
async fn strict_discovery_rejects_bounded_rrsets_without_dialing() {
    let mut layer = setup(false);
    let records = layer
        .resolver
        .records
        .get_mut(&Domain::from_static("origin.example"))
        .unwrap();
    records.push(records[0].clone());
    let bounded = rama_dns::client::resolver::BoundedDnsResolver::bounded(
        layer.resolver.clone(),
        std::num::NonZeroUsize::new(1).unwrap(),
    );
    let layer = layer
        .with_fail_on_discovery_error(true)
        .with_resolver(bounded);
    let (result, calls) = serve_discovery(layer).await;
    assert_eq!(calls, 0);
    let error = result.unwrap_err();
    let mut cause: &(dyn std::error::Error + 'static) = &error;
    while !cause.is::<rama_dns::client::resolver::DnsAnswerLimitReached>() {
        cause = cause.source().expect("retain bounded resolver cause");
    }
}

#[tokio::test]
async fn same_origin_alternative_reuses_origin_https_answer() {
    let ech: &[u8] = b"\x00\x05\xfe\x0d\x00\x01\x00";
    let resolver = Resolver {
        records: HashMap::from_iter([(
            Domain::from_static("origin.example"),
            vec![
                record("origin.example", "ech.example", &[(1, b"\x02h3"), (5, ech)]),
                record("origin.example", "plain.example", &[(1, b"\x02h2")]),
            ],
        )]),
        ..Default::default()
    };
    let cache = AltSvcCache::default();
    let request = input();
    cache.record_frame(
        &HttpOrigin::new(Protocol::HTTPS, request.authority.clone()).unwrap(),
        rama_core::bytes::Bytes::from_static(b"h3=\":443\", h2=\"alt.example:443\", h3=\":8443\""),
        std::time::Instant::now(),
    );
    let layer = HttpsServiceLayer::new()
        .with_resolver(resolver.clone())
        .with_ech_capable(true)
        .with_cache(cache);
    layer.discover(&request).await.unwrap();

    let snapshot = request
        .extensions()
        .get_ref::<HttpServiceCandidates>()
        .unwrap();
    let observed: Vec<_> = snapshot
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            let extensions = snapshot.candidate_extensions(index).unwrap();
            (
                candidate.protocol.to_string(),
                candidate.target.to_string(),
                extensions
                    .get_ref::<ConnectorTarget>()
                    .map(|target| target.0.to_string()),
                extensions
                    .get_ref::<TargetEchServiceBinding>()
                    .unwrap()
                    .reliant,
                extensions.contains::<TargetEchConfig>(),
                extensions
                    .get_ref::<HttpServiceSelection>()
                    .map(|selection| selection.index),
            )
        })
        .collect();
    let entry = |protocol: ApplicationProtocol,
                 target: &str,
                 endpoint: Option<&str>,
                 reliant: bool,
                 config: bool,
                 index: Option<usize>| {
        (
            protocol.to_string(),
            target.to_owned(),
            endpoint.map(ToOwned::to_owned),
            reliant,
            config,
            index,
        )
    };
    // Only the ECH-bearing record serves h3, so that alternative alone is reliant.
    assert_eq!(
        observed[..4],
        [
            entry(
                ApplicationProtocol::HTTP_3,
                "origin.example:443",
                Some("ech.example.:443"),
                true,
                true,
                Some(0)
            ),
            entry(
                ApplicationProtocol::HTTP_3,
                "origin.example:443",
                None,
                true,
                false,
                Some(0)
            ),
            entry(
                ApplicationProtocol::HTTP_2,
                "alt.example:443",
                None,
                false,
                false,
                Some(1)
            ),
            entry(
                ApplicationProtocol::HTTP_3,
                "origin.example:8443",
                None,
                false,
                false,
                Some(2)
            ),
        ]
    );
    let mut primary = observed[4..].to_vec();
    primary.sort_unstable();
    assert_eq!(
        primary,
        [
            entry(
                ApplicationProtocol::HTTP_2,
                "ech.example.:443",
                Some("ech.example.:443"),
                false,
                true,
                None
            ),
            entry(
                ApplicationProtocol::HTTP_2,
                "plain.example.:443",
                Some("plain.example.:443"),
                false,
                false,
                None
            ),
            entry(
                ApplicationProtocol::HTTP_3,
                "ech.example.:443",
                Some("ech.example.:443"),
                false,
                true,
                None
            ),
        ]
    );
    // The origin answer serves its own advertisement; other authorities query.
    assert_eq!(
        *resolver.queries.lock(),
        [
            "HTTPS origin.example",
            "HTTPS alt.example",
            "HTTPS _8443._https.origin.example"
        ]
    );
}
