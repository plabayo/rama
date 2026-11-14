use super::*;
use ahash::HashMap;
use parking_lot::Mutex;
use rama_core::futures::{Stream, stream};
use rama_dns::{
    client::resolver::ServiceBindingRecord,
    wire::{Name, ServiceBinding},
};
use rama_tls::client::{ServerVerifyMode, TlsServerVerify};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Default)]
struct Resolver {
    records: HashMap<Domain, Vec<ServiceBindingRecord>>,
    queries: Arc<Mutex<Vec<String>>>,
    pending: Option<Domain>,
    wait_for_address: bool,
    address_started: Arc<tokio::sync::Notify>,
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
        let wait_for_address = self.wait_for_address;
        let started = self.address_started.clone();
        rama_core::futures::StreamExt::flatten(stream::once(async move {
            if wait_for_address {
                started.notified().await;
            }
            if pending {
                std::future::pending::<()>().await;
            }
            stream::iter(records.into_iter().map(Ok))
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
        self.address_started.notify_one();
        stream::iter([Ok(Ipv4Addr::new(192, 0, 2, 1))])
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

#[tokio::test]
async fn intent_and_required_ech_control_reliance() {
    for (intent, required, reliant) in [
        (Some(true), false, true),
        (Some(false), false, false),
        (None, true, true),
        (None, false, false),
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
            rama_tls::client::target_ech_required(
                &effective,
                &snapshot.get(0).unwrap().target,
                true
            )
            .unwrap(),
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
                .insert(ConnectorTarget(request.authority.clone()));
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
    let mut redirected = false;
    for (index, candidate) in snapshot.iter().enumerate() {
        let extensions = snapshot.candidate_extensions(index).unwrap();
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
    rama_tls::client::target_ech_config(request.extensions(), &request.authority, true)
        .unwrap_err();
    request.extensions().insert(TlsEncryptedClientHello(false));
    assert!(
        rama_tls::client::target_ech_config(request.extensions(), &request.authority, true)
            .unwrap()
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
async fn origin_address_query_is_polled_while_https_is_pending() {
    let mut layer = setup(false).with_timeout(Duration::from_secs(1));
    layer.resolver.wait_for_address = true;
    let request = input();
    layer.discover(&request).await.unwrap();
    assert!(request.extensions().contains::<HttpServiceCandidates>());
    assert_eq!(
        layer
            .resolver
            .queries
            .lock()
            .iter()
            .filter(|query| query.as_str() == "A origin.example")
            .count(),
        1
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
            use rama_net::ConnectorTargetInputExt as _;
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
    use rama_net::{ConnectorTargetInputExt as _, client::EstablishedClientConnection};
    for ech in [false, true] {
        let request = input();
        request.extensions().insert(TlsAlpn::http_2());
        let dials = Arc::new(Mutex::new(Vec::new()));
        let inner = rama_core::service::service_fn({
            let dials = dials.clone();
            move |request: ConnectRequest| {
                let dials = dials.clone();
                async move {
                    // Installed by a per-candidate profile compiler after discovery.
                    request.extensions().insert(TlsEncryptedClientHello(ech));
                    let target = request.connector_target().unwrap();
                    rama_tls::client::target_ech_config(request.extensions(), &target, true)
                        .map_err(|error| {
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
        assert_eq!(dials.len(), if ech { 1 } else { 2 });
        assert_eq!(dials[0].to_string(), "physical.example.:9443");
        if !ech {
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
