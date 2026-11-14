use super::*;
use crate::wire::{Name, ServiceBinding};
use ahash::HashMap;
use parking_lot::Mutex;
use rama_core::futures::{Stream, stream};
use std::sync::Arc;

#[derive(Clone, Default)]
struct Resolver {
    answers: HashMap<Domain, Vec<Result<ServiceBindingRecord, &'static str>>>,
    calls: Arc<Mutex<Vec<Domain>>>,
}

impl DnsServiceBindingResolver for Resolver {
    type Error = BoxError;

    fn lookup_https(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<ServiceBindingRecord, BoxError>> + Send + '_ {
        self.calls.lock().push(domain.clone());
        stream::iter(
            self.answers
                .get(&domain)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|record| record.map_err(BoxError::from_static_str)),
        )
    }

    fn lookup_svcb(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<ServiceBindingRecord, BoxError>> + Send + '_ {
        stream::once(async { panic!("HTTPS discovery must not query SVCB") })
    }
}

fn record(
    owner: &str,
    priority: u16,
    target: &str,
    params: &[(u16, &[u8])],
) -> ServiceBindingRecord {
    let mut wire = priority.to_be_bytes().to_vec();
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

fn setup(
    entries: &[(&str, Vec<ServiceBindingRecord>)],
) -> (HttpsServiceBindingLookup<Resolver>, Arc<Mutex<Vec<Domain>>>) {
    let resolver = Resolver {
        answers: entries
            .iter()
            .map(|(name, values)| {
                (
                    Domain::try_from(*name).unwrap(),
                    values.iter().cloned().map(Ok).collect(),
                )
            })
            .collect(),
        ..Resolver::default()
    };
    let calls = resolver.calls.clone();
    (
        HttpsServiceBindingLookup::new().with_resolver(resolver),
        calls,
    )
}

fn authority() -> HostWithPort {
    "origin.example:443".parse().unwrap()
}

fn protocols() -> [ApplicationProtocol; 3] {
    [
        ApplicationProtocol::HTTP_3,
        ApplicationProtocol::HTTP_2,
        ApplicationProtocol::HTTP_11,
    ]
}

#[tokio::test]
async fn query_names_ip_bypass_and_actual_owner() {
    let (lookup, calls) = setup(&[
        (
            "origin.example",
            vec![record("actual.example", 1, ".", &[])],
        ),
        (
            "_8443._https.origin.example",
            vec![record("actual.example", 1, ".", &[(3, &[0x24, 0xe3])])],
        ),
    ]);
    let result = lookup.lookup(&authority(), &protocols(), false).await;
    assert_eq!(result.bindings[0].target.to_string(), "actual.example.:443");
    assert_eq!(result.bindings[0].protocols, [ApplicationProtocol::HTTP_11]);
    let other = lookup
        .lookup(&"origin.example:8443".parse().unwrap(), &protocols(), false)
        .await;
    assert_eq!(other.bindings[0].target.to_string(), "actual.example.:9443");
    assert!(
        lookup
            .lookup(&"127.0.0.1:443".parse().unwrap(), &protocols(), true)
            .await
            .bindings
            .is_empty()
    );
    assert_eq!(
        calls.lock().iter().map(|d| d.as_str()).collect::<Vec<_>>(),
        ["origin.example", "_8443._https.origin.example"]
    );
}

#[tokio::test]
async fn aliases_ignore_service_mode_and_keep_bare_endpoint_after_records() {
    let (lookup, calls) = setup(&[
        (
            "_8443._https.origin.example",
            vec![
                record("origin.example", 5, "wrong.example", &[]),
                record("origin.example", 0, "alias.example", &[]),
            ],
        ),
        (
            "alias.example",
            vec![record("canonical.example", 1, ".", &[])],
        ),
    ]);
    let result = lookup
        .lookup(&"origin.example:8443".parse().unwrap(), &protocols(), false)
        .await;
    assert_eq!(result.bindings.len(), 1);
    assert_eq!(
        result.bindings[0].target.to_string(),
        "canonical.example.:8443"
    );
    assert!(result.followed_alias());
    assert_eq!(
        result.alias_target.unwrap().to_string(),
        "alias.example.:8443"
    );
    assert_eq!(calls.lock().len(), 2);
}

#[tokio::test]
async fn aliases_without_records_and_resolution_failures_preserve_optional_fallback() {
    let (mut lookup, _) = setup(&[(
        "origin.example",
        vec![record("origin.example", 0, "alias.example", &[])],
    )]);
    let result = lookup.lookup(&authority(), &protocols(), false).await;
    assert!(result.bindings.is_empty());
    assert_eq!(
        result.alias_target.unwrap().to_string(),
        "alias.example.:443"
    );
    lookup.resolver.answers.insert(
        Domain::from_static("alias.example"),
        vec![Err("resolver failure")],
    );
    let result = lookup.lookup(&authority(), &protocols(), false).await;
    assert!(result.failure.is_some());
    assert_eq!(
        result.alias_target.unwrap().to_string(),
        "alias.example.:443"
    );
}

#[tokio::test]
async fn loops_and_depth_exhaustion_return_to_origin_without_alias_fallback() {
    let (lookup, calls) = setup(&[
        (
            "origin.example",
            vec![record("origin.example", 0, "alias.example", &[])],
        ),
        (
            "alias.example",
            vec![record("alias.example", 0, "origin.example", &[])],
        ),
    ]);
    let result = lookup.lookup(&authority(), &protocols(), false).await;
    assert!(result.failure.is_none());
    assert!(result.alias_target.is_none());
    assert_eq!(calls.lock().len(), 2);
    let result = lookup
        .with_max_aliases(NonZeroUsize::new(1).unwrap())
        .lookup(&authority(), &protocols(), false)
        .await;
    assert!(result.failure.is_none());
    assert!(result.alias_target.is_none());
}

#[tokio::test]
async fn protocol_intersection_priority_mandatory_and_default_alpn() {
    let (lookup, _) = setup(&[(
        "origin.example",
        vec![
            record("origin.example", 3, "third.example", &[(1, b"\x02h3")]),
            record(
                "origin.example",
                1,
                "first.example",
                &[(1, b"\x02h2"), (2, b"")],
            ),
            record(
                "origin.example",
                2,
                "ignored.example",
                &[(0, &[0, 100]), (100, b"opaque")],
            ),
            record(
                "origin.example",
                4,
                "unknown.example",
                &[(1, b"\x07unknown"), (2, b"")],
            ),
        ],
    )]);
    let result = lookup.lookup(&authority(), &protocols(), false).await;
    assert_eq!(result.bindings.len(), 2);
    assert_eq!(result.bindings[0].target.to_string(), "first.example.:443");
    assert_eq!(result.bindings[0].protocols, [ApplicationProtocol::HTTP_2]);
    assert_eq!(
        result.bindings[1].protocols,
        [ApplicationProtocol::HTTP_3, ApplicationProtocol::HTTP_11]
    );
}

#[tokio::test]
async fn ech_reliance_requires_capability_and_all_compatible_endpoints() {
    let ech = [0, 4, 0xfe, 0x0d, 0, 0];
    let (mut lookup, _) = setup(&[(
        "origin.example",
        vec![record("origin.example", 1, ".", &[(5, &ech)])],
    )]);
    assert!(
        !lookup
            .lookup(&authority(), &protocols(), false)
            .await
            .ech_reliant
    );
    assert!(
        lookup
            .lookup(&authority(), &protocols(), true)
            .await
            .ech_reliant
    );
    lookup
        .resolver
        .answers
        .get_mut(&Domain::from_static("origin.example"))
        .unwrap()
        .push(Ok(record("origin.example", 2, "other.example", &[])));
    assert!(
        !lookup
            .lookup(&authority(), &protocols(), true)
            .await
            .ech_reliant
    );
    let (lookup, _) = setup(&[(
        "origin.example",
        vec![record("origin.example", 1, ".", &[(0, &[0, 5]), (5, &ech)])],
    )]);
    assert!(
        lookup
            .lookup(&authority(), &protocols(), false)
            .await
            .bindings
            .is_empty()
    );
    assert!(
        lookup
            .lookup(&authority(), &protocols(), true)
            .await
            .ech_reliant
    );
}

#[tokio::test]
async fn oversized_or_late_malformed_answers_never_expose_partial_records() {
    let binding = record("origin.example", 1, ".", &[]);
    let (mut lookup, _) = setup(&[("origin.example", vec![binding.clone(), binding.clone()])]);
    lookup.set_max_records(NonZeroUsize::new(1).unwrap());
    let result = lookup.lookup(&authority(), &protocols(), true).await;
    assert!(result.failure.is_some());
    assert!(result.bindings.is_empty());
    lookup.resolver.answers.insert(
        Domain::from_static("origin.example"),
        vec![Ok(binding), Err("malformed RR")],
    );
    let result = lookup.lookup(&authority(), &protocols(), true).await;
    assert!(result.failure.is_some());
    assert!(result.bindings.is_empty());
    assert!(!result.ech_reliant);
}

#[tokio::test]
async fn unavailable_alias_and_unusable_service_targets_are_not_candidates() {
    let (lookup, calls) = setup(&[(
        "origin.example",
        vec![record("origin.example", 0, ".", &[])],
    )]);
    let result = lookup.lookup(&authority(), &protocols(), true).await;
    assert!(result.bindings.is_empty());
    assert!(result.alias_target.is_none());
    assert_eq!(calls.lock().len(), 1);
    let (lookup, _) = setup(&[(
        "origin.example",
        vec![
            record("origin.example", 1, ".", &[(3, &[0, 0])]),
            record("origin.example", 1, "bad\\032name.example", &[]),
        ],
    )]);
    let result = lookup.lookup(&authority(), &protocols(), true).await;
    assert!(result.bindings.is_empty());
    assert!(!result.ech_reliant);
}

#[tokio::test]
async fn protocol_preferences_are_deduplicated_and_hints_retained() {
    let (lookup, _) = setup(&[(
        "origin.example",
        vec![record(
            "origin.example",
            1,
            ".",
            &[(1, b"\x02h3\x02h2"), (4, &[192, 0, 2, 1])],
        )],
    )]);
    let result = lookup
        .lookup(
            &authority(),
            &[
                ApplicationProtocol::HTTP_2,
                ApplicationProtocol::HTTP_3,
                ApplicationProtocol::HTTP_2,
            ],
            false,
        )
        .await;
    assert_eq!(
        result.bindings[0].protocols,
        [ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_3]
    );
    assert_eq!(
        result.bindings[0].record.binding.ipv4_hints().unwrap(),
        &[std::net::Ipv4Addr::new(192, 0, 2, 1)]
    );
}

#[tokio::test]
async fn equal_priority_and_alias_selection_use_the_supplied_shuffle() {
    use rand::{SeedableRng, rngs::StdRng};
    let (lookup, _) = setup(&[(
        "origin.example",
        vec![
            record("origin.example", 2, "last.example", &[]),
            record("origin.example", 1, "a.example", &[]),
            record("origin.example", 1, "b.example", &[]),
        ],
    )]);
    let mut firsts = std::collections::BTreeSet::new();
    for seed in 0..8 {
        let mut rng = StdRng::seed_from_u64(seed);
        let result = lookup
            .lookup_with_shuffle(&authority(), &protocols(), false, |records| {
                records.shuffle(&mut rng)
            })
            .await;
        firsts.insert(result.bindings[0].target.to_string());
        assert_eq!(result.bindings[2].record.binding.priority(), 2);
    }
    assert_eq!(firsts.len(), 2);
    let (lookup, _) = setup(&[(
        "origin.example",
        vec![
            record("origin.example", 0, "a.example", &[]),
            record("origin.example", 0, "b.example", &[]),
        ],
    )]);
    let mut aliases = std::collections::BTreeSet::new();
    for seed in 0..8 {
        let mut rng = StdRng::seed_from_u64(seed);
        let result = lookup
            .lookup_with_shuffle(&authority(), &protocols(), false, |records| {
                records.shuffle(&mut rng)
            })
            .await;
        aliases.insert(result.alias_target.unwrap().to_string());
    }
    assert_eq!(aliases.len(), 2);
}

#[tokio::test]
async fn root_alias_after_a_hop_is_unavailable_and_attrleaf_owner_is_literal() {
    let (lookup, _) = setup(&[
        (
            "origin.example",
            vec![record("origin.example", 0, "alias.example", &[])],
        ),
        ("alias.example", vec![record("alias.example", 0, ".", &[])]),
        (
            "_8443._https.simple.example",
            vec![record(
                "_8443._https.simple.example",
                1,
                ".",
                &[(1, b"\x02h3")],
            )],
        ),
    ]);
    let result = lookup.lookup(&authority(), &protocols(), false).await;
    assert!(result.bindings().is_empty());
    assert!(result.alias_target().is_none());
    assert!(result.failure().is_none());
    let result = lookup
        .lookup(&"simple.example:8443".parse().unwrap(), &protocols(), false)
        .await;
    assert_eq!(
        result.bindings()[0].target.to_string(),
        "_8443._https.simple.example.:8443"
    );
}

#[tokio::test]
async fn localhost_service_discovery_never_queries_dns() {
    let (lookup, calls) = setup(&[]);
    let result = lookup
        .lookup(
            &"service.localhost:8443".parse().unwrap(),
            &protocols(),
            true,
        )
        .await;
    assert!(result.bindings().is_empty());
    assert!(!result.followed_alias());
    assert!(calls.lock().is_empty());
}
