//! Coalescing sets, pool identity and per-connection reuse scope.

use crate::client::{
    HttpConnIdentifier,
    h3::{Http3Coalescing, coalescing::restrict_reuse},
};
use rama_core::extensions::{Extensions, ExtensionsRef as _};
use rama_http_types::{
    Version,
    conn::{HttpOrigin, HttpServiceCandidate, SelectedHttpService, TargetHttpVersion},
};
use rama_net::{
    Protocol,
    address::Host,
    client::{
        ConnectRequest, ConnectorTarget,
        pool::{ConnectionReuse, ConnectionReusePolicy, ReqToConnID as _, ReuseKey},
    },
    tls::ApplicationProtocol,
};
use rama_tls::client::{TlsServerAuthenticatedAliases, TlsServerAuthentication};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn origin(authority: &str) -> HttpOrigin {
    HttpOrigin::new(Protocol::HTTPS, authority.parse().unwrap()).unwrap()
}

fn group(authorities: &[&str]) -> Arc<Http3Coalescing> {
    Arc::new(
        Http3Coalescing::try_new(authorities.iter().map(|authority| origin(authority))).unwrap(),
    )
}

fn configured(
    authority: &str,
    target: &str,
    group: Option<Arc<Http3Coalescing>>,
) -> ConnectRequest {
    let origin = origin(authority);
    let candidate = HttpServiceCandidate::new(ApplicationProtocol::HTTP_3, target.parse().unwrap());
    let input =
        ConnectRequest::new(origin.authority().clone()).with_application_protocol(Protocol::HTTPS);
    let extensions = input.extensions();
    extensions.insert(TargetHttpVersion(Version::HTTP_3));
    extensions.insert(ConnectorTarget(candidate.target.clone()));
    extensions.insert(SelectedHttpService::new(origin, candidate));
    if let Some(group) = group {
        extensions.insert_arc(group);
    }
    input
}

#[test]
fn sets_are_bounded_distinct_https_and_order_insensitive() {
    let origins = [origin("a.example:443"), origin("b.example:443")];
    assert_eq!(
        Http3Coalescing::try_new(origins.clone()).unwrap(),
        Http3Coalescing::try_new(origins.iter().rev().cloned()).unwrap()
    );
    let _err = Http3Coalescing::try_new([]).unwrap_err();
    let _err = Http3Coalescing::try_new([origins[0].clone(), origins[0].clone()]).unwrap_err();
    let plaintext = HttpOrigin::new(Protocol::HTTP, "a.example:80".parse().unwrap()).unwrap();
    let _err = Http3Coalescing::try_new([plaintext]).unwrap_err();

    let numbered = |index: usize| origin(&format!("host{index}.example:443"));
    let full = Http3Coalescing::try_new((0..Http3Coalescing::MAX_ORIGINS).map(numbered)).unwrap();
    assert_eq!(full.iter().count(), Http3Coalescing::MAX_ORIGINS);
    let consumed = AtomicUsize::new(0);
    let oversized = (0..Http3Coalescing::MAX_ORIGINS + 2).map(|index| {
        consumed.fetch_add(1, Ordering::Relaxed);
        numbered(index)
    });
    let _err = Http3Coalescing::try_new(oversized).unwrap_err();
    assert_eq!(
        consumed.load(Ordering::Relaxed),
        Http3Coalescing::MAX_ORIGINS + 1
    );
}

#[test]
fn only_one_set_at_one_literal_endpoint_shares_a_pool_identity() {
    let set = group(&["a.example:443", "b.example:443"]);
    let id = |input: ConnectRequest| HttpConnIdentifier::new().id(&input).unwrap();
    let a = id(configured(
        "a.example:443",
        "127.0.0.1:443",
        Some(set.clone()),
    ));
    assert_eq!(
        a,
        id(configured(
            "b.example:443",
            "127.0.0.1:443",
            Some(set.clone())
        ))
    );
    assert_eq!(
        a,
        id(configured(
            "b.example:443",
            "127.0.0.1:443",
            Some(group(&["b.example:443", "a.example:443"]))
        )),
        "equal sets share connections"
    );
    for other in [
        configured("b.example:443", "127.0.0.1:443", None),
        configured("b.example:443", "127.0.0.2:443", Some(set.clone())),
        configured("c.example:443", "127.0.0.1:443", Some(set.clone())),
        configured(
            "b.example:443",
            "127.0.0.1:443",
            Some(group(&["a.example:443", "b.example:443", "c.example:443"])),
        ),
    ] {
        assert_ne!(a, id(other));
    }
    assert_ne!(
        id(configured(
            "a.example:443",
            "edge.example:443",
            Some(set.clone())
        )),
        id(configured("b.example:443", "edge.example:443", Some(set))),
        "a domain target is not known to be the same endpoint"
    );
}

fn request(authority: &str) -> Extensions {
    configured(
        authority,
        "127.0.0.1:443",
        Some(group(&["a.example:443", "b.example:443"])),
    )
    .extensions()
    .clone()
}

#[derive(Debug)]
struct Any;

impl ConnectionReusePolicy for Any {
    fn classifier(&self) -> ReuseKey {
        ReuseKey::of::<Self>()
    }

    fn connection_key(&self) -> Option<ReuseKey> {
        Some(ReuseKey::of::<Self>())
    }

    fn request_key(&self, _: &Extensions) -> Option<ReuseKey> {
        Some(ReuseKey::of::<Self>())
    }
}

fn connection(
    primary: Option<&'static str>,
    aliases: Option<(&'static str, &[&'static str])>,
) -> Extensions {
    let connection = Extensions::new();
    connection.insert(ConnectionReuse::new(Any));
    connection.insert(TlsServerAuthentication(primary.map(Host::from_static)));
    if let Some((bound, names)) = aliases {
        connection.insert(TlsServerAuthenticatedAliases::new(
            Host::from_static(bound),
            names
                .iter()
                .copied()
                .map(Host::from_static)
                .collect::<Vec<_>>(),
        ));
    }
    restrict_reuse(&request("a.example:443"), &connection);
    connection
}

fn serves(connection: &Extensions, authority: &str) -> bool {
    connection
        .get_ref::<ConnectionReuse>()
        .unwrap()
        .matches(&request(authority))
}

#[test]
fn connections_serve_only_verified_origins() {
    let verified = connection(Some("a.example"), Some(("a.example", &["b.example"])));
    assert!(serves(&verified, "a.example:443"));
    assert!(serves(&verified, "b.example:443"));

    for unverified in [
        connection(Some("a.example"), None),
        connection(Some("a.example"), Some(("a.example", &[]))),
        connection(Some("a.example"), Some(("other.example", &["b.example"]))),
    ] {
        assert!(serves(&unverified, "a.example:443"));
        assert!(!serves(&unverified, "b.example:443"));
    }
}
