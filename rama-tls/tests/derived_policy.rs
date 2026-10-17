//! A layer derives TLS settings after a pool miss; the native connector must
//! retain caller compatibility without weakening producer or proxy restrictions.

use rama_core::extensions::{Extension, Extensions};
use rama_net::{
    address::Host,
    client::{
        ConnectionPolicyScope,
        pool::{ConnectionReuse, ConnectionReusePolicy, ReuseKey},
    },
    tls::TlsAlpn,
};
use rama_tls::{
    TlsTunnel,
    client::{
        ServerVerifyMode, TlsClientConfigProvider, TlsConnectionReuse, TlsPoolId, TlsServerName,
        TlsServerVerify,
    },
};

#[derive(Debug)]
struct Provider<const ID: u8>;

#[derive(Clone, Debug, Extension)]
struct Opaque;

impl<const ID: u8> TlsClientConfigProvider for Provider<ID> {
    fn pool_id(&self, input: &Extensions) -> Option<TlsPoolId> {
        if input.contains::<Opaque>() {
            return Some(TlsPoolId::non_reusable());
        }
        TlsPoolId::builder()
            .maybe_with_alpn(input.get_ref::<TlsAlpn>())
            .maybe_with_verify(input.get_ref::<TlsServerVerify>())
            .maybe_with_server_name(input.get_ref::<TlsServerName>())
            .build()
    }

    fn pool_classifier(&self) -> ReuseKey {
        ReuseKey::of::<Self>()
    }

    fn authenticates_server(&self, input: &Extensions) -> bool {
        input
            .get_ref::<TlsServerVerify>()
            .is_none_or(|verify| verify.0 != ServerVerifyMode::Disable)
    }
}

fn caller() -> Extensions {
    let input = Extensions::new();
    input.insert(TlsServerVerify(ServerVerifyMode::Auto));
    input
}

fn derive(input: &Extensions, alpn: TlsAlpn) -> Option<()> {
    let original = TlsConnectionReuse::new(Provider::<1>, input);
    input.insert(alpn);
    input.insert(original.for_derived_settings(input)?);
    Some(())
}

fn policy(input: &Extensions) -> ConnectionReuse {
    ConnectionReuse::new(TlsConnectionReuse::new(Provider::<1>, input))
}

#[test]
fn derived_settings_admit_and_reuse_the_original_caller_policy() {
    let input = caller();
    derive(&input, TlsAlpn::http_2()).unwrap();
    let policy = policy(&input);
    assert!(policy.matches(&input), "new connection admission");
    assert!(policy.matches(&caller()), "warm pool checkout");

    let changed = caller();
    changed.insert(TlsServerVerify(ServerVerifyMode::Disable));
    assert!(!policy.matches(&changed));
    changed.insert(TlsServerVerify(ServerVerifyMode::Auto));
    changed.insert(TlsServerName(Host::from_static("other.example")));
    assert!(!policy.matches(&changed));

    let explicit = caller();
    explicit.insert(TlsAlpn::http_2());
    assert!(!policy.matches(&explicit), "explicit caller choice differs");
}

#[test]
fn stale_derived_settings_cannot_admit_even_after_restoring_original_values() {
    let input = caller();
    input.insert(TlsAlpn::http_1());
    derive(&input, TlsAlpn::http_2()).unwrap();
    let policy = policy(&input);
    input.insert(TlsServerVerify(ServerVerifyMode::Disable));
    assert!(!policy.matches(&input));
    input.insert(TlsServerVerify(ServerVerifyMode::Auto));
    input.insert(TlsAlpn::http_1());
    assert!(
        !policy.matches(&input),
        "stale scope cannot alias caller key"
    );
    assert!(!self::policy(&input).is_reusable());
}

#[test]
fn a_derived_policy_is_not_interpreted_by_another_provider() {
    let input = caller();
    derive(&input, TlsAlpn::http_2()).unwrap();
    let other = ConnectionReuse::new(TlsConnectionReuse::new(Provider::<2>, &input));
    let raw = caller();
    raw.insert(TlsAlpn::http_2());
    assert!(other.matches(&raw));
    assert!(!other.matches(&caller()));
}

#[test]
fn nested_derivations_keep_the_original_caller_identity() {
    let input = caller();
    derive(&input, TlsAlpn::http_1()).unwrap();
    derive(&input, TlsAlpn::http_2()).unwrap();
    let policy = policy(&input);
    assert!(policy.matches(&input));
    assert!(policy.matches(&caller()));
    let different = caller();
    different.insert(TlsAlpn::http_1());
    assert!(!policy.matches(&different));
}

#[test]
fn opaque_policies_and_tunnels_cannot_gain_reuse_from_derivation() {
    let input = caller();
    input.insert(Opaque);
    let original = TlsConnectionReuse::new(Provider::<1>, &input);
    let derived = caller();
    derived.insert(TlsAlpn::http_2());
    derived.insert(original.for_derived_settings(&derived).unwrap());
    assert!(
        !policy(&derived).is_reusable(),
        "opaque caller remains opaque"
    );

    let input = caller();
    let original = TlsConnectionReuse::new(Provider::<1>, &input);
    input.insert(Opaque);
    assert!(original.for_derived_settings(&input).is_none());
    assert!(!policy(&input).is_reusable());
    assert!(
        TlsConnectionReuse::tunnel(Provider::<1>, &caller())
            .for_derived_settings(&caller())
            .is_none()
    );
}

#[derive(Clone, Debug, Extension)]
struct Producer(u64);

impl ConnectionReusePolicy for Producer {
    fn classifier(&self) -> ReuseKey {
        ReuseKey::of::<Self>()
    }

    fn connection_key(&self) -> Option<ReuseKey> {
        Some(ReuseKey::from_bits::<Self>(self.0.into()))
    }

    fn request_key(&self, input: &Extensions) -> Option<ReuseKey> {
        input.get_ref::<Self>()?.connection_key()
    }
}

#[test]
fn derived_origin_policy_retains_producer_and_proxy_restrictions() {
    let input = caller();
    input.insert(Producer(3));
    derive(&input, TlsAlpn::http_2()).unwrap();
    let connection = Extensions::new();
    connection.insert(ConnectionReuse::restriction(Producer(3)));
    TlsConnectionReuse::tunnel(Provider::<1>, &input).publish(&connection);
    TlsConnectionReuse::new(Provider::<1>, &input).publish(&connection);
    let policy = connection.get_ref::<ConnectionReuse>().unwrap();
    assert!(policy.matches(&input));

    let next = caller();
    next.insert(Producer(3));
    assert!(policy.matches(&next));
    next.insert(Producer(4));
    assert!(!policy.matches(&next));
    next.insert(Producer(3));
    next.insert(TlsTunnel {
        server_identity: Some(Host::from_static("other.proxy")),
        application_protocol: None,
        alpn: None,
    });
    assert!(!policy.matches(&next));
}

#[test]
fn policy_scope_follows_the_original_caller_and_rejects_stale_derivation() {
    let input = Extensions::new();
    assert_eq!(
        TlsConnectionReuse::new(Provider::<1>, &input).policy_scope(),
        ConnectionPolicyScope::Connector
    );
    derive(&input, TlsAlpn::http_2()).unwrap();
    assert_eq!(
        TlsConnectionReuse::new(Provider::<1>, &input).policy_scope(),
        ConnectionPolicyScope::Connector
    );
    input.insert(TlsServerVerify(ServerVerifyMode::Disable));
    assert_eq!(
        TlsConnectionReuse::new(Provider::<1>, &input).policy_scope(),
        ConnectionPolicyScope::Request
    );
    assert_eq!(
        TlsConnectionReuse::tunnel(Provider::<1>, &input).policy_scope(),
        ConnectionPolicyScope::Unknown
    );
    let input = caller();
    derive(&input, TlsAlpn::http_2()).unwrap();
    assert_eq!(
        TlsConnectionReuse::new(Provider::<1>, &input).policy_scope(),
        ConnectionPolicyScope::Request
    );
}
