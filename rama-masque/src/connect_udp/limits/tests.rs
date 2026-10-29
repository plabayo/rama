use rama_core::extensions::Extensions;
use rama_net::stream::SocketInfo;
use rama_utils::rate::Rate;

use super::*;
use crate::connect_udp::{DatagramRate, TunnelBudget, budget::Charge};

fn user(name: &str) -> PrincipalKey {
    PrincipalKey::user(&UserId::Username(name.to_owned()))
}

#[test]
fn the_total_cap_holds_until_a_lease_drops() {
    let limits = ConnectUdpLimits::new().with_max_tunnels(2);
    let first = limits.try_acquire(user("a")).unwrap();
    let _second = limits.try_acquire(user("b")).unwrap();
    assert_eq!(
        limits.try_acquire(user("c")).unwrap_err(),
        TunnelLimitReached
    );
    assert_eq!(limits.live_tunnels(), 2);
    drop(first);
    assert_eq!(limits.live_tunnels(), 1);
    limits.try_acquire(user("c")).unwrap();
}

#[test]
fn each_principal_has_its_own_cap_and_clones_share_them() {
    let limits = ConnectUdpLimits::new().with_max_tunnels_per_principal(1);
    let clone = limits.clone();
    let alice = limits.try_acquire(user("alice")).unwrap();
    assert_eq!(
        clone.try_acquire(user("alice")).unwrap_err(),
        TunnelLimitReached
    );
    let _bob = clone.try_acquire(user("bob")).unwrap();
    assert_eq!(limits.live_tunnels(), 2);
    drop(alice);
    clone.try_acquire(user("alice")).unwrap();
}

#[test]
fn a_refused_principal_gives_the_total_place_back() {
    let limits = ConnectUdpLimits::new()
        .with_max_tunnels(10)
        .with_max_tunnels_per_principal(1);
    let _held = limits.try_acquire(user("alice")).unwrap();
    for _ in 0..20 {
        limits.try_acquire(user("alice")).unwrap_err();
    }
    assert_eq!(limits.live_tunnels(), 1);
}

/// What the default keyer derives for a request with these `extensions`.
fn default_key(extensions: &Extensions) -> PrincipalKey {
    UserOrClientIpKey::new()
        .rate_key(extensions)
        .unwrap()
        .expect("the default keyer always yields a key")
}

/// Extensions of a request from `peer`.
fn from_peer(peer: &str) -> Extensions {
    let extensions = Extensions::new();
    extensions.insert(SocketInfo::new(None, peer.parse().unwrap()));
    extensions
}

#[test]
fn the_default_keyer_takes_the_user_then_the_client_ip() {
    assert_eq!(default_key(&Extensions::new()), PrincipalKey::ANONYMOUS);
    // One IPv6 /64 is one principal; a v4-mapped client is its IPv4 address.
    assert_eq!(
        default_key(&from_peer("[2001:db8:1:2::1]:1")),
        default_key(&from_peer("[2001:db8:1:2:ffff::9]:1")),
    );
    assert_ne!(
        default_key(&from_peer("[2001:db8:1:2::1]:1")),
        default_key(&from_peer("[2001:db8:1:3::1]:1")),
    );
    assert_eq!(
        default_key(&from_peer("[::ffff:192.0.2.1]:1")),
        PrincipalKey::ip("192.0.2.1".parse().unwrap()),
    );
    let extensions = from_peer("192.0.2.1:5000");
    extensions.insert(UserId::Anonymous);
    assert_eq!(
        default_key(&extensions),
        PrincipalKey::ip("192.0.2.1".parse().unwrap())
    );
    extensions.insert(UserId::Token(b"bearer-secret".to_vec()));
    let token = default_key(&extensions);
    assert_eq!(
        token,
        PrincipalKey::user(&UserId::Token(b"bearer-secret".to_vec()))
    );
    extensions.insert(UserId::Username("alice-secret".to_owned()));
    let name = default_key(&extensions);
    assert_eq!(name, user("alice-secret"));
    for key in [token, name] {
        let debug = format!("{key:?}");
        assert!(!debug.contains("secret"), "{debug}");
    }
}

#[test]
fn the_ipv6_aggregation_of_the_default_keyer_is_configurable() {
    let exact =
        UserOrClientIpKey::new().with_client_ip(ClientIpRateKey::new().with_ipv6_prefix(128));
    let key = |peer| exact.rate_key(&from_peer(peer)).unwrap().unwrap();
    assert_ne!(key("[2001:db8:1:2::1]:1"), key("[2001:db8:1:2::2]:1"));
}

#[test]
fn any_keyer_keys_principals() {
    // IP only: two users from one address share a principal.
    let limits = ConnectUdpLimits::new()
        .with_max_tunnels_per_principal(1)
        .with_keyer(ClientIpRateKey::new());
    let alice = limits.try_acquire("192.0.2.1".parse().unwrap()).unwrap();
    limits
        .try_acquire("192.0.2.1".parse().unwrap())
        .unwrap_err();
    drop(alice);
    // A keyer of its own, with its own key type.
    let tenants = ConnectUdpLimits::new()
        .with_max_tunnels_per_principal(1)
        .with_keyer(|_: &Request| Ok::<_, BoxError>(Some(7u64)));
    let _held = tenants.try_acquire(7).unwrap();
    tenants.try_acquire(7).unwrap_err();
    tenants.try_acquire(8).unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_full_map_refuses_new_principals_until_one_is_idle() {
    let limits = ConnectUdpLimits::new()
        .with_max_tunnels_per_principal(4)
        .with_max_principals(1)
        .with_principal_idle_timeout(Duration::from_secs(10));
    let alice = limits.try_acquire(user("alice")).unwrap();
    assert_eq!(
        limits.try_acquire(user("bob")).unwrap_err(),
        TunnelLimitReached
    );

    // A principal with a tunnel is never dropped, however long it is held.
    tokio::time::advance(Duration::from_secs(60)).await;
    assert_eq!(
        limits.try_acquire(user("bob")).unwrap_err(),
        TunnelLimitReached
    );

    // Without tunnels it stays tracked for the idle timeout from its last tunnel.
    drop(alice);
    tokio::time::advance(Duration::from_secs(9)).await;
    assert_eq!(
        limits.try_acquire(user("bob")).unwrap_err(),
        TunnelLimitReached
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    let _bob = limits.try_acquire(user("bob")).unwrap();
    assert_eq!(limits.tracked_principals(), 1);
}

#[test]
fn principals_are_not_tracked_without_per_principal_limits() {
    let limits = ConnectUdpLimits::new().with_max_tunnels(8);
    let _leases: Vec<_> = (0..4)
        .map(|n| limits.try_acquire(user(&n.to_string())).unwrap())
        .collect();
    assert_eq!(limits.tracked_principals(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_held_principal_survives_a_zero_idle_timeout() {
    let limits = ConnectUdpLimits::new()
        .with_max_tunnels_per_principal(1)
        .with_max_principals(2)
        .with_principal_idle_timeout(Duration::ZERO);
    let _alice = limits.try_acquire(user("alice")).unwrap();
    // A new principal sweeps the map; Alice's held entry stays, and so does her cap.
    let _bob = limits.try_acquire(user("bob")).unwrap();
    assert_eq!(
        limits.try_acquire(user("alice")).unwrap_err(),
        TunnelLimitReached
    );
    assert_eq!(limits.tracked_principals(), 2);

    let full = ConnectUdpLimits::new()
        .with_max_tunnels_per_principal(1)
        .with_max_principals(1)
        .with_principal_idle_timeout(Duration::ZERO);
    let alice = full.try_acquire(user("alice")).unwrap();
    assert_eq!(
        full.try_acquire(user("bob")).unwrap_err(),
        TunnelLimitReached
    );
    // Without a lease, a zero idle timeout drops it at its next look.
    drop(alice);
    tokio::time::advance(Duration::from_millis(1)).await;
    full.try_acquire(user("bob")).unwrap();
}

#[tokio::test(start_paused = true)]
async fn the_idle_timeout_runs_from_the_last_tunnels_end() {
    let limits = ConnectUdpLimits::new()
        .with_max_tunnels_per_principal(1)
        .with_max_principals(1)
        .with_principal_idle_timeout(Duration::from_secs(10));
    let alice = limits.try_acquire(user("alice")).unwrap();
    tokio::time::advance(Duration::from_secs(9)).await;
    drop(alice);
    // Alice's first expiry is due, but she has been idle for only a second.
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(
        limits.try_acquire(user("bob")).unwrap_err(),
        TunnelLimitReached
    );
    tokio::time::advance(Duration::from_secs(8)).await;
    assert_eq!(
        limits.try_acquire(user("bob")).unwrap_err(),
        TunnelLimitReached
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    let _bob = limits.try_acquire(user("bob")).unwrap();
}

/// A burst of ten packets that takes ten seconds to refill.
fn ten_second_refill() -> PrincipalBudget {
    PrincipalBudget::new().with_to_target(
        DatagramRate::new(Rate::per_sec(1), Rate::per_sec(1_000_000)).with_packet_burst(10),
    )
}

/// Spend everything `lease`'s principal may send to targets.
fn drain_principal(lease: &TunnelLease) {
    let account = TunnelBudget::unlimited().account_for(lease.principal_spend());
    let spent = (0..1_000).any(|_| account.charge_to_target(1) != Charge::Paid);
    assert!(spent, "the principal's budget never ran out");
}

#[tokio::test(start_paused = true)]
async fn a_principal_in_debt_outlives_a_shorter_idle_timeout() {
    let limits = ConnectUdpLimits::new()
        .with_principal_budget(ten_second_refill())
        .with_max_principals(1)
        .with_principal_idle_timeout(Duration::from_secs(1));
    let alice = limits.try_acquire(user("alice")).unwrap();
    drain_principal(&alice);
    drop(alice);

    // Past the idle timeout, not yet refilled: Alice stays, and so does her debt.
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(
        limits.try_acquire(user("bob")).unwrap_err(),
        TunnelLimitReached
    );
    let again = limits.try_acquire(user("alice")).unwrap();
    let account = TunnelBudget::unlimited().account_for(again.principal_spend());
    assert_eq!(
        account.charge_to_target(1),
        Charge::Paid,
        "two seconds refilled"
    );
    assert_eq!(account.charge_to_target(1), Charge::Paid);
    assert_eq!(account.charge_to_target(1), Charge::RateLimited);
    drop(again);

    // Once her rates would be full again, Alice may be forgotten.
    tokio::time::advance(Duration::from_secs(10)).await;
    let _bob = limits.try_acquire(user("bob")).unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_principal_stays_tracked_until_its_quota_window_ends() {
    let limits = ConnectUdpLimits::new()
        .with_principal_budget(PrincipalBudget::new().with_quota(1_000, Duration::from_mins(1)))
        .with_max_principals(1)
        .with_principal_idle_timeout(Duration::from_secs(1));
    let alice = limits.try_acquire(user("alice")).unwrap();
    let account = TunnelBudget::unlimited().account_for(alice.principal_spend());
    assert_eq!(account.charge_to_target(900), Charge::Paid);
    drop(account);
    drop(alice);
    tokio::time::advance(Duration::from_secs(59)).await;
    assert_eq!(
        limits.try_acquire(user("bob")).unwrap_err(),
        TunnelLimitReached
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    let _bob = limits.try_acquire(user("bob")).unwrap();
}

#[test]
fn a_principal_budget_alone_tracks_principals() {
    let limits = ConnectUdpLimits::new().with_principal_budget(ten_second_refill());
    let lease = limits.try_acquire(user("alice")).unwrap();
    assert!(lease.principal_spend().is_some());
    assert_eq!(limits.tracked_principals(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_quota_window_no_instant_can_end_keeps_its_principal() {
    let limits = ConnectUdpLimits::new()
        .with_principal_budget(PrincipalBudget::new().with_quota(64, Duration::MAX))
        .with_max_principals(1)
        .with_principal_idle_timeout(Duration::ZERO);
    let alice = limits.try_acquire(user("alice")).unwrap();
    let account = TunnelBudget::unlimited().account_for(alice.principal_spend());
    assert_eq!(account.charge_to_target(64), Charge::Paid);
    drop(account);
    drop(alice);
    for _ in 0..3 {
        tokio::time::advance(Duration::from_secs(3600)).await;
        assert_eq!(
            limits.try_acquire(user("bob")).unwrap_err(),
            TunnelLimitReached
        );
    }
}
