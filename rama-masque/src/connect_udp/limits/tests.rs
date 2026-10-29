use std::net::Ipv6Addr;

use super::*;

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

#[test]
fn principals_come_from_the_user_then_the_client_ip() {
    let extensions = Extensions::new();
    let v6 = |s: &str| SocketAddress::new(IpAddr::V6(s.parse::<Ipv6Addr>().unwrap()), 1);
    assert_eq!(
        PrincipalKey::from_request(&extensions, None),
        PrincipalKey::ANONYMOUS
    );
    // One IPv6 /64 is one principal; a v4-mapped client is its IPv4 address.
    assert_eq!(
        PrincipalKey::from_request(&extensions, Some(v6("2001:db8:1:2::1"))),
        PrincipalKey::from_request(&extensions, Some(v6("2001:db8:1:2:ffff::9"))),
    );
    assert_ne!(
        PrincipalKey::from_request(&extensions, Some(v6("2001:db8:1:2::1"))),
        PrincipalKey::from_request(&extensions, Some(v6("2001:db8:1:3::1"))),
    );
    assert_eq!(
        PrincipalKey::from_request(&extensions, Some(v6("::ffff:192.0.2.1"))),
        PrincipalKey::ip("192.0.2.1".parse().unwrap()),
    );
    let peer = Some("192.0.2.1:5000".parse().unwrap());
    extensions.insert(UserId::Anonymous);
    assert_eq!(
        PrincipalKey::from_request(&extensions, peer),
        PrincipalKey::ip("192.0.2.1".parse().unwrap())
    );
    extensions.insert(UserId::Token(b"bearer-secret".to_vec()));
    let token = PrincipalKey::from_request(&extensions, peer);
    assert_eq!(
        token,
        PrincipalKey::user(&UserId::Token(b"bearer-secret".to_vec()))
    );
    extensions.insert(UserId::Username("alice-secret".to_owned()));
    let name = PrincipalKey::from_request(&extensions, peer);
    assert_eq!(name, user("alice-secret"));
    for key in [token, name] {
        let debug = format!("{key:?}");
        assert!(!debug.contains("secret"), "{debug}");
    }
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
