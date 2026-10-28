use std::num::NonZeroU16;

use rama_net::{
    address::{Domain, ip::TranslationPrefix},
    user::UserId,
};

use super::*;

fn target(host: Host, port: u16) -> ConnectUdpTarget {
    ConnectUdpTarget::new(host, NonZeroU16::new(port).unwrap())
}

fn judge_with(
    policy: &impl ConnectUdpPolicy,
    target: &ConnectUdpTarget,
    address: &str,
    proxy: Option<&str>,
    extensions: &Extensions,
    prefixes: &[TranslationPrefix],
) -> bool {
    let address: SocketAddress = address.parse().unwrap();
    let Some((embedded, translated)) = embedded_destinations(address.ip_addr, prefixes) else {
        return false;
    };
    policy.allows(&ConnectUdpDestination {
        target,
        address,
        proxy_address: proxy.map(|proxy| proxy.parse().unwrap()),
        extensions,
        embedded: &embedded,
        translated,
    })
}

fn judge(
    policy: &impl ConnectUdpPolicy,
    target: &ConnectUdpTarget,
    address: &str,
    proxy: Option<&str>,
    extensions: &Extensions,
) -> bool {
    judge_with(policy, target, address, proxy, extensions, &[])
}

fn allows(policy: &impl ConnectUdpPolicy, address: &str, proxy: Option<&str>) -> bool {
    judge(
        policy,
        &target(Host::LOCALHOST_NAME, 1),
        address,
        proxy,
        &Extensions::new(),
    )
}

fn allows_via(policy: &impl ConnectUdpPolicy, address: &str, prefixes: &[&str]) -> bool {
    let prefixes: Vec<_> = prefixes
        .iter()
        .map(|prefix| TranslationPrefix::try_new(prefix.parse().unwrap()).unwrap())
        .collect();
    judge_with(
        policy,
        &target(Host::LOCALHOST_NAME, 1),
        address,
        None,
        &Extensions::new(),
        &prefixes,
    )
}

#[test]
fn the_default_refuses_non_global_addresses() {
    let policy = DestinationScopePolicy::default();
    for address in [
        "127.0.0.1:53",
        "10.0.0.1:53",
        "172.16.0.1:53",
        "192.168.1.1:53",
        "100.64.0.1:53",
        "169.254.169.254:53",
        "0.0.0.0:53",
        "224.0.0.251:5353",
        "255.255.255.255:53",
        "[::1]:53",
        "[::]:53",
        "[fe80::1]:53",
        "[fd00::1]:53",
        "[ff02::fb]:5353",
        "[::ffff:127.0.0.1]:53",
        "[::ffff:10.0.0.1]:53",
    ] {
        assert!(!allows(&policy, address, None), "{address}");
    }
    assert!(allows(&policy, "8.8.8.8:53", None));
    assert!(allows(&policy, "[2001:4860:4860::8888]:53", None));
}

#[test]
fn the_default_refuses_the_proxy_ip_on_every_port() {
    let policy = DestinationScopePolicy::default();
    assert!(!allows(&policy, "203.0.113.7:53", Some("203.0.113.7:443")));
    assert!(allows(&policy, "8.8.8.8:53", Some("203.0.113.7:443")));
    let policy = policy.with_deny_proxy_ip(false);
    assert!(allows(&policy, "8.8.4.4:53", Some("8.8.4.4:443")));
}

#[test]
fn allowing_private_still_refuses_the_proxy_socket() {
    let policy = DestinationScopePolicy::allow_private();
    assert!(allows(&policy, "127.0.0.1:53", Some("127.0.0.1:443")));
    assert!(allows(&policy, "[::1]:53", None));
    assert!(!allows(&policy, "127.0.0.1:443", Some("127.0.0.1:443")));
    // A dual-stack listener reports a v4-mapped local address.
    assert!(!allows(
        &policy,
        "127.0.0.1:443",
        Some("[::ffff:127.0.0.1]:443")
    ));
    // Nor through an address that carries it.
    assert!(!allows(
        &policy,
        "[64:ff9b::7f00:1]:443",
        Some("127.0.0.1:443")
    ));
}

#[test]
fn embedded_ipv4_is_judged_like_the_address_it_carries() {
    let policy = DestinationScopePolicy::default();
    for address in [
        "[64:ff9b::a00:1]:53",
        "[64:ff9b::7f00:1]:53",
        "[64:ff9b::a9fe:a9fe]:53",
        "[::127.0.0.1]:53",
        "[::10.0.0.1]:53",
        "[2002:c0a8:101::1]:53",
        "[2002:7f00:1::1]:53",
        // Teredo: private server, then a client mapped to 10.0.0.1 (obfuscated f5ff:fffe).
        "[2001:0:a00:1:8000:63bf:3fff:fdd2]:53",
        "[2001:0:4136:e378:8000:63bf:f5ff:fffe]:53",
    ] {
        assert!(!allows(&policy, address, None), "{address}");
    }
    for address in [
        "[64:ff9b::808:808]:53",
        "[::8.8.8.8]:53",
        "[2002:808:808::1]:53",
        "[2001:0:4136:e378:8000:63bf:f7f7:f7f7]:53",
    ] {
        assert!(allows(&policy, address, None), "{address}");
    }
    // The proxy's own IP is refused through an embedding too.
    assert!(!allows(
        &policy,
        "[64:ff9b::808:808]:53",
        Some("8.8.8.8:443")
    ));
    assert!(allows(
        &DestinationScopePolicy::allow_private(),
        "[64:ff9b::a00:1]:53",
        None
    ));
}

#[test]
fn configured_translation_prefixes_judge_the_ipv4_behind_them() {
    let policy = DestinationScopePolicy::default();
    let local_use = "[64:ff9b:1::808:808]:53";
    assert!(!allows(&policy, local_use, None), "local-use is non-global");
    assert!(allows_via(&policy, local_use, &["64:ff9b:1::/96"]));
    assert!(!allows_via(
        &policy,
        "[64:ff9b:1::a00:1]:53",
        &["64:ff9b:1::/96"]
    ));

    // A /48 prefix places the IPv4 address around the reserved octet (RFC 6052 §2.2).
    let prefix = ["2001:db8:122::/48"];
    assert!(allows_via(
        &policy,
        "[2001:db8:122:808:8:800::]:53",
        &prefix
    ));
    assert!(!allows_via(
        &policy,
        "[2001:db8:122:a00:0:100::]:53",
        &prefix
    ));
    // Reserved bits set: no IPv4 address, refused even by an open policy.
    let open = DestinationScopePolicy::allow_private();
    assert!(!allows_via(
        &open,
        "[2001:db8:122:808:108:800::]:53",
        &prefix
    ));

    // The proxy's own address inside a configured prefix stays refused: its socket always,
    // its other ports under the default policy.
    let prefixes =
        [TranslationPrefix::try_new("2001:4860:1234:5678::/96".parse().unwrap()).unwrap()];
    let inside = "[2001:4860:1234:5678::808:808]:443";
    let judge_proxy = |policy: &DestinationScopePolicy, proxy: &str| {
        judge_with(
            policy,
            &target(Host::LOCALHOST_NAME, 443),
            inside,
            Some(proxy),
            &Extensions::new(),
            &prefixes,
        )
    };
    assert!(!judge_proxy(
        &DestinationScopePolicy::allow_private(),
        inside
    ));
    assert!(!judge_proxy(&policy, "[2001:4860:1234:5678::808:808]:8443"));
    assert!(judge_proxy(&policy, "[2001:4860:1234:5678::1]:443"));

    // Overlapping prefixes: every interpretation is judged, whatever the order.
    for prefixes in [
        ["64:ff9b:1::/48", "64:ff9b:1::/96"],
        ["64:ff9b:1::/96", "64:ff9b:1::/48"],
    ] {
        // /96 reads 8.8.8.8; /48 reads 0.0.0.0 from the same address.
        assert!(!allows_via(&policy, local_use, &prefixes), "{prefixes:?}");
    }
}

#[test]
fn closures_are_policies() {
    let policy = |destination: &ConnectUdpDestination<'_>| destination.address.port == 53;
    assert!(allows(&policy, "127.0.0.1:53", None));
    assert!(!allows(&policy, "127.0.0.1:54", None));
}

#[test]
fn tuples_need_every_member_to_allow() {
    let port_53 = |destination: &ConnectUdpDestination<'_>| destination.address.port == 53;
    let policy = (DestinationScopePolicy::new(), port_53);
    assert!(allows(&policy, "8.8.8.8:53", None));
    assert!(!allows(&policy, "8.8.8.8:54", None));
    assert!(!allows(&policy, "10.0.0.1:53", None));
}

#[test]
fn policies_see_the_request_extensions() {
    let only_john = |destination: &ConnectUdpDestination<'_>| {
        destination
            .extensions
            .get_ref::<UserId>()
            .is_some_and(|user| user == "john")
    };
    let target = target(Host::LOCALHOST_NAME, 53);
    let extensions = Extensions::new();
    assert!(!judge(&only_john, &target, "8.8.8.8:53", None, &extensions));
    extensions.insert(UserId::Username("john".to_owned()));
    assert!(judge(&only_john, &target, "8.8.8.8:53", None, &extensions));
}

#[test]
fn the_first_matching_rule_decides() {
    let rules = ConnectUdpRules::new(ConnectUdpAction::Deny)
        .with_rule(
            ConnectUdpRule::deny()
                .with_network("8.8.4.0/24".parse().unwrap())
                .with_ports(53..=53),
        )
        .with_rule(ConnectUdpRule::allow().with_network("8.8.0.0/16".parse().unwrap()))
        .with_rule(ConnectUdpRule::allow().with_ports(443..=443));
    assert!(!allows(&rules, "8.8.4.4:53", None));
    assert!(allows(&rules, "8.8.4.4:54", None));
    assert!(allows(&rules, "8.8.8.8:53", None));
    assert!(allows(&rules, "1.1.1.1:443", None));
    assert!(!allows(&rules, "1.1.1.1:53", None), "the default");

    let open = ConnectUdpRules::new(ConnectUdpAction::Allow)
        .with_rule(ConnectUdpRule::deny().with_ports(0..=1023));
    assert!(allows(&open, "1.1.1.1:3478", None));
    assert!(!allows(&open, "1.1.1.1:123", None));
}

#[test]
fn rules_judge_every_address_a_destination_carries() {
    let deny_one = ConnectUdpRules::new(ConnectUdpAction::Allow)
        .with_rule(ConnectUdpRule::deny().with_network("8.8.8.8/32".parse().unwrap()));
    let policy = (DestinationScopePolicy::new(), deny_one);
    assert!(!allows(&policy, "8.8.8.8:53", None));
    for alias in [
        "[64:ff9b::808:808]:53",
        "[::8.8.8.8]:53",
        "[2002:808:808::1]:53",
        "[2001:0:4136:e378:8000:63bf:f7f7:f7f7]:53",
    ] {
        assert!(!allows(&policy, alias, None), "{alias}");
    }
    assert!(!allows_via(
        &policy,
        "[64:ff9b:1::808:808]:53",
        &["64:ff9b:1::/96"]
    ));
    assert!(allows(&policy, "[64:ff9b::808:404]:53", None));

    // Allowing a translated destination takes both the prefix and the IPv4 network.
    let only = |networks: &[&str]| {
        networks.iter().fold(
            ConnectUdpRules::new(ConnectUdpAction::Deny),
            |rules, net| {
                rules.with_rule(ConnectUdpRule::allow().with_network(net.parse().unwrap()))
            },
        )
    };
    assert!(!allows(
        &only(&["8.8.8.0/24"]),
        "[64:ff9b::808:808]:53",
        None
    ));
    assert!(!allows(
        &only(&["64:ff9b::/96"]),
        "[64:ff9b::808:808]:53",
        None
    ));
    assert!(allows(
        &only(&["64:ff9b::/96", "8.8.8.0/24"]),
        "[64:ff9b::808:808]:53",
        None
    ));
}

#[test]
fn name_rules_match_requested_names_only() {
    let rules = ConnectUdpRules::new(ConnectUdpAction::Deny).with_rule(
        ConnectUdpRule::allow().with_names(
            DomainTrie::new()
                .with_insert_domain("*.example.com", ())
                .with_insert_domain("exact.example.org", ()),
        ),
    );
    let extensions = Extensions::new();
    let by_name = |name: &'static str| target(Host::Name(Domain::from_static(name)), 443);
    for (target, allowed) in [
        (by_name("example.com"), true),
        (by_name("quic.example.com"), true),
        (by_name("example.org"), false),
        (by_name("badexample.com"), false),
        (by_name("exact.example.org"), true),
        (by_name("sub.exact.example.org"), false),
        (
            target(Host::Address("8.8.8.8".parse().unwrap()), 443),
            false,
        ),
    ] {
        assert_eq!(
            judge(&rules, &target, "8.8.8.8:443", None, &extensions),
            allowed,
            "{target:?}"
        );
    }
}
