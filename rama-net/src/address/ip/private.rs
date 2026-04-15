//! Helpers for IP ranges that should bypass public-Internet interception.
//!
//! The goal here is intentionally narrower than "all IANA special-purpose
//! addresses". Some IANA special-purpose blocks contain globally reachable
//! anycast or transition addresses, so treating the entire registry as
//! passthrough would be too broad for proxying.
//!
//! References:
//! - <https://www.iana.org/assignments/iana-ipv4-special-registry/>
//! - <https://www.iana.org/assignments/iana-ipv6-special-registry/>

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Returns `true` when the address belongs to a range that should be treated as
/// private instead of a normal public-Internet destination.
#[inline]
#[must_use]
pub fn is_private_ip(addr: impl Into<IpAddr>) -> bool {
    match addr.into() {
        IpAddr::V4(addr) => is_private_ipv4(addr),
        IpAddr::V6(addr) => is_private_ipv6(addr),
    }
}

/// Returns `true` for IPv4 ranges that are not meant to be treated as ordinary
/// public-Internet destinations.
#[inline]
#[must_use]
pub fn is_private_ipv4(addr: Ipv4Addr) -> bool {
    let val = u32::from(addr);

    addr.is_loopback()      // 127.0.0.0/8
        || addr.is_private()   // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        || addr.is_link_local() // 169.254.0.0/16
        || addr.is_multicast()  // 224.0.0.0/4
        || addr.is_broadcast()  // 255.255.255.255
        || addr.is_documentation()
        || is_ipv4_this_network(val)
        || is_ipv4_shared(val)
        || is_ipv4_protocol_assignments(val)
        || is_ipv4_benchmarking(val)
        || is_ipv4_reserved(val)
}

/// Returns `true` for IPv6 ranges that are not meant to be treated as ordinary
/// public-Internet destinations.
#[inline]
#[must_use]
pub fn is_private_ipv6(addr: Ipv6Addr) -> bool {
    let val = u128::from(addr);

    addr.is_loopback()
        || addr.is_multicast()
        || addr.is_unicast_link_local()
        || addr.is_unique_local()
        || addr.is_unspecified()
        || is_ipv6_site_local(val)
        || is_ipv6_documentation(val)
        || is_ipv6_benchmarking(val)
        || is_ipv6_discard_only(val)
        || is_ipv6_dummy_prefix(val)
        || is_ipv6_local_use_translation(val)
}

// --- IPv4 Helpers ---

#[inline(always)]
fn is_ipv4_this_network(val: u32) -> bool {
    // RFC 791 / IANA "This network": 0.0.0.0/8.
    val & 0xFF00_0000 == 0x0000_0000
}

#[inline(always)]
fn is_ipv4_shared(val: u32) -> bool {
    // RFC 6598 shared address space: 100.64.0.0/10.
    val & 0xFFC0_0000 == 0x6440_0000
}

#[inline(always)]
fn is_ipv4_protocol_assignments(val: u32) -> bool {
    // Conservatively cover only the clearly non-global allocations under
    // 192.0.0.0/24, leaving out the globally reachable anycast addresses
    // 192.0.0.9/32 and 192.0.0.10/32.
    if val & 0xFFFF_FF00 == 0xC000_0000 {
        let d = (val & 0xFF) as u8;
        // Exclude globally reachable .9 (PCP Anycast) and .10 (TURN Anycast)
        return (0..=8).contains(&d) || d == 170 || d == 171;
    }
    false
}

#[inline(always)]
fn is_ipv4_benchmarking(val: u32) -> bool {
    // RFC 2544 benchmarking: 198.18.0.0/15.
    val & 0xFFFE_0000 == 0xC612_0000
}

#[inline(always)]
fn is_ipv4_reserved(val: u32) -> bool {
    // IANA reserved/future-use block: 240.0.0.0/4.
    val & 0xF000_0000 == 0xF000_0000
}

// --- IPv6 Helpers ---

#[inline(always)]
fn is_ipv6_site_local(val: u128) -> bool {
    // fec0::/10 (Deprecated, but non-global)
    (val >> 118) == 0x03fb
}

#[inline(always)]
fn is_ipv6_documentation(val: u128) -> bool {
    // 2001:db8::/32 (RFC 3849) or 3fff::/20 (RFC 9637)
    (val >> 96 == 0x2001_0db8) || (val >> 108 == 0x3fff0)
}

#[inline(always)]
fn is_ipv6_benchmarking(val: u128) -> bool {
    // RFC 5180 benchmarking: 2001:2::/48.
    (val >> 80) == 0x2001_0002_0000
}

#[inline(always)]
fn is_ipv6_discard_only(val: u128) -> bool {
    // RFC 6666 discard-only prefix: 100::/64.
    (val >> 64) == 0x0100_0000_0000_0000
}

#[inline(always)]
fn is_ipv6_dummy_prefix(val: u128) -> bool {
    // RFC 9780 dummy prefix: 100:0:0:1::/64.
    (val >> 64) == 0x0100_0000_0000_0001
}

#[inline(always)]
fn is_ipv6_local_use_translation(val: u128) -> bool {
    // RFC 8215 local-use translation prefix: 64:ff9b:1::/48.
    (val >> 80) == 0x0064_ff9b_0001
}

#[cfg(test)]
mod tests {
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{is_private_ip, is_private_ipv4, is_private_ipv6};

    #[test]
    fn passthrough_ipv4_includes_non_public_ranges() {
        let cases = [
            // loopback
            (Ipv4Addr::new(127, 0, 0, 1), true),
            // RFC-1918 private
            (Ipv4Addr::new(10, 0, 0, 1), true),
            (Ipv4Addr::new(172, 16, 0, 1), true),
            (Ipv4Addr::new(192, 168, 1, 1), true),
            // RFC 791 this-network space
            (Ipv4Addr::new(0, 1, 2, 3), true),
            // RFC 6598 shared address space
            (Ipv4Addr::new(100, 64, 0, 1), true),
            (Ipv4Addr::new(100, 100, 12, 34), true),
            (Ipv4Addr::new(100, 127, 255, 254), true),
            // special protocol assignment sub-ranges that are not globally reachable
            (Ipv4Addr::new(192, 0, 0, 3), true),
            (Ipv4Addr::new(192, 0, 0, 8), true),
            (Ipv4Addr::new(192, 0, 0, 170), true),
            (Ipv4Addr::new(192, 0, 0, 171), true),
            // benchmarking
            (Ipv4Addr::new(198, 18, 0, 1), true),
            (Ipv4Addr::new(198, 19, 255, 254), true),
            // multicast
            (Ipv4Addr::new(224, 0, 0, 1), true),
            // reserved/future use
            (Ipv4Addr::new(250, 10, 20, 30), true),
            // just outside non-public ranges
            (Ipv4Addr::new(100, 63, 255, 255), false),
            (Ipv4Addr::new(100, 128, 0, 1), false),
            (Ipv4Addr::new(192, 0, 0, 9), false),
            (Ipv4Addr::new(192, 0, 0, 10), false),
            (Ipv4Addr::new(198, 17, 255, 255), false),
            (Ipv4Addr::new(198, 20, 0, 0), false),
            // public internet
            (Ipv4Addr::new(8, 8, 8, 8), false),
            (Ipv4Addr::new(1, 1, 1, 1), false),
            // explicit anycast/global
            (Ipv4Addr::new(192, 88, 99, 1), false), // 6to4 Relay Anycast (RFC 3068)
            (Ipv4Addr::new(192, 31, 196, 1), false), // AS112-v4 Anycast (RFC 7535)
            (Ipv4Addr::new(198, 51, 100, 1), true), // TEST-NET-2 (Globally unreachable, but documentation)
            (Ipv4Addr::new(192, 52, 193, 1), false), // AMT Anycast (RFC 7450)
        ];

        for (addr, expected) in cases {
            assert_eq!(is_private_ipv4(addr), expected, "addr: {addr}");
        }
    }

    #[test]
    fn passthrough_ipv4_boundary_cases_are_correct() {
        let cases = [
            (Ipv4Addr::new(0, 0, 0, 0), true),
            (Ipv4Addr::new(0, 255, 255, 255), true),
            (Ipv4Addr::new(100, 64, 0, 0), true),
            (Ipv4Addr::new(100, 127, 255, 255), true),
            (Ipv4Addr::new(100, 63, 255, 255), false),
            (Ipv4Addr::new(100, 128, 0, 0), false),
            (Ipv4Addr::new(192, 0, 0, 0), true),
            (Ipv4Addr::new(192, 0, 0, 8), true),
            (Ipv4Addr::new(192, 0, 0, 9), false),
            (Ipv4Addr::new(192, 0, 0, 10), false),
            (Ipv4Addr::new(192, 0, 0, 11), false),
            (Ipv4Addr::new(192, 0, 0, 170), true),
            (Ipv4Addr::new(192, 0, 0, 171), true),
            (Ipv4Addr::new(192, 0, 0, 172), false),
            (Ipv4Addr::new(198, 18, 0, 0), true),
            (Ipv4Addr::new(198, 19, 255, 255), true),
            (Ipv4Addr::new(198, 17, 255, 255), false),
            (Ipv4Addr::new(198, 20, 0, 0), false),
            (Ipv4Addr::new(223, 255, 255, 255), false),
            (Ipv4Addr::new(224, 0, 0, 0), true),
            (Ipv4Addr::new(239, 255, 255, 255), true),
            (Ipv4Addr::new(240, 0, 0, 0), true),
            (Ipv4Addr::new(255, 255, 255, 254), true),
            (Ipv4Addr::new(255, 255, 255, 255), true),
            (Ipv4Addr::new(172, 15, 255, 255), false),
            (Ipv4Addr::new(172, 16, 0, 0), true),
            (Ipv4Addr::new(172, 31, 255, 255), true),
            (Ipv4Addr::new(172, 32, 0, 0), false),
        ];

        for (addr, expected) in cases {
            assert_eq!(is_private_ipv4(addr), expected, "addr: {addr}");
        }
    }

    #[test]
    fn passthrough_ipv6_includes_non_public_ranges() {
        let cases = [
            (Ipv6Addr::LOCALHOST, true),
            (Ipv6Addr::UNSPECIFIED, true),
            ("fc00::1".parse().unwrap(), true),
            ("fe80::1".parse().unwrap(), true),
            ("ff02::1".parse().unwrap(), true),
            ("fec0::1".parse().unwrap(), true),
            ("2001:db8::1".parse().unwrap(), true),
            ("3fff::1".parse().unwrap(), true),
            ("2001:2::1".parse().unwrap(), true),
            ("100::1".parse().unwrap(), true),
            ("100:0:0:1::1".parse().unwrap(), true),
            ("64:ff9b:1::1".parse().unwrap(), true),
            ("64:ff9b::1".parse().unwrap(), false), // Generic NAT64 (Global)
            ("64:ff9b::808:808".parse().unwrap(), false),
            ("2001:4860:4860::8888".parse().unwrap(), false),
            ("2606:4700:4700::1111".parse().unwrap(), false),
            ("2001:0::1".parse().unwrap(), false),  // Teredo
            ("2001:20::1".parse().unwrap(), false), // ORCHIDv2
        ];

        for (addr, expected) in cases {
            assert_eq!(is_private_ipv6(addr), expected, "addr: {addr}");
        }
    }

    #[test]
    fn passthrough_ipv6_boundary_cases_are_correct() {
        let cases = [
            ("febf:ffff:ffff:ffff::1".parse().unwrap(), true),
            ("fec0::".parse().unwrap(), true),
            ("feff:ffff:ffff:ffff::1".parse().unwrap(), true),
            ("2001:db7:ffff::1".parse().unwrap(), false),
            ("2001:db8::".parse().unwrap(), true),
            ("2001:db8:ffff:ffff::1".parse().unwrap(), true),
            ("2001:db9::1".parse().unwrap(), false),
            ("3ffe:ffff::1".parse().unwrap(), false),
            ("3fff::".parse().unwrap(), true),
            ("3fff:0fff:ffff:ffff::1".parse().unwrap(), true),
            ("3fff:1000::1".parse().unwrap(), false),
            ("4000::1".parse().unwrap(), false),
            ("2001:2::".parse().unwrap(), true),
            ("2001:2:0:1::1".parse().unwrap(), true),
            ("2001:2:1::1".parse().unwrap(), false),
            ("100::".parse().unwrap(), true),
            ("100::ffff".parse().unwrap(), true),
            ("100:0:0:1::".parse().unwrap(), true),
            ("100:0:0:2::1".parse().unwrap(), false),
            ("64:ff9b:1::".parse().unwrap(), true),
            ("64:ff9b:1:ffff::1".parse().unwrap(), true),
            ("64:ff9b:2::1".parse().unwrap(), false),
        ];

        for (addr, expected) in cases {
            assert_eq!(is_private_ipv6(addr), expected, "addr: {addr}");
        }
    }

    #[test]
    fn passthrough_ip_dispatches_to_both_versions() {
        let cases = [
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), true),
            (IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), false),
            (IpAddr::V6("fc00::1".parse().unwrap()), true),
            (IpAddr::V6("2001:4860:4860::8888".parse().unwrap()), false),
        ];

        for (addr, expected) in cases {
            assert_eq!(is_private_ip(addr), expected, "addr: {addr}");
        }
    }

    #[test]
    fn defensive_anycast_and_transition_checks() {
        let cases = [
            // IPv4 Anycast that should NOT be passthrough
            (IpAddr::V4(Ipv4Addr::new(192, 88, 99, 1)), false), // 6to4 Anycast
            (IpAddr::V4(Ipv4Addr::new(192, 31, 196, 1)), false), // AS112 Anycast
            (IpAddr::V4(Ipv4Addr::new(192, 52, 193, 1)), false), // AMT Anycast
            // IPv6 Transition/Anycast that should NOT be passthrough
            (IpAddr::V6("2001:0::1".parse().unwrap()), false), // Teredo
            (IpAddr::V6("2001:1::1".parse().unwrap()), false), // Port Control Protocol
            (IpAddr::V6("2620:4f:8000::1".parse().unwrap()), false), // AS112-v6
            (IpAddr::V6("64:ff9b::1".parse().unwrap()), false), // Well-Known NAT64
        ];

        for (addr, expected) in cases {
            assert_eq!(is_private_ip(addr), expected, "addr: {addr}");
        }
    }

    #[test]
    fn test_trait_dispatch_consistency() {
        // Verify that passing raw arrays works as expected via Into<IpAddr>
        assert!(is_private_ip([127, 0, 0, 1]));
        assert!(!is_private_ip([8, 8, 8, 8]));
    }
}
