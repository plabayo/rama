//! Classify IP addresses into special-use [`IpScopes`] and enumerate the CIDR
//! ranges that make up a scope.
//!
//! [`super::private::is_private_ip`] collapses every non-global range into a
//! single bool. [`ip_scope`] keeps the categories apart, so callers can compose
//! them with ordinary set algebra — the "a / b / a+b" question:
//!
//! ```
//! use rama_net::address::ip::scope::{ip_scope, IpScopes};
//!
//! let ip = [127, 0, 0, 1];
//! // loopback only
//! assert_eq!(ip_scope(ip), IpScopes::LOOPBACK);
//! // "private but not loopback" — PRIVATE and LOOPBACK are distinct bits
//! assert!(!ip_scope(ip).contains(IpScopes::PRIVATE));
//! // "private OR loopback"
//! assert!(ip_scope(ip).intersects(IpScopes::PRIVATE | IpScopes::LOOPBACK));
//! ```
//!
//! References:
//! - <https://www.iana.org/assignments/iana-ipv4-special-registry/>
//! - <https://www.iana.org/assignments/iana-ipv6-special-registry/>

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::ipnet::{IpNet, Ipv4Net, Ipv6Net};
use super::private::{
    is_ipv4_benchmarking, is_ipv4_protocol_assignments, is_ipv4_reserved, is_ipv4_shared,
    is_ipv4_this_network, is_ipv6_benchmarking, is_ipv6_discard_only, is_ipv6_documentation,
    is_ipv6_dummy_prefix, is_ipv6_local_use_translation, is_ipv6_site_local,
};

bitflags::bitflags! {
    /// Special-use scope an IP address belongs to.
    ///
    /// [`ip_scope`] returns exactly one bit per address (the most specific
    /// category, or [`IpScopes::GLOBAL`] for an ordinary public address). The
    /// bits are meant to be combined into masks — see [`IpScopes::LOCAL`] and
    /// [`IpScopes::NON_GLOBAL`] — so a caller can ask "is this in *any* of these
    /// scopes?" with [`IpScopes::intersects`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct IpScopes: u16 {
        /// Loopback: `127.0.0.0/8`, `::1`.
        const LOOPBACK = 1 << 0;
        /// RFC 1918 private (`10/8`, `172.16/12`, `192.168/16`) and IPv6
        /// unique-local (`fc00::/7`).
        const PRIVATE = 1 << 1;
        /// Link-local: `169.254.0.0/16`, `fe80::/10`.
        const LINK_LOCAL = 1 << 2;
        /// RFC 6598 shared / CGNAT address space: `100.64.0.0/10`.
        const SHARED = 1 << 3;
        /// Unspecified / "this network": `0.0.0.0/8`, `::`.
        const UNSPECIFIED = 1 << 4;
        /// Multicast: `224.0.0.0/4`, `ff00::/8`.
        const MULTICAST = 1 << 5;
        /// Documentation ranges (e.g. `192.0.2.0/24`, `2001:db8::/32`).
        const DOCUMENTATION = 1 << 6;
        /// Benchmarking ranges (`198.18.0.0/15`, `2001:2::/48`).
        const BENCHMARKING = 1 << 7;
        /// Everything else that is non-global: reserved/future-use, broadcast,
        /// protocol-assignment sub-ranges, deprecated site-local, and the v6
        /// discard / dummy / local-use-translation prefixes.
        const RESERVED = 1 << 8;
        /// Ordinary, globally-routable public address (none of the above).
        const GLOBAL = 1 << 15;
    }
}

impl IpScopes {
    /// Every scope except [`IpScopes::GLOBAL`] — i.e. exactly the set that
    /// [`is_private_ip`](super::private::is_private_ip) treats as non-public.
    pub const NON_GLOBAL: Self = Self::all().difference(Self::GLOBAL);

    /// The local-network-ish scopes most commonly excluded from interception:
    /// loopback, RFC 1918 private, link-local and CGNAT/shared.
    pub const LOCAL: Self = Self::LOOPBACK
        .union(Self::PRIVATE)
        .union(Self::LINK_LOCAL)
        .union(Self::SHARED);
}

/// Classify `addr` into the special-use [`IpScopes`] it belongs to.
///
/// Returns a single bit; [`IpScopes::GLOBAL`] for ordinary public addresses.
#[inline]
#[must_use]
pub fn ip_scope(addr: impl Into<IpAddr>) -> IpScopes {
    match addr.into() {
        IpAddr::V4(addr) => ipv4_scope(addr),
        IpAddr::V6(addr) => ipv6_scope(addr),
    }
}

/// Classify an IPv4 address. See [`ip_scope`].
#[must_use]
pub fn ipv4_scope(addr: Ipv4Addr) -> IpScopes {
    let val = u32::from(addr);

    // Ordered most-specific first; the non-global ranges are disjoint except
    // broadcast ⊂ reserved (both land in RESERVED), so order only affects which
    // single bit is reported, never GLOBAL-vs-not.
    if addr.is_loopback() {
        IpScopes::LOOPBACK
    } else if addr.is_private() {
        IpScopes::PRIVATE
    } else if is_ipv4_shared(val) {
        IpScopes::SHARED
    } else if addr.is_link_local() {
        IpScopes::LINK_LOCAL
    } else if is_ipv4_this_network(val) {
        IpScopes::UNSPECIFIED
    } else if is_ipv4_benchmarking(val) {
        IpScopes::BENCHMARKING
    } else if addr.is_documentation() {
        IpScopes::DOCUMENTATION
    } else if addr.is_multicast() {
        IpScopes::MULTICAST
    } else if is_ipv4_protocol_assignments(val) || addr.is_broadcast() || is_ipv4_reserved(val) {
        IpScopes::RESERVED
    } else {
        IpScopes::GLOBAL
    }
}

/// Classify an IPv6 address. See [`ip_scope`].
#[must_use]
pub fn ipv6_scope(addr: Ipv6Addr) -> IpScopes {
    let val = u128::from(addr);

    if addr.is_loopback() {
        IpScopes::LOOPBACK
    } else if addr.is_unspecified() {
        IpScopes::UNSPECIFIED
    } else if addr.is_multicast() {
        IpScopes::MULTICAST
    } else if addr.is_unicast_link_local() {
        IpScopes::LINK_LOCAL
    } else if addr.is_unique_local() {
        IpScopes::PRIVATE
    } else if is_ipv6_benchmarking(val) {
        IpScopes::BENCHMARKING
    } else if is_ipv6_documentation(val) {
        IpScopes::DOCUMENTATION
    } else if is_ipv6_site_local(val)
        || is_ipv6_discard_only(val)
        || is_ipv6_dummy_prefix(val)
        || is_ipv6_local_use_translation(val)
    {
        IpScopes::RESERVED
    } else {
        IpScopes::GLOBAL
    }
}

/// The CIDR ranges that make up the given `scopes` mask, across IPv4 and IPv6.
///
/// Intended for turning a scope mask into concrete network rules (e.g. excluding
/// every local range from interception in one call). [`IpScopes::GLOBAL`] has no
/// finite CIDR list and contributes nothing. Only the well-defined,
/// rule-shaped ranges are emitted; partial/sparse sets (the v4
/// protocol-assignment carve-outs) are intentionally omitted from
/// [`IpScopes::RESERVED`] since they don't form a clean prefix.
#[must_use]
pub fn scope_cidrs(scopes: IpScopes) -> Vec<IpNet> {
    // `new_assert` is infallible for the hardcoded, statically-valid prefixes
    // below (and avoids the `unwrap`/`expect` clippy gate).
    fn v4(a: [u8; 4], prefix: u8) -> IpNet {
        IpNet::V4(Ipv4Net::new_assert(
            Ipv4Addr::new(a[0], a[1], a[2], a[3]),
            prefix,
        ))
    }
    fn v6(addr: Ipv6Addr, prefix: u8) -> IpNet {
        IpNet::V6(Ipv6Net::new_assert(addr, prefix))
    }

    let mut out = Vec::new();
    if scopes.contains(IpScopes::LOOPBACK) {
        out.push(v4([127, 0, 0, 0], 8));
        out.push(v6(Ipv6Addr::LOCALHOST, 128));
    }
    if scopes.contains(IpScopes::PRIVATE) {
        out.push(v4([10, 0, 0, 0], 8));
        out.push(v4([172, 16, 0, 0], 12));
        out.push(v4([192, 168, 0, 0], 16));
        out.push(v6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7)); // fc00::/7
    }
    if scopes.contains(IpScopes::LINK_LOCAL) {
        out.push(v4([169, 254, 0, 0], 16));
        out.push(v6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10)); // fe80::/10
    }
    if scopes.contains(IpScopes::SHARED) {
        out.push(v4([100, 64, 0, 0], 10));
    }
    if scopes.contains(IpScopes::UNSPECIFIED) {
        out.push(v4([0, 0, 0, 0], 8));
        out.push(v6(Ipv6Addr::UNSPECIFIED, 128));
    }
    if scopes.contains(IpScopes::MULTICAST) {
        out.push(v4([224, 0, 0, 0], 4));
        out.push(v6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8)); // ff00::/8
    }
    if scopes.contains(IpScopes::DOCUMENTATION) {
        out.push(v4([192, 0, 2, 0], 24));
        out.push(v4([198, 51, 100, 0], 24));
        out.push(v4([203, 0, 113, 0], 24));
        out.push(v6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32)); // 2001:db8::/32
    }
    if scopes.contains(IpScopes::BENCHMARKING) {
        out.push(v4([198, 18, 0, 0], 15));
        out.push(v6(Ipv6Addr::new(0x2001, 0x2, 0, 0, 0, 0, 0, 0), 48)); // 2001:2::/48
    }
    if scopes.contains(IpScopes::RESERVED) {
        out.push(v4([240, 0, 0, 0], 4));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::private::is_private_ip;
    use super::*;

    /// The scope classifier must agree with the existing `is_private_ip` bool:
    /// non-global iff private. This pins `ip_scope` against the trusted
    /// (heavily-tested) classifier without duplicating its case table.
    #[test]
    fn scope_non_global_matches_is_private_ip() {
        let v4: &[[u8; 4]] = &[
            [127, 0, 0, 1],
            [10, 0, 0, 1],
            [172, 16, 0, 1],
            [192, 168, 1, 1],
            [0, 1, 2, 3],
            [100, 64, 0, 1],
            [100, 63, 255, 255],
            [169, 254, 1, 1],
            [192, 0, 0, 8],
            [192, 0, 0, 9],
            [192, 0, 2, 1],
            [198, 18, 0, 1],
            [198, 51, 100, 1],
            [224, 0, 0, 1],
            [240, 0, 0, 1],
            [255, 255, 255, 255],
            [8, 8, 8, 8],
            [1, 1, 1, 1],
            [192, 88, 99, 1],
        ];
        for a in v4 {
            let ip = IpAddr::from(*a);
            assert_eq!(
                ip_scope(ip).contains(IpScopes::GLOBAL),
                !is_private_ip(ip),
                "v4 {ip}: scope={:?}",
                ip_scope(ip)
            );
            // exactly one bit is ever set
            assert_eq!(
                ip_scope(ip).bits().count_ones(),
                1,
                "v4 {ip} not single-bit"
            );
        }

        let v6: &[&str] = &[
            "::1",
            "::",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "fec0::1",
            "2001:db8::1",
            "2001:2::1",
            "100::1",
            "64:ff9b:1::1",
            "64:ff9b::1",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
        ];
        for s in v6 {
            let ip: IpAddr = s.parse().unwrap();
            assert_eq!(
                ip_scope(ip).contains(IpScopes::GLOBAL),
                !is_private_ip(ip),
                "v6 {ip}: scope={:?}",
                ip_scope(ip)
            );
            assert_eq!(
                ip_scope(ip).bits().count_ones(),
                1,
                "v6 {ip} not single-bit"
            );
        }
    }

    #[test]
    fn scope_assigns_expected_categories() {
        assert_eq!(ip_scope([127, 0, 0, 1]), IpScopes::LOOPBACK);
        assert_eq!(ip_scope([10, 1, 2, 3]), IpScopes::PRIVATE);
        assert_eq!(ip_scope([100, 64, 0, 1]), IpScopes::SHARED);
        assert_eq!(ip_scope([169, 254, 0, 1]), IpScopes::LINK_LOCAL);
        assert_eq!(ip_scope([224, 0, 0, 1]), IpScopes::MULTICAST);
        assert_eq!(ip_scope([8, 8, 8, 8]), IpScopes::GLOBAL);
        assert_eq!(
            ip_scope("::1".parse::<IpAddr>().unwrap()),
            IpScopes::LOOPBACK
        );
        assert_eq!(
            ip_scope("fc00::1".parse::<IpAddr>().unwrap()),
            IpScopes::PRIVATE
        );
        assert_eq!(
            ip_scope("fe80::1".parse::<IpAddr>().unwrap()),
            IpScopes::LINK_LOCAL
        );
    }

    #[test]
    fn masks_compose_as_expected() {
        // "private but not loopback"
        assert!(ip_scope([10, 0, 0, 1]).contains(IpScopes::PRIVATE));
        assert!(!ip_scope([10, 0, 0, 1]).contains(IpScopes::LOOPBACK));
        // LOCAL covers loopback/private/link-local/shared but not multicast/global
        assert!(IpScopes::LOCAL.contains(ip_scope([127, 0, 0, 1])));
        assert!(IpScopes::LOCAL.contains(ip_scope([100, 64, 0, 1])));
        assert!(!IpScopes::LOCAL.intersects(ip_scope([224, 0, 0, 1])));
        assert!(!IpScopes::LOCAL.intersects(ip_scope([8, 8, 8, 8])));
        // NON_GLOBAL is the complement of GLOBAL
        assert!(IpScopes::NON_GLOBAL.intersects(ip_scope([10, 0, 0, 1])));
        assert!(!IpScopes::NON_GLOBAL.intersects(ip_scope([8, 8, 8, 8])));
    }

    #[test]
    fn scope_cidrs_cover_their_members() {
        let nets = scope_cidrs(IpScopes::LOCAL);
        // every emitted CIDR must itself classify within LOCAL
        for net in &nets {
            assert!(
                IpScopes::LOCAL.contains(ip_scope(net.network())),
                "cidr {net} not LOCAL"
            );
        }
        // a representative member of each LOCAL scope is contained by some cidr
        for ip in [
            IpAddr::from([10, 1, 2, 3]),
            IpAddr::from([127, 0, 0, 5]),
            IpAddr::from([169, 254, 9, 9]),
            IpAddr::from([100, 100, 0, 1]),
        ] {
            assert!(
                nets.iter().any(|n| n.contains(&ip)),
                "no cidr contains {ip}"
            );
        }
        assert!(scope_cidrs(IpScopes::GLOBAL).is_empty());
    }
}
