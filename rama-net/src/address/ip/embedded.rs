use core::net::{Ipv4Addr, Ipv6Addr};

use rama_utils::macros::error::static_str_error;

use super::ipnet::Ipv6Net;

/// IPv4 addresses an IPv6 address carries for a translation or transition mechanism.
///
/// Traffic to such an address can end at the embedded IPv4 address, so a policy on
/// destinations judges those as well. See [`embedded_ipv4`] and [`TranslationPrefix`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EmbeddedIpv4 {
    /// The IPv4 destination behind an IPv4/IPv6 translator ([RFC 6052]).
    ///
    /// [RFC 6052]: https://datatracker.ietf.org/doc/html/rfc6052
    Translated(Ipv4Addr),
    /// A deprecated IPv4-compatible address ([RFC 4291, Section 2.5.5.1]).
    ///
    /// [RFC 4291, Section 2.5.5.1]: https://datatracker.ietf.org/doc/html/rfc4291#section-2.5.5.1
    Compatible(Ipv4Addr),
    /// The IPv4 router of a 6to4 site ([RFC 3056, Section 2]).
    ///
    /// [RFC 3056, Section 2]: https://datatracker.ietf.org/doc/html/rfc3056#section-2
    SixToFour(Ipv4Addr),
    /// The Teredo server and the client's mapped IPv4 address ([RFC 4380, Section 4]).
    ///
    /// [RFC 4380, Section 4]: https://datatracker.ietf.org/doc/html/rfc4380#section-4
    Teredo {
        /// The Teredo server.
        server: Ipv4Addr,
        /// The client's mapped address, de-obfuscated.
        client: Ipv4Addr,
    },
}

impl EmbeddedIpv4 {
    /// Every IPv4 address embedded.
    pub fn addresses(self) -> impl Iterator<Item = Ipv4Addr> {
        let (first, second) = match self {
            Self::Translated(ip) | Self::Compatible(ip) | Self::SixToFour(ip) => (ip, None),
            Self::Teredo { server, client } => (server, Some(client)),
        };
        core::iter::once(first).chain(second)
    }
}

/// The IPv4 addresses `addr` embeds in a well-known form: the NAT64 well-known prefix
/// `64:ff9b::/96` ([`TranslationPrefix::WELL_KNOWN`]), IPv4-compatible `::/96` (other than
/// `::` and `::1`), 6to4 `2002::/16` or the Teredo prefix `2001::/32`.
///
/// IPv4-mapped addresses are not included: they are IPv4 already
/// ([`IntoCanonicalIpAddr`](super::IntoCanonicalIpAddr)). Translation prefixes a network
/// operator chose, such as the local-use `64:ff9b:1::/48`, are a [`TranslationPrefix`].
#[must_use]
pub fn embedded_ipv4(addr: Ipv6Addr) -> Option<EmbeddedIpv4> {
    let octets = addr.octets();
    let ipv4 =
        |at: usize| Ipv4Addr::new(octets[at], octets[at + 1], octets[at + 2], octets[at + 3]);
    match addr.segments() {
        [0x64, 0xff9b, 0, 0, 0, 0, _, _] => Some(EmbeddedIpv4::Translated(ipv4(12))),
        [0, 0, 0, 0, 0, 0, 0, 0 | 1] => None,
        [0, 0, 0, 0, 0, 0, _, _] => Some(EmbeddedIpv4::Compatible(ipv4(12))),
        [0x2002, ..] => Some(EmbeddedIpv4::SixToFour(ipv4(2))),
        [0x2001, 0, ..] => Some(EmbeddedIpv4::Teredo {
            server: ipv4(4),
            client: Ipv4Addr::from_bits(!ipv4(12).to_bits()),
        }),
        _ => None,
    }
}

static_str_error! {
    #[doc = "translation prefix length is not 32, 40, 48, 56, 64 or 96, or a /96 prefix sets bits 64 to 71"]
    pub struct InvalidTranslationPrefix;
}

/// An IPv4/IPv6 translation prefix ([RFC 6052, Section 2.2]): the IPv6 network a translator
/// maps IPv4 addresses into.
///
/// [RFC 6052, Section 2.2]: https://datatracker.ietf.org/doc/html/rfc6052#section-2.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TranslationPrefix(Ipv6Net);

impl TranslationPrefix {
    /// The NAT64 well-known prefix `64:ff9b::/96`.
    pub const WELL_KNOWN: Self = Self(Ipv6Net::new_assert(
        Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0),
        96,
    ));

    /// A network-specific prefix, such as one inside the local-use `64:ff9b:1::/48`.
    ///
    /// Its length must be 32, 40, 48, 56, 64 or 96; a /96 prefix must leave bits 64 to 71
    /// zero (RFC 6052, Section 2.2).
    pub fn try_new(prefix: Ipv6Net) -> Result<Self, InvalidTranslationPrefix> {
        let prefix = prefix.trunc();
        match prefix.prefix_len() {
            32 | 40 | 48 | 56 | 64 => Ok(Self(prefix)),
            96 if prefix.addr().octets()[8] == 0 => Ok(Self(prefix)),
            _ => Err(InvalidTranslationPrefix),
        }
    }

    /// The IPv6 network of the prefix.
    #[must_use]
    pub const fn network(&self) -> Ipv6Net {
        self.0
    }

    /// Whether `addr` is inside the prefix.
    #[must_use]
    pub fn contains(&self, addr: Ipv6Addr) -> bool {
        self.0.contains(&addr)
    }

    /// The IPv4 address `addr` carries, or `None` when it is outside the prefix or sets the
    /// reserved bits 64 to 71, which RFC 6052 requires to be zero.
    #[must_use]
    pub fn ipv4(&self, addr: Ipv6Addr) -> Option<Ipv4Addr> {
        if !self.contains(addr) {
            return None;
        }
        let octets = addr.octets();
        let at: [usize; 4] = match self.0.prefix_len() {
            32 => [4, 5, 6, 7],
            40 => [5, 6, 7, 9],
            48 => [6, 7, 9, 10],
            56 => [7, 9, 10, 11],
            64 => [9, 10, 11, 12],
            _ => [12, 13, 14, 15],
        };
        (octets[8] == 0)
            .then(|| Ipv4Addr::new(octets[at[0]], octets[at[1]], octets[at[2]], octets[at[3]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn prefix(s: &str) -> TranslationPrefix {
        TranslationPrefix::try_new(s.parse().unwrap()).unwrap()
    }

    #[test]
    fn well_known_forms_yield_their_ipv4() {
        for (addr, expected) in [
            (
                "64:ff9b::a00:1",
                Some(EmbeddedIpv4::Translated(v4("10.0.0.1"))),
            ),
            (
                "64:ff9b::192.0.2.33",
                Some(EmbeddedIpv4::Translated(v4("192.0.2.33"))),
            ),
            (
                "::127.0.0.1",
                Some(EmbeddedIpv4::Compatible(v4("127.0.0.1"))),
            ),
            (
                "2002:c0a8:101::1",
                Some(EmbeddedIpv4::SixToFour(v4("192.168.1.1"))),
            ),
            // Server 65.54.227.120; client 192.0.2.45, every bit reversed (RFC 4380 §4).
            (
                "2001:0:4136:e378:8000:63bf:3fff:fdd2",
                Some(EmbeddedIpv4::Teredo {
                    server: v4("65.54.227.120"),
                    client: v4("192.0.2.45"),
                }),
            ),
            ("::", None),
            ("::1", None),
            ("::ffff:10.0.0.1", None),
            ("64:ff9b:1::a00:1", None),
            ("64:ff9b:0:0:0:1::1", None),
            ("2001:db8::1", None),
            ("2001:1::1", None),
            ("2606:4700::1111", None),
        ] {
            assert_eq!(embedded_ipv4(v6(addr)), expected, "{addr}");
        }
    }

    #[test]
    fn teredo_lists_both_addresses() {
        let embedded = embedded_ipv4(v6("2001:0:4136:e378:8000:63bf:3fff:fdd2")).unwrap();
        assert!(
            embedded
                .addresses()
                .eq([v4("65.54.227.120"), v4("192.0.2.45")])
        );
        let embedded = embedded_ipv4(v6("64:ff9b::a00:1")).unwrap();
        assert!(embedded.addresses().eq([v4("10.0.0.1")]));
    }

    #[test]
    fn rfc_6052_examples_place_the_ipv4_address() {
        // RFC 6052 Section 2.4, Tables 1 and 2.
        for (prefix, addr) in [
            ("2001:db8::/32", "2001:db8:c000:221::"),
            ("2001:db8:100::/40", "2001:db8:1c0:2:21::"),
            ("2001:db8:122::/48", "2001:db8:122:c000:2:2100::"),
            ("2001:db8:122:300::/56", "2001:db8:122:3c0:0:221::"),
            ("2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100::"),
            ("2001:db8:122:344::/96", "2001:db8:122:344::192.0.2.33"),
            ("64:ff9b::/96", "64:ff9b::192.0.2.33"),
        ] {
            assert_eq!(
                self::prefix(prefix).ipv4(v6(addr)),
                Some(v4("192.0.2.33")),
                "{prefix}"
            );
        }
        assert_eq!(TranslationPrefix::WELL_KNOWN, self::prefix("64:ff9b::/96"));
    }

    #[test]
    fn prefixes_follow_rfc_6052_lengths_and_reserved_bits() {
        for valid in ["64:ff9b:1::/48", "2001:db8::/32", "2001:db8:122:344::/96"] {
            TranslationPrefix::try_new(valid.parse().unwrap()).unwrap();
        }
        for invalid in ["2001:db8::/44", "2001:db8::/128", "2001:db8:0:0:100::/96"] {
            TranslationPrefix::try_new(invalid.parse().unwrap()).unwrap_err();
        }
    }

    #[test]
    fn addresses_outside_or_setting_reserved_bits_carry_nothing() {
        let local_use = prefix("64:ff9b:1::/48");
        assert_eq!(local_use.ipv4(v6("64:ff9b:2::1")), None);
        assert_eq!(
            local_use.ipv4(v6("64:ff9b:1:c000:2:2100::")),
            Some(v4("192.0.2.33"))
        );
        assert_eq!(local_use.ipv4(v6("64:ff9b:1:c000:102:2100::")), None);
    }
}
