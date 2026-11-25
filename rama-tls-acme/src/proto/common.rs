use std::{
    borrow::Cow,
    fmt::{Display, Write as _},
    net::IpAddr,
    str::FromStr,
};

use rama_core::error::{BoxError, ErrorContext as _};
use rama_crypto::{
    cert::CertificateIdentity,
    jose::{JWA, JWK},
};
use rama_net::address::{Domain, Host, IntoDomain};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Hash)]
#[serde(from = "WireIdentifier")]
/// An identifier in an ACME order: a DNS name ([RFC 8555]) or an IP address ([RFC 8738]).
///
/// Text that spells an IP address is always the address, never a `dns` identifier.
/// Build one with [`Identifier::dns`] or [`Identifier::ip`], or parse text with `FromStr`;
/// read it with [`Identifier::as_domain`] and [`Identifier::as_ip`].
///
/// [RFC 8555]: https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.7
/// [RFC 8738]: https://datatracker.ietf.org/doc/html/rfc8738#section-3
pub struct Identifier(IdentifierValue);

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
enum IdentifierValue {
    Dns(Domain),
    Ip(IpAddr),
}

/// The identifier as it is written on the wire, before canonicalisation.
#[derive(Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
enum WireIdentifier {
    Dns(Domain),
    Ip(IpAddr),
}

impl From<WireIdentifier> for Identifier {
    fn from(identifier: WireIdentifier) -> Self {
        match identifier {
            WireIdentifier::Dns(domain) => Self::from(domain),
            WireIdentifier::Ip(ip) => Self::from(ip),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub(crate) enum CanonicalIdentifier<'a> {
    Dns(&'a Domain),
    Ip(IpAddr),
}

impl Serialize for Identifier {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.canonical_view().serialize(serializer)
    }
}

impl From<Domain> for Identifier {
    fn from(domain: Domain) -> Self {
        domain
            .as_ip()
            .map_or_else(|| Self(IdentifierValue::Dns(domain)), Self::from)
    }
}

impl From<IpAddr> for Identifier {
    fn from(ip: IpAddr) -> Self {
        Self(IdentifierValue::Ip(ip))
    }
}

impl TryFrom<&Host> for Identifier {
    type Error = BoxError;

    fn try_from(host: &Host) -> Result<Self, Self::Error> {
        if let Ok(ip) = host.try_as_ip() {
            return Ok(Self::from(ip));
        }
        let domain = host.try_as_domain()?;
        Ok(Self::from(domain.into_owned()))
    }
}

impl TryFrom<Host> for Identifier {
    type Error = BoxError;

    fn try_from(host: Host) -> Result<Self, Self::Error> {
        match host {
            Host::Name(domain) => Ok(Self::from(domain)),
            other => Self::try_from(&other),
        }
    }
}

impl FromStr for Identifier {
    type Err = BoxError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::try_from(Host::parse_name(text)?)
    }
}

impl Identifier {
    /// Create a DNS identifier, treating text that spells an IP address as an IP identifier.
    #[must_use]
    pub fn dns(domain: impl IntoDomain) -> Self {
        Self::from(domain.into_domain())
    }

    /// Create an IP identifier.
    #[must_use]
    pub fn ip(ip: IpAddr) -> Self {
        Self::from(ip)
    }

    /// Clone this canonical identifier.
    #[must_use]
    pub fn canonical(&self) -> Self {
        self.clone()
    }

    /// Borrow this canonical identifier.
    pub(crate) fn canonical_view(&self) -> CanonicalIdentifier<'_> {
        match &self.0 {
            IdentifierValue::Dns(domain) => CanonicalIdentifier::Dns(domain),
            IdentifierValue::Ip(ip) => CanonicalIdentifier::Ip(*ip),
        }
    }

    /// The DNS name of a `dns` identifier.
    #[must_use]
    pub fn as_domain(&self) -> Option<&Domain> {
        match &self.0 {
            IdentifierValue::Dns(domain) => Some(domain),
            IdentifierValue::Ip(_) => None,
        }
    }

    /// The address of an `ip` identifier.
    #[must_use]
    pub fn as_ip(&self) -> Option<IpAddr> {
        match &self.0 {
            IdentifierValue::Dns(_) => None,
            IdentifierValue::Ip(ip) => Some(*ip),
        }
    }

    /// The certificate identity this identifier names.
    #[must_use]
    pub fn certificate_identity(&self) -> CertificateIdentity {
        match self.canonical_view() {
            CanonicalIdentifier::Dns(domain) => CertificateIdentity::Dns(domain.clone()),
            CanonicalIdentifier::Ip(ip) => CertificateIdentity::Ip(ip),
        }
    }

    /// The server name a `tls-alpn-01` validator sends for this identifier.
    ///
    /// SNI cannot carry an IP address, so an `ip` identifier is validated under
    /// its reverse mapping name in `in-addr.arpa` or `ip6.arpa` ([RFC 8738 section 6]).
    ///
    /// [RFC 8738 section 6]: https://datatracker.ietf.org/doc/html/rfc8738#section-6
    pub fn tls_alpn_server_name(&self) -> Result<Domain, BoxError> {
        let ip = match self.canonical_view() {
            CanonicalIdentifier::Dns(domain) => return Ok(domain.clone()),
            CanonicalIdentifier::Ip(ip) => ip,
        };
        let mut name = String::with_capacity(72);
        match ip {
            IpAddr::V4(ip) => {
                for octet in ip.octets().iter().rev() {
                    write!(name, "{octet}.").context("write reverse mapping label")?;
                }
                name.push_str("in-addr.arpa");
            }
            IpAddr::V6(ip) => {
                for octet in ip.octets().iter().rev() {
                    for nibble in [octet & 0x0f, octet >> 4] {
                        name.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
                        name.push('.');
                    }
                }
                name.push_str("ip6.arpa");
            }
        }
        Domain::try_from(name).context("reverse mapping name of an ip identifier")
    }
}

impl Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            IdentifierValue::Dns(domain) => domain.fmt(f),
            IdentifierValue::Ip(ip) => ip.fmt(f),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
/// JWS protected header for acme requests, such as defined in [rfc8555 section 6.2]
///
/// [rfc8555 section 6.2]: https://datatracker.ietf.org/doc/html/rfc8555/#section-6.2
pub struct ProtectedHeader<'a> {
    #[serde(flatten)]
    pub crypto: ProtectedHeaderCrypto<'a>,
    #[serde(flatten)]
    pub acme: ProtectedHeaderAcme<'a>,
}

#[derive(Debug, Serialize, Deserialize)]
/// Cryptographic part of the [`ProtectedHeader`]
pub struct ProtectedHeaderCrypto<'a> {
    /// Algorithm that was used to sign the JWS
    pub alg: JWA,
    #[serde(flatten)]
    /// JWK or KeyId which is used to identify this request
    pub key: ProtectedHeaderKey<'a>,
}

#[derive(Debug, Serialize, Deserialize)]
/// Acme specific part of the [`ProtectedHeader`]
pub struct ProtectedHeaderAcme<'a> {
    /// Previous nonce that was given by the server to use
    pub nonce: Cow<'a, str>,
    /// Url of the acme endpoint for which we are making a request
    pub url: Cow<'a, str>,
}

#[derive(Debug, Serialize, Deserialize)]
/// [`ProtectedHeaderKey`] send as key for [`ProtectedHeader`]
///
/// `JWK` is used for the first request to create an account, once we
/// have an account we use the `KeyID` instead
pub enum ProtectedHeaderKey<'a> {
    #[serde(rename = "jwk")]
    Jwk(Cow<'a, JWK>),
    #[serde(rename = "kid")]
    KeyID(Cow<'a, str>),
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use rama_net::address::{Domain, Host};
    use serde_json::json;

    use super::Identifier;

    #[test]
    fn named_constructors_classify_dns_text_before_constructing() {
        let ip = IpAddr::from([192, 0, 2, 1]);
        assert_eq!("192.0.2.1".parse::<Identifier>().unwrap().as_ip(), Some(ip));
        assert_eq!(
            "2001:db8::1".parse::<Identifier>().unwrap().as_ip(),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(Identifier::ip(ip).as_ip(), Some(ip));
        assert_eq!(
            Identifier::dns(Domain::example()).as_domain(),
            Some(&Domain::example())
        );
    }

    #[test]
    fn dns_takes_static_names_and_domains_and_classifies_ip_text() {
        assert_eq!(
            Identifier::dns("example.com").as_domain(),
            Some(&Domain::example())
        );
        assert_eq!(
            Identifier::dns(Domain::example()),
            Identifier::dns("example.com")
        );
        let spelled = Identifier::dns("192.0.2.1");
        assert_eq!(spelled.as_ip(), Some(Ipv4Addr::new(192, 0, 2, 1).into()));
        assert_eq!(spelled.as_domain(), None);
        assert_eq!(
            Identifier::dns(Domain::from_static("192.0.2.1")),
            Identifier::ip(IpAddr::from([192, 0, 2, 1]))
        );
    }

    #[test]
    fn ip_identifiers_round_trip_in_their_rfc_text_form() {
        // RFC 8738 section 3.
        let v6 =
            serde_json::from_value::<Identifier>(json!({"type": "ip", "value": "2001:db8::1"}))
                .unwrap();
        assert_eq!(v6, Identifier::ip("2001:db8::1".parse().unwrap()));
        assert_eq!(
            serde_json::to_value(&v6).unwrap(),
            json!({"type": "ip", "value": "2001:db8::1"})
        );
        let v4 = serde_json::from_value::<Identifier>(json!({"type": "ip", "value": "192.0.2.1"}))
            .unwrap();
        assert_eq!(v4, Identifier::ip(Ipv4Addr::new(192, 0, 2, 1).into()));
        assert_eq!(
            serde_json::to_value(&v4).unwrap(),
            json!({"type": "ip", "value": "192.0.2.1"})
        );
        // Any accepted spelling is written back in the RFC 5952 form.
        let long = serde_json::from_value::<Identifier>(
            json!({"type": "ip", "value": "2001:DB8:0:0:0:0:0:1"}),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&long).unwrap(),
            json!({"type": "ip", "value": "2001:db8::1"})
        );
        let dns = serde_json::from_value::<Identifier>(
            json!({"type": "dns", "value": "www.example.org"}),
        )
        .unwrap();
        assert_eq!(dns, Identifier::dns(Domain::from_static("www.example.org")));
        assert_eq!(
            serde_json::to_value(&dns).unwrap(),
            json!({"type": "dns", "value": "www.example.org"})
        );
    }

    #[test]
    fn names_spelling_an_address_are_ip_identifiers() {
        let spelled = Domain::try_from("1.2.3.4").unwrap();
        let address = IpAddr::from([1, 2, 3, 4]);
        assert_eq!(Identifier::from(spelled.clone()), Identifier::ip(address));
        assert_eq!(
            Identifier::try_from(Host::Name(spelled.clone())).unwrap(),
            Identifier::ip(address)
        );
        assert_eq!(
            Identifier::try_from(Host::Address(Ipv6Addr::LOCALHOST.into())).unwrap(),
            Identifier::ip(Ipv6Addr::LOCALHOST.into())
        );
        // Constructors and wire accessors share the same identity.
        let direct = Identifier::from(spelled);
        assert_eq!(
            serde_json::to_value(&direct).unwrap(),
            json!({"type": "ip", "value": "1.2.3.4"})
        );
        assert_eq!(
            serde_json::from_value::<Identifier>(json!({"type": "dns", "value": "1.2.3.4"}))
                .unwrap(),
            Identifier::ip(address)
        );
        assert_eq!(
            Identifier::from(Domain::example()),
            Identifier::dns(Domain::example())
        );
    }

    #[test]
    fn tls_alpn_server_names_use_the_reverse_mapping_for_addresses() {
        // RFC 8738 section 6.
        let v6 = Identifier::ip("2001:db8::1".parse().unwrap());
        assert_eq!(
            v6.tls_alpn_server_name().unwrap().as_str(),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
        let v4 = Identifier::ip(Ipv4Addr::new(192, 0, 2, 1).into());
        assert_eq!(
            v4.tls_alpn_server_name().unwrap().as_str(),
            "1.2.0.192.in-addr.arpa"
        );
        let dns = Identifier::dns(Domain::example());
        assert_eq!(dns.tls_alpn_server_name().unwrap().as_str(), "example.com");
    }
}
