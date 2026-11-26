use core::{
    fmt,
    hash::{Hash, Hasher},
    net::IpAddr,
    str::FromStr,
};

use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::Extension,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    address::{Domain, DomainRef, Host, HostRef},
    std::boxed::Box,
};

/// A canonical network host restricted to DNS names and IP addresses.
/// IP literals received in SNI are retained even though RFC 6066 excludes them.
///
/// As an extension it is the name a TLS client verifies the server certificate
/// against and, per the client's SNI policy, offers as SNI; a later layer may overwrite it.
#[derive(Debug, Clone, PartialEq, Eq, Extension)]
#[extension(tags(tls), scope(connection))]
pub struct ServerName(Repr);

/// Variant names match [`Host`], so `Debug` output equals that of the equal host.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Repr {
    Name(Domain),
    Address(IpAddr),
}

impl ServerName {
    /// Parse a received SNI name through the network host parser.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        name.parse().ok()
    }

    /// Borrow the DNS name, if this is a DNS identity.
    #[must_use]
    pub fn as_domain(&self) -> Option<&Domain> {
        match &self.0 {
            Repr::Name(domain) => Some(domain),
            Repr::Address(_) => None,
        }
    }

    /// Return the address, if this is an IP identity.
    #[must_use]
    pub fn as_ip(&self) -> Option<IpAddr> {
        match self.0 {
            Repr::Name(_) => None,
            Repr::Address(ip) => Some(ip),
        }
    }

    /// The DNS host name as certificates and SNI spell it, without a trailing dot.
    ///
    /// `None` for an address, and for a name that only its trailing dot keeps from
    /// spelling one, such as `192.0.2.1.`.
    #[must_use]
    pub fn as_dns_host(&self) -> Option<DomainRef<'_>> {
        let host = self.as_domain()?.as_non_fqdn();
        host.as_str().parse::<IpAddr>().is_err().then_some(host)
    }

    /// Consume this name and return its DNS identity, if present.
    #[must_use]
    pub fn into_domain(self) -> Option<Domain> {
        match self.0 {
            Repr::Name(domain) => Some(domain),
            Repr::Address(_) => None,
        }
    }
}

impl FromStr for ServerName {
    type Err = BoxError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::try_from(Host::parse_name(name)?)
    }
}

impl TryFrom<&Host> for ServerName {
    type Error = BoxError;

    fn try_from(host: &Host) -> Result<Self, Self::Error> {
        match host {
            Host::Name(domain) => Ok(Self::from(domain.clone())),
            Host::Address(ip) => Ok(Self::from(*ip)),
            Host::Uninterpreted(_) => Self::try_from(host.clone()),
        }
    }
}

impl TryFrom<Host> for ServerName {
    type Error = BoxError;

    fn try_from(host: Host) -> Result<Self, Self::Error> {
        match host {
            Host::Name(domain) => Ok(Self::from(domain)),
            Host::Address(ip) => Ok(Self::from(ip)),
            // Percent-decoding may reveal a name or an address.
            Host::Uninterpreted(_) => match host.canonicalize() {
                Host::Name(domain) => Ok(Self::from(domain)),
                Host::Address(ip) => Ok(Self::from(ip)),
                Host::Uninterpreted(_) => {
                    Err(BoxError::from_static_str("host is not a TLS server name"))
                }
            },
        }
    }
}

// The one place a name spelling an IP literal becomes that address, as `Host::canonicalize` does.
impl From<Domain> for ServerName {
    fn from(domain: Domain) -> Self {
        match domain.as_ip() {
            Some(ip) => Self(Repr::Address(ip)),
            None => Self(Repr::Name(domain.canonicalize())),
        }
    }
}

impl From<IpAddr> for ServerName {
    fn from(ip: IpAddr) -> Self {
        Self(Repr::Address(ip))
    }
}

impl From<ServerName> for Host {
    fn from(name: ServerName) -> Self {
        match name.0 {
            Repr::Name(domain) => Self::Name(domain),
            Repr::Address(ip) => Self::Address(ip),
        }
    }
}

impl From<&ServerName> for Host {
    fn from(name: &ServerName) -> Self {
        HostRef::from(name).into_owned()
    }
}

impl<'a> From<&'a ServerName> for HostRef<'a> {
    fn from(name: &'a ServerName) -> Self {
        match &name.0 {
            Repr::Name(domain) => Self::Name(domain.into()),
            Repr::Address(ip) => Self::Address(*ip),
        }
    }
}

// Hashes as the equal `Host` does, so keys built from either agree.
impl Hash for ServerName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        HostRef::from(self).hash(state);
    }
}

impl fmt::Display for ServerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Repr::Name(domain) => domain.fmt(f),
            Repr::Address(ip) => ip.fmt(f),
        }
    }
}

impl Serialize for ServerName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ServerName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = Box::<str>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "dial9")]
impl dial9_trace_format::TraceField for ServerName {
    fn field_type() -> dial9_trace_format::types::FieldType {
        dial9_trace_format::types::FieldType::String
    }

    fn encode<W: std::io::Write>(
        &self,
        enc: &mut dial9_trace_format::EventEncoder<'_, W>,
    ) -> std::io::Result<()> {
        match &self.0 {
            Repr::Name(domain) => enc.write_string(domain.as_str()),
            Repr::Address(ip) => enc.write_string(&ip.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_hash::hash;

    #[test]
    fn encodings_and_identity_match_the_equal_host() {
        for text in ["example.test", "192.0.2.1", "2001:db8::1"] {
            let name: ServerName = text.parse().unwrap();
            let host = Host::from(&name);
            assert_eq!(name.to_string(), host.to_string());
            assert_eq!(
                serde_json::to_string(&name).unwrap(),
                serde_json::to_string(&host).unwrap()
            );
            assert_eq!(hash(&name), hash(&host));
            assert_eq!(format!("{name:?}"), format!("ServerName({host:?})"));
            assert_eq!(HostRef::from(&name), HostRef::from(&host));
        }
    }

    #[test]
    fn names_classify_and_round_trip_without_losing_addresses() {
        for text in ["192.0.2.1", "2001:db8::1", "[2001:db8::1]", "example.test"] {
            let name: ServerName = text.parse().unwrap();
            let encoded = serde_json::to_vec(&name).unwrap();
            assert_eq!(
                serde_json::from_slice::<ServerName>(&encoded).unwrap(),
                name
            );
            let host = Host::from(name.clone());
            assert_eq!(ServerName::try_from(&host).unwrap(), name);
            assert_eq!(ServerName::try_from(host).unwrap(), name);
            assert_eq!(name.to_string().parse::<ServerName>().unwrap(), name);
            assert_eq!(name.as_domain().is_some(), text == "example.test");
            assert_eq!(name.as_ip().is_some(), text != "example.test");
        }
        let numeric = Domain::try_from("192.0.2.1").unwrap();
        assert_eq!(
            ServerName::from(numeric.clone()),
            ServerName::try_from(Host::Name(numeric)).unwrap()
        );
    }

    #[test]
    fn dns_representation_rejects_address_literals() {
        let name = ServerName::from(Domain::from_static("192.0.2.1"));
        assert!(name.as_ip().is_some());
        assert!(name.as_domain().is_none());
        let dotted = ServerName::from(Domain::from_static("192.0.2.1."));
        assert!(dotted.as_domain().is_some());
        assert_ne!(dotted, name);
        // Neither spells a DNS host once the trailing dot is gone.
        assert!(name.as_dns_host().is_none());
        assert!(dotted.as_dns_host().is_none());
        for text in ["example.test", "example.test."] {
            let name = ServerName::from(Domain::from_static(text));
            assert_eq!(
                name.as_dns_host().map(|host| host.as_str()),
                Some("example.test")
            );
        }
    }

    #[test]
    fn uninterpreted_hosts_are_promoted_or_refused() {
        for text in ["%65xample.test", "%31%39%32.0.2.1", "%3a%3a1"] {
            let host: Host = text.parse().unwrap();
            let name = ServerName::try_from(&host).unwrap();
            assert_eq!(ServerName::try_from(host).unwrap(), name);
            assert!(name.as_domain().is_some() || name.as_ip().is_some());
        }
        "%3a%3a1".parse::<ServerName>().unwrap_err();
        for text in [
            "",
            "bad!name",
            "[v1.foo]",
            "fe80::1%eth0",
            "[fe80::1%25eth0]",
        ] {
            assert!(text.parse::<ServerName>().is_err(), "{text}");
            if let Ok(host) = text.parse::<Host>() {
                assert!(ServerName::try_from(&host).is_err(), "{text}");
                assert!(ServerName::try_from(host).is_err(), "{text}");
            }
        }
    }
}
