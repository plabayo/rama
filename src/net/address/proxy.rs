use super::{Authority, Host};
use crate::{
    error::{ErrorContext, OpaqueError},
    net::{proto::try_to_extract_protocol_from_uri_scheme, user::ProxyCredential, Protocol},
};
use std::{fmt::Display, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq)]
/// Address of a proxy that can be connected to.
pub struct ProxyAddress {
    protocol: Protocol,
    authority: Authority,
    credential: Option<ProxyCredential>,
}

impl ProxyAddress {
    /// Creates a new [`ProxyAddress`] with the given [`Protocol`], [`Authority`], and optional [`ProxyCredential`].
    pub fn new(
        protocol: Protocol,
        authority: Authority,
        credential: Option<ProxyCredential>,
    ) -> Self {
        Self {
            protocol,
            authority,
            credential,
        }
    }

    /// Returns the protocol of this [`ProxyAddress`].
    pub fn protocol(&self) -> &Protocol {
        &self.protocol
    }

    /// Overwrites the [`Protocol`] of this [`ProxyAddress`].
    pub fn with_protocol(&mut self, proto: Protocol) {
        self.protocol = proto;
    }

    /// Returns the [`Authority`] of this [`ProxyAddress`].
    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    /// Overwrites the [`Authority`] of this [`ProxyAddress`].
    pub fn with_authority(&mut self, authority: Authority) {
        self.authority = authority;
    }

    /// Returns the [`ProxyCredential`] of this [`ProxyAddress`].
    pub fn credential(&self) -> Option<&ProxyCredential> {
        self.credential.as_ref()
    }

    /// Overwrites the [`ProxyCredential`] of this [`ProxyAddress`].
    pub fn with_credential(&mut self, credential: ProxyCredential) {
        self.credential = Some(credential);
    }
}

impl TryFrom<&str> for ProxyAddress {
    type Error = OpaqueError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let slice = value.as_bytes();

        let (protocol, size) = try_to_extract_protocol_from_uri_scheme(slice)
            .context("extract protocol from proxy address scheme")?;
        let slice = &slice[size..];

        for i in 0..slice.len() {
            if slice[i] == b'@' {
                let credential = ProxyCredential::try_from_clear_str(
                    std::str::from_utf8(&slice[..i])
                        .context("parse proxy address: view credential as utf-8")?
                        .to_owned(),
                )
                .context("parse proxy credential from address")?;

                let authority: Authority = slice[i + 1..]
                    .try_into()
                    .or_else(|_| {
                        Host::try_from(&slice[i + 1..]).map(|h| (h, protocol.default_port()).into())
                    })
                    .context("parse proxy authority from address")?;

                return Ok(ProxyAddress::new(protocol, authority, Some(credential)));
            }
        }

        let authority: Authority = slice
            .try_into()
            .or_else(|_| Host::try_from(slice).map(|h| (h, protocol.default_port()).into()))
            .context("parse proxy authority from address")?;
        Ok(ProxyAddress::new(protocol, authority, None))
    }
}

impl TryFrom<String> for ProxyAddress {
    type Error = OpaqueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl FromStr for ProxyAddress {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl Display for ProxyAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://", self.protocol.as_str())?;
        if let Some(credential) = &self.credential {
            write!(f, "{}@", credential.as_clear_string())?;
        }
        self.authority.fmt(f)
    }
}

impl serde::Serialize for ProxyAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let addr = self.to_string();
        addr.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for ProxyAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.try_into().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{
        address::Host,
        user::{Basic, Bearer},
    };

    #[test]
    fn test_valid_http_proxy() {
        let addr: ProxyAddress = "https://foo-cc-be:baz@my.proxy.io.:9999"
            .try_into()
            .unwrap();
        assert_eq!(
            addr,
            ProxyAddress::new(
                Protocol::HTTPS,
                Authority::new(Host::Name("my.proxy.io.".parse().unwrap()), 9999),
                Some(Basic::new("foo-cc-be", "baz").into()),
            )
        );
    }

    #[test]
    fn test_valid_socks5h_proxy() {
        let addr: ProxyAddress = "socks5h://foo@[::1]:60000".try_into().unwrap();
        assert_eq!(
            addr,
            ProxyAddress::new(
                Protocol::SOCKS5H,
                Authority::new(Host::Address("::1".parse().unwrap()), 60000),
                Some(Bearer::try_from_clear_str("foo").unwrap().into()),
            )
        );
    }

    #[test]
    fn test_valid_proxy_address_symmetric() {
        for s in [
            "proxy.io",
            "proxy.io:8080",
            "127.0.0.1",
            "127.0.0.1:8080",
            "::1",
            "[::1]:8080",
            "socks5://proxy.io",
            "socks5://proxy.io:8080",
            "socks5://127.0.0.1",
            "socks5://127.0.0.1:8080",
            "socks5://::1",
            "socks5://[::1]:8080",
            "socks5://foo@proxy.io",
            "socks5://foo@proxy.io:8080",
            "socks5://foo@127.0.0.1",
            "socks5://foo@127.0.0.1:8080",
            "socks5://foo@::1",
            "socks5://foo@[::1]:8080",
            "socks5://foo:@proxy.io",
            "socks5://foo:@proxy.io:8080",
            "socks5://foo:@127.0.0.1",
            "socks5://foo:@127.0.0.1:8080",
            "socks5://foo:@::1",
            "socks5://foo:@[::1]:8080",
            "socks5://foo:bar@proxy.io",
            "socks5://foo:bar@proxy.io:8080",
            "socks5://foo:bar@127.0.0.1",
            "socks5://foo:bar@127.0.0.1:8080",
            "socks5://foo:bar@::1",
            "socks5://foo:bar@[::1]:8080",
        ] {
            let addr: ProxyAddress = match s.try_into() {
                Ok(addr) => addr,
                Err(err) => panic!("invalid addr '{s}': {err}"),
            };
            let out = addr.to_string();
            let mut s = s.to_owned();
            if !s.contains("://") {
                s = format!("http://{s}");
            }
            if !s.ends_with(":8080") {
                if s.contains("::1") {
                    let mut it = s.split("://");
                    let scheme = it.next().unwrap();
                    let host = it.next().unwrap();
                    if host.contains('@') {
                        let mut it = host.split('@');
                        let credential = it.next().unwrap();
                        let host = it.next().unwrap();
                        s = format!("{scheme}://{credential}@[{host}]:80");
                    } else {
                        s = format!("{scheme}://[{host}]:80");
                    }
                } else {
                    s = format!("{s}:80");
                }
            }
            assert_eq!(s, out);
        }
    }
}
