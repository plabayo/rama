use super::Authority;
use crate::{
    Protocol,
    address::{HostWithOptPort, HostWithPort},
    proto::try_to_extract_protocol_from_uri_scheme,
    user::ProxyCredential,
};
use rama_core::{
    error::{ErrorContext, OpaqueError},
    telemetry::tracing,
};
use std::{fmt::Display, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq)]
/// Address of a proxy that can be connected to.
pub struct ProxyAddress {
    /// [`Protocol`] used by the proxy.
    pub protocol: Option<Protocol>,

    /// [`Host`] of the proxy with optional (u16) port.
    ///
    /// [`Host`]: crate::address::Host
    pub address: HostWithPort,

    /// [`ProxyCredential`] of the proxy.
    pub credential: Option<ProxyCredential>,
}

impl TryFrom<&str> for ProxyAddress {
    type Error = OpaqueError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let slice = value.as_bytes();

        let (protocol, size) = try_to_extract_protocol_from_uri_scheme(slice)
            .context("extract protocol from proxy address scheme")?;
        let slice = &slice[size..];

        let Authority {
            user_info,
            address:
                HostWithOptPort {
                    host,
                    port: maybe_port,
                },
        } = Authority::try_from(slice)?;

        let port = maybe_port.or_else(|| protocol.as_ref().and_then(|protocol| protocol.default_port()))
            .context("proxy address contains no port or scheme with known port; port is required for proxy connections!!")?;

        Ok(Self {
            protocol,
            address: HostWithPort::new(host, port),
            credential: user_info.map(ProxyCredential::Basic),
        })
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
        if let Some(protocol) = &self.protocol {
            write!(f, "{}://", protocol.as_str())?;
        }
        if let Some(credential) = &self.credential {
            match credential {
                ProxyCredential::Basic(basic) => {
                    let username = basic.username();
                    if let Some(password) = basic.password() {
                        write!(f, "{username}:{password}@")?;
                    } else {
                        write!(f, "{username}@")?;
                    }
                }
                ProxyCredential::Bearer(_) => {
                    tracing::trace!(
                        "ignore bearer token for ProxyAddress display (other means are required for these)"
                    )
                }
            }
        }
        self.address.fmt(f)
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
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use crate::user::credentials::basic;
    use rama_utils::str::non_empty_str;

    use super::*;
    use crate::{
        address::{Domain, Host},
        user::Basic,
    };

    #[test]
    fn test_valid_proxy() {
        let addr: ProxyAddress = "127.0.0.1:8080".try_into().unwrap();
        assert_eq!(
            addr,
            ProxyAddress {
                protocol: None,
                address: HostWithPort::local_ipv4(8080),
                credential: None,
            }
        );
    }

    #[test]
    fn test_valid_domain_proxy() {
        let addr: ProxyAddress = "proxy.example.com:80".try_into().unwrap();
        assert_eq!(
            addr,
            ProxyAddress {
                protocol: None,
                address: HostWithPort::new(
                    Host::Name(Domain::from_static("proxy.example.com")),
                    80
                ),
                credential: None,
            }
        );
    }

    #[test]
    fn test_valid_proxy_with_credential() {
        let addr: ProxyAddress = "foo:bar@127.0.0.1:8080".try_into().unwrap();
        assert_eq!(
            addr,
            ProxyAddress {
                protocol: None,
                address: HostWithPort::local_ipv4(8080),
                credential: Some(basic!("foo", "bar").into()),
            }
        );
    }

    #[test]
    fn test_valid_proxy_with_insecure_credential() {
        let addr: ProxyAddress = "foo@127.0.0.1:8080".try_into().unwrap();
        assert_eq!(
            addr,
            ProxyAddress {
                protocol: None,
                address: HostWithPort::local_ipv4(8080),
                credential: Some(Basic::new_insecure(non_empty_str!("foo")).into()),
            }
        );
    }

    #[test]
    fn test_valid_http_proxy() {
        let addr: ProxyAddress = "http://127.0.0.1:8080".try_into().unwrap();
        assert_eq!(
            addr,
            ProxyAddress {
                protocol: Some(Protocol::HTTP),
                address: HostWithPort::local_ipv4(8080),
                credential: None,
            }
        );
    }

    #[test]
    fn test_valid_http_proxy_with_credential() {
        let addr: ProxyAddress = "http://foo:bar@127.0.0.1:8080".try_into().unwrap();
        assert_eq!(
            addr,
            ProxyAddress {
                protocol: Some(Protocol::HTTP),
                address: HostWithPort::local_ipv4(8080),
                credential: Some(basic!("foo", "bar").into()),
            }
        );
    }

    #[test]
    fn test_valid_http_proxy_with_insecure_credential() {
        let addr: ProxyAddress = "http://foo@127.0.0.1:8080".try_into().unwrap();
        assert_eq!(
            addr,
            ProxyAddress {
                protocol: Some(Protocol::HTTP),
                address: HostWithPort::local_ipv4(8080),
                credential: Some(Basic::new_insecure(non_empty_str!("foo")).into()),
            }
        );
    }

    #[test]
    fn test_valid_https_proxy() {
        let addr: ProxyAddress = "https://foo-cc-be:baz@my.proxy.io.:9999"
            .try_into()
            .unwrap();
        assert_eq!(
            addr,
            ProxyAddress {
                protocol: Some(Protocol::HTTPS),
                address: HostWithPort::new(Host::Name(Domain::from_static("my.proxy.io.")), 9999),
                credential: Some(basic!("foo-cc-be", "baz").into()),
            }
        );
    }

    #[test]
    fn test_valid_https_proxy_with_insecure_credentials() {
        let addr: ProxyAddress = "https://foo-cc-be@my.proxy.io.:9999".try_into().unwrap();
        assert_eq!(
            addr,
            ProxyAddress {
                protocol: Some(Protocol::HTTPS),
                address: HostWithPort::new(Host::Name(Domain::from_static("my.proxy.io.")), 9999),
                credential: Some(Basic::new_insecure(non_empty_str!("foo-cc-be")).into()),
            }
        );
    }

    #[test]
    fn test_valid_socks5h_proxy() {
        let addr: ProxyAddress = "socks5h://foo@[::1]:60000".try_into().unwrap();
        assert_eq!(
            addr,
            ProxyAddress {
                protocol: Some(Protocol::SOCKS5H),
                address: HostWithPort::local_ipv6(60000),
                credential: Some(Basic::new_insecure(non_empty_str!("foo")).into()),
            }
        );
    }

    #[test]
    fn test_valid_socks5h_proxy_trailing_colon() {
        let addr: ProxyAddress = "socks5h://foo:@[::1]:60000".try_into().unwrap();
        assert_eq!(
            addr,
            ProxyAddress {
                protocol: Some(Protocol::SOCKS5H),
                address: HostWithPort::local_ipv6(60000),
                credential: Some(Basic::new_insecure(non_empty_str!("foo")).into()),
            }
        );
    }

    #[test]
    fn test_valid_proxy_address_symmetric() {
        for (s, expected) in [
            ("http://proxy.io", Some("http://proxy.io:80")),
            ("proxy.io:8080", None),
            ("127.0.0.1:8080", None),
            ("[::1]:8080", None),
            ("socks5://proxy.io", Some("socks5://proxy.io:1080")),
            ("socks5://proxy.io:8080", None),
            ("socks5://127.0.0.1", Some("socks5://127.0.0.1:1080")),
            ("socks5://127.0.0.1:8080", None),
            ("socks5://::1", Some("socks5://[::1]:1080")),
            ("socks5://[::1]:8080", None),
            ("socks5://foo@proxy.io", Some("socks5://foo@proxy.io:1080")),
            ("socks5://foo@proxy.io:8080", None),
            (
                "socks5://foo@127.0.0.1",
                Some("socks5://foo@127.0.0.1:1080"),
            ),
            ("socks5://foo@127.0.0.1:8080", None),
            ("socks5://foo@::1", Some("socks5://foo@[::1]:1080")),
            ("socks5://foo@[::1]:8080", None),
            (
                "socks5://foo:@127.0.0.1:8080",
                Some("socks5://foo@127.0.0.1:8080"),
            ),
            ("socks5://foo:@::1", Some("socks5://foo@[::1]:1080")),
            ("socks5://foo:@[::1]:8080", Some("socks5://foo@[::1]:8080")),
            (
                "socks5://foo:bar@proxy.io",
                Some("socks5://foo:bar@proxy.io:1080"),
            ),
            ("socks5://foo:bar@proxy.io:8080", None),
            (
                "socks5://foo:bar@127.0.0.1",
                Some("socks5://foo:bar@127.0.0.1:1080"),
            ),
            ("socks5://foo:bar@127.0.0.1:8080", None),
            ("socks5://foo:bar@::1", Some("socks5://foo:bar@[::1]:1080")),
            ("socks5://foo:bar@[::1]:8080", None),
        ] {
            let addr: ProxyAddress = match s.try_into() {
                Ok(addr) => addr,
                Err(err) => panic!("invalid addr '{s}': {err}"),
            };
            let out = addr.to_string();
            let expected = expected.unwrap_or(s);
            assert_eq!(expected, out, "addr: {addr}");
        }
    }
}
