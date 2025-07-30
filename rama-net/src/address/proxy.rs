use super::{Authority, Host};
use crate::{
    Protocol,
    proto::try_to_extract_protocol_from_uri_scheme,
    user::{Basic, ProxyCredential},
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

    /// [`Authority`] of the proxy.
    pub authority: Authority,

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

        for i in 0..slice.len() {
            if slice[i] == b'@' {
                let credential = Basic::try_from(
                    std::str::from_utf8(&slice[..i])
                        .context("parse proxy address: view credential as utf-8")?,
                )
                .context("parse proxy credential from address")?;

                let authority: Authority = slice[i + 1..]
                    .try_into()
                    .or_else(|_| {
                        Host::try_from(&slice[i + 1..]).map(|h| {
                            (
                                h,
                                protocol
                                    .as_ref()
                                    .and_then(|proto| proto.default_port())
                                    .unwrap_or(80),
                            )
                                .into()
                        })
                    })
                    .context("parse proxy authority from address")?;

                return Ok(Self {
                    protocol,
                    authority,
                    credential: Some(ProxyCredential::Basic(credential)),
                });
            }
        }

        let authority: Authority = slice
            .try_into()
            .or_else(|_| {
                Host::try_from(slice).map(|h| {
                    (
                        h,
                        protocol
                            .as_ref()
                            .and_then(|proto| proto.default_port())
                            .unwrap_or(80),
                    )
                        .into()
                })
            })
            .context("parse proxy authority from address")?;
        Ok(Self {
            protocol,
            authority,
            credential: None,
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
                    write!(f, "{basic}@")?;
                }
                ProxyCredential::Bearer(_) => {
                    tracing::trace!(
                        "ignore bearer token for ProxyAddress display (other means are required for these)"
                    )
                }
            }
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
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{address::Host, user::Basic};

    #[test]
    fn test_valid_proxy() {
        let addr: ProxyAddress = "127.0.0.1:8080".try_into().unwrap();
        assert_eq!(
            addr,
            ProxyAddress {
                protocol: None,
                authority: Authority::new(Host::Address("127.0.0.1".parse().unwrap()), 8080),
                credential: None,
            }
        );
    }

    #[test]
    fn test_valid_domain_proxy() {
        let addr: ProxyAddress = "proxy.example.com".try_into().unwrap();
        assert_eq!(
            addr,
            ProxyAddress {
                protocol: None,
                authority: Authority::new(Host::Name("proxy.example.com".parse().unwrap()), 80),
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
                authority: Authority::new(Host::Address("127.0.0.1".parse().unwrap()), 8080),
                credential: Some(Basic::new_static("foo", "bar").into()),
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
                authority: Authority::new(Host::Address("127.0.0.1".parse().unwrap()), 8080),
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
                authority: Authority::new(Host::Address("127.0.0.1".parse().unwrap()), 8080),
                credential: Some(Basic::new_static("foo", "bar").into()),
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
                authority: Authority::new(Host::Name("my.proxy.io.".parse().unwrap()), 9999),
                credential: Some(Basic::new_static("foo-cc-be", "baz").into()),
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
                authority: Authority::new(Host::Address("::1".parse().unwrap()), 60000),
                credential: Some(Basic::new_insecure("foo").into()),
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
                authority: Authority::new(Host::Address("::1".parse().unwrap()), 60000),
                credential: Some(Basic::new_insecure("foo").into()),
            }
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
            if !s.ends_with(":8080") {
                if s.contains("::1") {
                    let mut it = s.split("://");
                    let mut scheme = Some(it.next().unwrap());
                    let host = it.next().unwrap_or_else(|| scheme.take().unwrap());
                    if host.contains('@') {
                        let mut it = host.split('@');
                        let credential = it.next().unwrap();
                        let host = it.next().unwrap();
                        s = match scheme {
                            Some(scheme) => format!("{scheme}://{credential}@[{host}]:1080"),
                            None => format!("{credential}@[{host}]:80"),
                        };
                    } else {
                        s = match scheme {
                            Some(scheme) => format!("{scheme}://[{host}]:1080"),
                            None => format!("[{host}]:80"),
                        };
                    }
                } else {
                    s = if s.contains("://") {
                        format!("{s}:1080")
                    } else {
                        format!("{s}:80")
                    };
                }
            }
            assert_eq!(s, out, "addr: {addr}");
        }
    }
}
