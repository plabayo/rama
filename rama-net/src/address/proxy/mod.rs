use core::{fmt::Display, str::FromStr};

use rama_core::{
    error::{BoxError, BoxErrorExt as _, ErrorContext, ErrorExt as _},
    telemetry::tracing,
};

use super::Authority;

mod template;
use crate::{
    Protocol,
    address::{HostWithOptPort, HostWithPort, UserInfo},
    http::Version,
    proto::try_to_extract_protocol_from_uri_scheme,
    std::string::String,
    user::ProxyCredential,
};
pub use template::{ProxyPathTemplate, ProxyPathTemplateError};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// Address of a proxy that can be connected to.
pub struct ProxyAddress {
    /// How to talk to the proxy.
    pub protocol: ProxyProtocol,

    /// [`Host`] of the proxy with optional (u16) port.
    ///
    /// [`Host`]: crate::address::Host
    pub address: HostWithPort,

    /// [`ProxyCredential`] of the proxy.
    pub credential: Option<ProxyCredential>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// The protocol of a proxy, with the options that only exist for that protocol.
pub enum ProxyProtocol {
    /// An HTTP proxy, spoken to with exactly `version`: there is no negotiation.
    Http {
        version: Version,
        /// TLS to the proxy itself (`https://`).
        secure: bool,
        /// The proxy also offers MASQUE tunnels next to ordinary CONNECT.
        masque: Option<Masque>,
    },
    Socks5 {
        /// The proxy resolves target names (`socks5h://`).
        remote_dns: bool,
        /// The proxy relays UDP (UDP ASSOCIATE).
        udp: bool,
    },
    /// A scheme rama has no proxy support for.
    Other(Protocol),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// MASQUE tunnels offered by an HTTP proxy.
pub struct Masque {
    /// CONNECT-UDP path template; `None` is the RFC 9298 default
    /// ([`ProxyPathTemplate::CONNECT_UDP_DEFAULT`]).
    pub connect_udp: Option<ProxyPathTemplate>,
}

impl ProxyProtocol {
    pub const HTTP: Self = Self::Http {
        version: Version::HTTP_11,
        secure: false,
        masque: None,
    };

    pub const HTTPS: Self = Self::Http {
        version: Version::HTTP_11,
        secure: true,
        masque: None,
    };

    pub const MASQUE: Self = Self::Http {
        version: Version::HTTP_3,
        secure: true,
        masque: Some(Masque { connect_udp: None }),
    };

    pub const SOCKS5: Self = Self::Socks5 {
        remote_dns: false,
        udp: false,
    };

    pub const SOCKS5H: Self = Self::Socks5 {
        remote_dns: true,
        udp: false,
    };

    #[must_use]
    pub fn is_http(&self) -> bool {
        matches!(self, Self::Http { .. })
    }

    #[must_use]
    pub fn is_socks5(&self) -> bool {
        matches!(self, Self::Socks5 { .. })
    }

    /// Whether the connection to the proxy itself is TLS.
    #[must_use]
    pub fn is_secure(&self) -> bool {
        matches!(self, Self::Http { secure: true, .. })
    }

    #[must_use]
    pub fn masque(&self) -> Option<&Masque> {
        match self {
            Self::Http { masque, .. } => masque.as_ref(),
            Self::Socks5 { .. } | Self::Other(_) => None,
        }
    }

    #[must_use]
    pub fn is_masque(&self) -> bool {
        self.masque().is_some()
    }

    #[must_use]
    pub fn http_version(&self) -> Option<Version> {
        match self {
            Self::Http { version, .. } => Some(*version),
            Self::Socks5 { .. } | Self::Other(_) => None,
        }
    }

    /// The URI scheme naming this protocol.
    #[must_use]
    pub fn to_protocol(&self) -> Protocol {
        match self {
            Self::Http {
                masque: Some(_), ..
            } => Protocol::MASQUE,
            Self::Http { secure: true, .. } => Protocol::HTTPS,
            Self::Http { secure: false, .. } => Protocol::HTTP,
            Self::Socks5 {
                remote_dns: false, ..
            } => Protocol::SOCKS5,
            Self::Socks5 {
                remote_dns: true, ..
            } => Protocol::SOCKS5H,
            Self::Other(protocol) => protocol.clone(),
        }
    }
}

impl Default for ProxyProtocol {
    fn default() -> Self {
        Self::HTTP
    }
}

impl From<Protocol> for ProxyProtocol {
    fn from(protocol: Protocol) -> Self {
        if protocol == Protocol::HTTP {
            Self::HTTP
        } else if protocol == Protocol::HTTPS {
            Self::HTTPS
        } else if protocol == Protocol::MASQUE {
            Self::MASQUE
        } else if protocol == Protocol::SOCKS5 {
            Self::SOCKS5
        } else if protocol == Protocol::SOCKS5H {
            Self::SOCKS5H
        } else {
            Self::Other(protocol)
        }
    }
}

impl TryFrom<&str> for ProxyAddress {
    type Error = BoxError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let slice = value.as_bytes();

        let (scheme, size) = try_to_extract_protocol_from_uri_scheme(slice)
            .context("extract protocol from proxy address scheme")?;
        let slice = &slice[size..];

        // The authority never contains '/', so a path starts at the first one.
        let (slice, path) = match slice.iter().position(|&b| b == b'/') {
            Some(index) => (&slice[..index], &value[size + index..]),
            None => (slice, ""),
        };
        let mut protocol = scheme.clone().map(ProxyProtocol::from).unwrap_or_default();
        if !path.is_empty() && path != "/" {
            // A path is only meaningful as a MASQUE template; it makes the route MASQUE.
            if !protocol.is_masque() && protocol != ProxyProtocol::HTTPS {
                return Err(BoxError::from_static_str(
                    "a proxy path template requires the masque or https scheme",
                )
                .context_debug_field("protocol", scheme));
            }
            let template = ProxyPathTemplate::try_new(path).context("parse proxy path template")?;
            protocol = ProxyProtocol::Http {
                version: Version::HTTP_3,
                secure: true,
                masque: Some(Masque {
                    connect_udp: (!template.is_connect_udp_default()).then_some(template),
                }),
            };
        }

        let Authority {
            user_info,
            address:
                HostWithOptPort {
                    host,
                    port: maybe_port,
                },
        } = Authority::try_from(slice)?;

        let port = maybe_port
            .as_u16()
            .or_else(|| scheme.as_ref().and_then(Protocol::proxy_default_port))
            .context(
                "proxy address contains no port or scheme with a known proxy port; port is required for proxy connections",
            )?;

        Ok(Self {
            protocol,
            address: HostWithPort::new(host, port),
            // RFC 3986 userinfo → HTTP Basic-Auth credential. Drop the
            // credential (rather than fail the parse) if it can't be
            // expressed as Basic (e.g. empty user). The proxy will
            // attempt unauthenticated.
            credential: user_info
                .and_then(|ui| ui.to_basic().ok())
                .map(ProxyCredential::Basic),
        })
    }
}

impl TryFrom<String> for ProxyAddress {
    type Error = BoxError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl FromStr for ProxyAddress {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl Display for ProxyAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}://", self.protocol.to_protocol().as_str())?;
        if let Some(credential) = &self.credential {
            match credential {
                ProxyCredential::Basic(basic) => {
                    // Basic contains decoded credentials; URI delimiters must
                    // be encoded before placing them back in the authority.
                    write!(f, "{}@", UserInfo::from(basic.clone()))?;
                }
                ProxyCredential::Bearer(_) => {
                    tracing::trace!(
                        "ignore bearer token for ProxyAddress display (other means are required for these)"
                    )
                }
            }
        }
        self.address.fmt(f)?;
        if let Some(template) = self
            .protocol
            .masque()
            .and_then(|masque| masque.connect_udp.as_ref())
        {
            template.fmt(f)?;
        }
        Ok(())
    }
}

use rama_utils::macros::serde_str::impl_serde_str;

impl_serde_str!(display ProxyAddress);

#[cfg(test)]
mod tests {
    use rama_utils::str::non_empty_str;

    use super::*;
    use crate::{
        address::{Domain, Host},
        uri::TemplateOperator,
        user::{Basic, credentials::basic},
    };

    #[test]
    fn test_valid_proxy() {
        let addr: ProxyAddress = "127.0.0.1:8080".try_into().unwrap();
        assert_eq!(
            addr,
            ProxyAddress {
                protocol: ProxyProtocol::HTTP,
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
                protocol: ProxyProtocol::HTTP,
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
                protocol: ProxyProtocol::HTTP,
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
                protocol: ProxyProtocol::HTTP,
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
                protocol: ProxyProtocol::HTTP,
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
                protocol: ProxyProtocol::HTTP,
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
                protocol: ProxyProtocol::HTTP,
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
                protocol: ProxyProtocol::HTTPS,
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
                protocol: ProxyProtocol::HTTPS,
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
                protocol: ProxyProtocol::SOCKS5H,
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
                protocol: ProxyProtocol::SOCKS5H,
                address: HostWithPort::local_ipv6(60000),
                credential: Some(Basic::new_insecure(non_empty_str!("foo")).into()),
            }
        );
    }

    #[test]
    fn test_valid_proxy_address_symmetric() {
        for (s, expected) in [
            ("http://proxy.io", Some("http://proxy.io:1080")),
            ("https://proxy.io", Some("https://proxy.io:443")),
            ("socks5://proxy.io", Some("socks5://proxy.io:1080")),
            ("socks5h://proxy.io", Some("socks5h://proxy.io:1080")),
            ("proxy.io:8080", Some("http://proxy.io:8080")),
            ("127.0.0.1:8080", Some("http://127.0.0.1:8080")),
            ("[::1]:8080", Some("http://[::1]:8080")),
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

    #[test]
    fn credentials_with_uri_delimiters_round_trip() {
        for input in [
            "@1%2f@.010:0;A767@559@2072070:6",
            "http://u%2Fser:p%40ss%25word%23%3F@proxy.example:8080",
            "socks5://user%3Aname:p%3A%2F%2Fword@[::1]:1080",
            "masque://user%2Fname:p%2Fword@proxy.example:443/x/{target_host}/{target_port}",
        ] {
            let address: ProxyAddress = input.parse().unwrap();
            assert!(address.credential.is_some());
            let displayed = address.to_string();
            let reparsed: ProxyAddress = displayed.parse().expect("displayed proxy must parse");
            assert_eq!(reparsed, address, "{input}");
        }
    }

    #[test]
    fn masque_proxy_addresses() {
        let addr: ProxyAddress = "masque://proxy.example".parse().unwrap();
        assert_eq!(addr.protocol, ProxyProtocol::MASQUE);
        assert_eq!(addr.address.port, 443);
        assert_eq!(addr.to_string(), "masque://proxy.example:443");

        let addr: ProxyAddress =
            "masque://user:pass@proxy.example:8443/masque?h={target_host}&p={target_port}"
                .parse()
                .unwrap();
        assert_eq!(addr.protocol.http_version(), Some(Version::HTTP_3));
        assert_eq!(
            addr.protocol
                .masque()
                .and_then(|masque| masque.connect_udp.as_ref())
                .map(ProxyPathTemplate::as_str),
            Some("/masque?h={target_host}&p={target_port}")
        );
        assert!(matches!(addr.credential, Some(ProxyCredential::Basic(_))));
    }

    #[test]
    fn https_proxy_with_a_template_is_masque() {
        let addr: ProxyAddress = "https://proxy.example/masque{?target_host,target_port}"
            .parse()
            .unwrap();
        assert_eq!(addr.protocol.http_version(), Some(Version::HTTP_3));
        assert!(addr.protocol.is_masque());
        assert_eq!(
            addr.to_string(),
            "masque://proxy.example:443/masque{?target_host,target_port}"
        );

        // The RFC default template normalises to `None`, so both spellings are equal.
        let explicit: ProxyAddress =
            "https://proxy.example:443/.well-known/masque/udp/{target_host}/{target_port}/"
                .parse()
                .unwrap();
        let implicit: ProxyAddress = "masque://proxy.example".parse().unwrap();
        assert_eq!(explicit, implicit);

        for plain in ["https://proxy.example:443", "https://proxy.example:443/"] {
            let addr: ProxyAddress = plain.parse().unwrap();
            assert_eq!(addr.protocol, ProxyProtocol::HTTPS, "{plain}");
        }
    }

    #[test]
    fn invalid_proxy_path_templates_are_rejected() {
        for s in [
            "https://proxy.example/foo",
            "https://proxy.example/{target_host}",
            "masque://proxy.example/{target_host}/{+target_port}",
            "masque://proxy.example/{target_host}/{target_port}#x",
            "http://proxy.example/{target_host}/{target_port}/",
            "socks5://proxy.example/{target_host}/{target_port}/",
            "masque://proxy.example/{target_host/{target_port}",
        ] {
            assert!(s.parse::<ProxyAddress>().is_err(), "{s}");
        }
    }

    #[test]
    fn masque_proxy_addresses_round_trip() {
        for s in [
            "masque://proxy.example:443",
            "masque://u:p@[::1]:4433/masque?h={target_host}&p={target_port}",
            "masque://127.0.0.1:443/x/{target_host}/{target_port}{?session}",
        ] {
            let addr: ProxyAddress = s.parse().unwrap();
            assert_eq!(addr.to_string(), s);
            assert_eq!(addr.to_string().parse::<ProxyAddress>().unwrap(), addr);
        }
    }

    #[test]
    fn proxy_path_template_expands_targets() {
        let template =
            ProxyPathTemplate::try_new("/m?h={target_host}&p={target_port}{&extra}").unwrap();
        for (host, expected) in [
            (
                Host::Address("2001:db8::42".parse().unwrap()),
                "/m?h=2001%3Adb8%3A%3A42&p=443",
            ),
            (
                Host::Address("192.0.2.6".parse().unwrap()),
                "/m?h=192.0.2.6&p=443",
            ),
            (
                Host::Name(Domain::from_static("example.org")),
                "/m?h=example.org&p=443",
            ),
        ] {
            let mut out = String::new();
            template.expand_target_to(&mut out, &host, 443);
            assert_eq!(out, expected);

            let default =
                ProxyPathTemplate::try_new(ProxyPathTemplate::CONNECT_UDP_DEFAULT).unwrap();
            assert!(default.is_connect_udp_default());
            let (mut slow, mut fast) = (String::new(), String::new());
            default.expand_target_to(&mut slow, &host, 443);
            ProxyPathTemplate::expand_connect_udp_default_to(&mut fast, &host, 443);
            assert_eq!(slow, fast);
        }
    }

    #[test]
    fn proxy_path_template_rules() {
        assert_eq!(
            ProxyPathTemplate::try_new("masque/{target_host}/{target_port}").unwrap_err(),
            ProxyPathTemplateError::NotAbsolutePath
        );
        assert_eq!(
            ProxyPathTemplate::try_new("/{target_host}").unwrap_err(),
            ProxyPathTemplateError::MissingTargetPort
        );
        assert_eq!(
            ProxyPathTemplate::try_new("/{target_port}").unwrap_err(),
            ProxyPathTemplateError::MissingTargetHost
        );
        for (template, operator) in [
            ("/{+target_host}/{target_port}", TemplateOperator::Reserved),
            ("/{target_host}{#target_port}", TemplateOperator::Fragment),
            ("/x{.target_host}{target_port}", TemplateOperator::Label),
            (
                "/x{/target_host,target_port}",
                TemplateOperator::PathSegment,
            ),
            (
                "/x{;target_host,target_port}",
                TemplateOperator::PathParameter,
            ),
        ] {
            assert_eq!(
                ProxyPathTemplate::try_new(template).unwrap_err(),
                ProxyPathTemplateError::ForbiddenOperator(operator),
                "{template}"
            );
        }
    }
}
