use core::{fmt::Display, str::FromStr};

use rama_core::{
    error::{BoxError, ErrorContext},
    telemetry::tracing,
};

use super::Authority;

mod scheme;
mod template;
use crate::{
    Protocol,
    address::{HostWithOptPort, HostWithPort, UserInfo},
    http::Version,
    proto::try_to_extract_scheme_from_uri,
    std::string::String,
    transport::TransportProtocol,
    user::ProxyCredential,
};
use rama_utils::str::smol_str::SmolStr;
pub use template::{ProxyPathProtocolTemplate, ProxyPathTemplate, ProxyPathTemplateError};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// Address of a proxy that can be connected to.
///
/// Written as `[scheme://][user[:pass]@]host[:port][/template]`, where the scheme names the
/// protocol and what differs from that protocol's default; see
/// [`ProxyProtocol::try_from_scheme`].
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
/// How to reach a proxy and what to ask it.
pub enum ProxyProtocol {
    /// An HTTP proxy: CONNECT for TCP, and MASQUE for UDP or IP when it has a template.
    Http {
        /// The HTTP version spoken to it. `None` over TLS lets the client pick one as it
        /// does for an origin: HTTP/3 when the proxy advertises it (HTTPS record or
        /// Alt-Svc), else ALPN over TCP. `None` in plaintext means HTTP/1.1. A plaintext proxy with `None` is dialed the same
        /// as [`ProxyProtocol::HTTP`] (`Some(HTTP_11)`), but does not compare equal to it.
        version: Option<Version>,
        /// TLS to the proxy itself (`https://`).
        secure: bool,
        /// Where its MASQUE tunnels live; `None` offers CONNECT only.
        path_template: Option<ProxyPathTemplate>,
    },
    /// A SOCKS5 proxy: CONNECT for TCP, UDP ASSOCIATE for UDP.
    Socks5 {
        /// The proxy resolves target names (`socks5h://`).
        remote_dns: bool,
        /// Only CONNECT (`+tcp`) or only UDP ASSOCIATE (`+udp`); `None` is whichever
        /// the traffic needs.
        transport: Option<TransportProtocol>,
        /// TLS to the proxy itself (`+tls`). With UDP ASSOCIATE this secures the TCP
        /// control connection only: the UDP relay stays plaintext.
        secure: bool,
    },
    /// A scheme rama does not interpret.
    Custom(SmolStr),
}

impl ProxyProtocol {
    /// A plaintext HTTP/1.1 proxy (`http://`).
    pub const HTTP: Self = Self::Http {
        version: Some(Version::HTTP_11),
        secure: false,
        path_template: None,
    };

    /// An HTTP proxy over TLS, version picked as for an origin (`https://`).
    pub const HTTPS: Self = Self::Http {
        version: None,
        secure: true,
        path_template: None,
    };

    /// An HTTP/1.1 proxy over TLS (`h1://`).
    pub const H1: Self = Self::Http {
        version: Some(Version::HTTP_11),
        secure: true,
        path_template: None,
    };

    /// An HTTP/2 proxy over TLS (`h2://`).
    pub const H2: Self = Self::Http {
        version: Some(Version::HTTP_2),
        secure: true,
        path_template: None,
    };

    /// A plaintext HTTP/2 proxy (`h2c://`).
    pub const H2C: Self = Self::Http {
        version: Some(Version::HTTP_2),
        secure: false,
        path_template: None,
    };

    /// An HTTP/3 proxy over QUIC (`h3://`).
    pub const H3: Self = Self::Http {
        version: Some(Version::HTTP_3),
        secure: true,
        path_template: None,
    };

    /// A SOCKS5 proxy which resolves target names locally (`socks5://`).
    pub const SOCKS5: Self = Self::Socks5 {
        remote_dns: false,
        transport: None,
        secure: false,
    };

    /// A SOCKS5 proxy which resolves target names itself (`socks5h://`).
    pub const SOCKS5H: Self = Self::Socks5 {
        remote_dns: true,
        transport: None,
        secure: false,
    };

    /// A SOCKS5 proxy for CONNECT only (`socks5+tcp`).
    pub const SOCKS5_TCP: Self = Self::Socks5 {
        remote_dns: false,
        transport: Some(TransportProtocol::Tcp),
        secure: false,
    };

    /// A SOCKS5 proxy for UDP ASSOCIATE only (`socks5+udp`).
    pub const SOCKS5_UDP: Self = Self::Socks5 {
        remote_dns: false,
        transport: Some(TransportProtocol::Udp),
        secure: false,
    };

    /// A SOCKS5 proxy for CONNECT only, which resolves target names itself (`socks5h+tcp`).
    pub const SOCKS5H_TCP: Self = Self::Socks5 {
        remote_dns: true,
        transport: Some(TransportProtocol::Tcp),
        secure: false,
    };

    /// A SOCKS5 proxy for UDP ASSOCIATE only, which resolves target names itself
    /// (`socks5h+udp`).
    pub const SOCKS5H_UDP: Self = Self::Socks5 {
        remote_dns: true,
        transport: Some(TransportProtocol::Udp),
        secure: false,
    };

    /// A SOCKS5 proxy over TLS (`socks5+tls`).
    pub const SOCKS5_TLS: Self = Self::Socks5 {
        remote_dns: false,
        transport: None,
        secure: true,
    };

    /// A SOCKS5 proxy over TLS, which resolves target names itself (`socks5h+tls`).
    pub const SOCKS5H_TLS: Self = Self::Socks5 {
        remote_dns: true,
        transport: None,
        secure: true,
    };

    /// A SOCKS5 proxy over TLS for CONNECT only (`socks5+tcp+tls`).
    pub const SOCKS5_TCP_TLS: Self = Self::Socks5 {
        remote_dns: false,
        transport: Some(TransportProtocol::Tcp),
        secure: true,
    };

    /// A SOCKS5 proxy over TLS for UDP ASSOCIATE only; the UDP relay stays plaintext (`socks5+udp+tls`).
    pub const SOCKS5_UDP_TLS: Self = Self::Socks5 {
        remote_dns: false,
        transport: Some(TransportProtocol::Udp),
        secure: true,
    };

    /// A SOCKS5 proxy over TLS for CONNECT only, which resolves target names itself (`socks5h+tcp+tls`).
    pub const SOCKS5H_TCP_TLS: Self = Self::Socks5 {
        remote_dns: true,
        transport: Some(TransportProtocol::Tcp),
        secure: true,
    };

    /// A SOCKS5 proxy over TLS for UDP ASSOCIATE only, which resolves target names itself; the UDP relay stays plaintext (`socks5h+udp+tls`).
    pub const SOCKS5H_UDP_TLS: Self = Self::Socks5 {
        remote_dns: true,
        transport: Some(TransportProtocol::Udp),
        secure: true,
    };

    /// An HTTP proxy over TLS speaking `version`, which offers CONNECT-UDP on the default
    /// template (`h3+udp` for HTTP/3).
    #[must_use]
    pub fn connect_udp(version: Version) -> Self {
        Self::Http {
            version: Some(version),
            secure: true,
            path_template: Some(ProxyPathTemplate::connect_udp_default()),
        }
    }

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
        matches!(
            self,
            Self::Http { secure: true, .. } | Self::Socks5 { secure: true, .. }
        )
    }

    #[must_use]
    pub fn path_template(&self) -> Option<&ProxyPathTemplate> {
        match self {
            Self::Http { path_template, .. } => path_template.as_ref(),
            Self::Socks5 { .. } | Self::Custom(_) => None,
        }
    }

    /// The template to open CONNECT-UDP tunnels on, if this proxy offers them.
    ///
    /// An HTTP proxy offers them only where its address says so, with `+udp` or a
    /// CONNECT-UDP path template.
    #[must_use]
    pub fn connect_udp_template(&self) -> Option<ProxyPathTemplate> {
        match self {
            Self::Http {
                path_template: Some(template),
                ..
            } => template.is_connect_udp().then(|| template.clone()),
            Self::Http { .. } | Self::Socks5 { .. } | Self::Custom(_) => None,
        }
    }

    /// Whether this protocol can carry traffic of the given transport.
    ///
    /// A [`Self::Custom`] protocol carries nothing rama knows of.
    #[must_use]
    pub fn carries(&self, transport: TransportProtocol) -> bool {
        match self {
            Self::Http { path_template, .. } => match transport {
                TransportProtocol::Tcp => true,
                TransportProtocol::Udp => path_template
                    .as_ref()
                    .is_some_and(ProxyPathTemplate::is_connect_udp),
            },
            Self::Socks5 {
                transport: only, ..
            } => only.is_none_or(|only| only == transport),
            Self::Custom(_) => false,
        }
    }

    #[must_use]
    pub fn http_version(&self) -> Option<Version> {
        match self {
            Self::Http { version, .. } => *version,
            Self::Socks5 { .. } | Self::Custom(_) => None,
        }
    }

    /// The URI scheme naming this protocol, `None` for a [`Self::Custom`] one.
    #[must_use]
    pub fn as_protocol(&self) -> Option<Protocol> {
        match self {
            Self::Http { secure: true, .. } => Some(Protocol::HTTPS),
            Self::Http { secure: false, .. } => Some(Protocol::HTTP),
            Self::Socks5 {
                remote_dns: false, ..
            } => Some(Protocol::SOCKS5),
            Self::Socks5 {
                remote_dns: true, ..
            } => Some(Protocol::SOCKS5H),
            Self::Custom(_) => None,
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
        } else if protocol == Protocol::SOCKS5 {
            Self::SOCKS5
        } else if protocol == Protocol::SOCKS5H {
            Self::SOCKS5H
        } else {
            Self::Custom(SmolStr::new(protocol.as_str()))
        }
    }
}

impl TryFrom<&str> for ProxyAddress {
    type Error = BoxError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let slice = value.as_bytes();

        let (scheme, size) = try_to_extract_scheme_from_uri(slice)
            .context("extract the scheme of a proxy address")?;
        let slice = &slice[size..];

        // The authority never contains '/', so a path starts at the first one.
        let (slice, path) = match slice.iter().position(|&b| b == b'/') {
            Some(index) => (&slice[..index], &value[size + index..]),
            None => (slice, ""),
        };
        let protocol =
            ProxyProtocol::try_from_scheme_and_path(scheme.unwrap_or(Protocol::HTTP_SCHEME), path)
                .context("parse the scheme of a proxy address")?;

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
            .or_else(|| {
                scheme.and(protocol.as_protocol())?.proxy_default_port()
            })
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
        write!(f, "{}://", self.protocol)?;
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
        if let Some(template) = self.protocol.path_template()
            && !template.is_connect_udp_default()
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
            "h3://user%2Fname:p%2Fword@proxy.example:443/x/{target_host}/{target_port}",
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
        let addr: ProxyAddress = "h3+udp://proxy.example".parse().unwrap();
        assert_eq!(addr.address.port, 443);
        assert_eq!(addr.protocol.http_version(), Some(Version::HTTP_3));
        assert!(addr.protocol.carries(TransportProtocol::Tcp));
        assert!(addr.protocol.carries(TransportProtocol::Udp));
        assert!(
            addr.protocol
                .connect_udp_template()
                .unwrap()
                .is_connect_udp_default()
        );
        assert_eq!(addr.to_string(), "h3+udp://proxy.example:443");

        let addr: ProxyAddress =
            "h3://user:pass@proxy.example:8443/masque?h={target_host}&p={target_port}"
                .parse()
                .unwrap();
        assert!(addr.protocol.carries(TransportProtocol::Udp));
        assert_eq!(
            addr.protocol
                .connect_udp_template()
                .as_ref()
                .map(ProxyPathTemplate::as_str),
            Some("/masque?h={target_host}&p={target_port}")
        );
        assert!(matches!(addr.credential, Some(ProxyCredential::Basic(_))));

        // `+udp` is the default template, so a template next to it is refused as ambiguous.
        for ambiguous in [
            "h3+udp://proxy.example/masque?h={target_host}&p={target_port}",
            "https+udp://proxy.example:443/.well-known/masque/udp/{target_host}/{target_port}/",
        ] {
            assert!(ambiguous.parse::<ProxyAddress>().is_err(), "{ambiguous}");
        }

        // An HTTP proxy carries UDP only where its address says the tunnels are.
        let plain: ProxyAddress = "h3://proxy.example".parse().unwrap();
        assert!(plain.protocol.carries(TransportProtocol::Tcp));
        assert!(!plain.protocol.carries(TransportProtocol::Udp));
        assert!(plain.protocol.connect_udp_template().is_none());

        let error = "masque://proxy.example:443"
            .parse::<ProxyAddress>()
            .unwrap_err()
            .to_string();
        assert!(error.contains("h3+udp"), "{error}");
    }

    #[test]
    fn https_proxy_with_a_template_is_masque() {
        let addr: ProxyAddress =
            "https://user:pass@proxy.example:8443/masque?h={target_host}&p={target_port}"
                .parse()
                .unwrap();
        assert_eq!(addr.protocol.http_version(), None);
        assert_eq!(
            addr.protocol
                .connect_udp_template()
                .as_ref()
                .map(ProxyPathTemplate::as_str),
            Some("/masque?h={target_host}&p={target_port}")
        );
        assert!(matches!(addr.credential, Some(ProxyCredential::Basic(_))));

        // The RFC default template is what `+udp` is short for, so both spellings are equal.
        let explicit: ProxyAddress =
            "https://proxy.example:443/.well-known/masque/udp/{target_host}/{target_port}/"
                .parse()
                .unwrap();
        let implicit: ProxyAddress = "https+udp://proxy.example".parse().unwrap();
        assert_eq!(explicit, implicit);

        let ip: ProxyAddress = "h3://proxy.example/ip/{target}/{ipproto}".parse().unwrap();
        assert!(ip.protocol.path_template().unwrap().is_connect_ip());
        assert!(!ip.protocol.carries(TransportProtocol::Udp));

        for plain in ["https://proxy.example:443", "https://proxy.example:443/"] {
            let addr: ProxyAddress = plain.parse().unwrap();
            assert_eq!(addr.protocol, ProxyProtocol::HTTPS, "{plain}");
            assert_eq!(addr.protocol.path_template(), None, "{plain}");
        }
    }

    #[test]
    fn a_socks5_option_limits_the_transport() {
        for (s, tcp, udp) in [
            ("socks5://proxy.example", true, true),
            ("socks5+tcp://proxy.example", true, false),
            ("socks5h+udp://proxy.example", false, true),
        ] {
            let addr: ProxyAddress = s.parse().unwrap();
            assert_eq!(addr.protocol.carries(TransportProtocol::Tcp), tcp, "{s}");
            assert_eq!(addr.protocol.carries(TransportProtocol::Udp), udp, "{s}");
        }
    }

    #[test]
    fn every_constant_prints_its_scheme() {
        for (protocol, scheme) in [
            (ProxyProtocol::HTTP, "http"),
            (ProxyProtocol::HTTPS, "https"),
            (ProxyProtocol::H1, "h1"),
            (ProxyProtocol::H2, "h2"),
            (ProxyProtocol::H2C, "h2c"),
            (ProxyProtocol::H3, "h3"),
            (ProxyProtocol::SOCKS5, "socks5"),
            (ProxyProtocol::SOCKS5H, "socks5h"),
            (ProxyProtocol::SOCKS5_TCP, "socks5+tcp"),
            (ProxyProtocol::SOCKS5_UDP, "socks5+udp"),
            (ProxyProtocol::SOCKS5H_TCP, "socks5h+tcp"),
            (ProxyProtocol::SOCKS5H_UDP, "socks5h+udp"),
            (ProxyProtocol::SOCKS5_TLS, "socks5+tls"),
            (ProxyProtocol::SOCKS5H_TLS, "socks5h+tls"),
            (ProxyProtocol::SOCKS5_TCP_TLS, "socks5+tcp+tls"),
            (ProxyProtocol::SOCKS5_UDP_TLS, "socks5+udp+tls"),
            (ProxyProtocol::SOCKS5H_TCP_TLS, "socks5h+tcp+tls"),
            (ProxyProtocol::SOCKS5H_UDP_TLS, "socks5h+udp+tls"),
            (ProxyProtocol::connect_udp(Version::HTTP_3), "h3+udp"),
        ] {
            assert_eq!(protocol.to_string(), scheme);
            assert_eq!(ProxyProtocol::try_from_scheme(scheme).unwrap(), protocol);
        }
    }

    #[test]
    fn an_unknown_scheme_is_kept_as_is() {
        let addr: ProxyAddress = "warp://proxy.example:80".parse().unwrap();
        assert_eq!(addr.protocol, ProxyProtocol::Custom(SmolStr::new("warp")));
        assert_eq!(addr.protocol.as_protocol(), None);
        assert_eq!(addr.to_string(), "warp://proxy.example:80");
    }

    #[test]
    fn invalid_proxy_path_templates_are_rejected() {
        for s in [
            "https://proxy.example/{target_host}",
            "h3://proxy.example/{target_host}/{+target_port}",
            "h3://proxy.example/{target_host}/{target_port}#x",
            "socks5://proxy.example/{target_host}/{target_port}/",
            "h3://proxy.example/{target_host/{target_port}",
            "https://proxy.example/foo",
            "h3://proxy.example/masque?h={host}&p={port}",
        ] {
            assert!(s.parse::<ProxyAddress>().is_err(), "{s}");
        }
    }

    #[test]
    fn masque_proxy_addresses_round_trip() {
        for s in [
            "http://proxy.example:8080",
            "h2c://proxy.example:8080",
            "https://proxy.example:8443",
            "h1://proxy.example:8443",
            "h2://proxy.example:8443",
            "h3://u:p@proxy.example:8443",
            "h3+udp://proxy.example:443",
            "h2://127.0.0.1:443/x/{target_host}/{target_port}{?session}",
            "https://proxy.example:443/masque/ip{?target,ipproto}",
            "h3://u:p@[::1]:4433/masque?h={target_host}&p={target_port}",
            "http://proxy.example:8080/x/{target_host}/{target_port}",
            "socks5://proxy.example:1080",
            "socks5+udp://proxy.example:1080",
            "socks5+tcp://proxy.example:1080",
            "socks5h://proxy.example:1080",
            "socks5h+udp://u:p@proxy.example:1080",
        ] {
            let addr: ProxyAddress = s.parse().unwrap();
            assert_eq!(addr.to_string(), s, "{s}");
            assert_eq!(
                addr.to_string().parse::<ProxyAddress>().unwrap(),
                addr,
                "{s}"
            );
        }
    }

    #[test]
    fn invalid_proxy_schemes_are_rejected() {
        for s in [" http://proxy.example:8080", "://proxy.example:8080"] {
            assert!(s.parse::<ProxyAddress>().is_err(), "{s}");
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
        for template in [
            "/foo",
            "/masque?h={host}&p={port}",
            "/.well-known/masque/udp/",
        ] {
            assert_eq!(
                ProxyPathTemplate::try_new(template).unwrap_err(),
                ProxyPathTemplateError::MissingTargetHost,
                "{template}"
            );
        }
        for template in [
            "/ip/{target}",
            "/ip{?ipproto}",
            "/.well-known/masque/ip/",
            "/.well-known/masque/ip/any/any/",
            ProxyPathTemplate::CONNECT_IP_DEFAULT,
        ] {
            assert!(
                ProxyPathTemplate::try_new(template)
                    .unwrap()
                    .is_connect_ip(),
                "{template}"
            );
        }
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
