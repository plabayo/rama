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
    user::ProxyCredential,
};
use rama_utils::macros::generate_set_and_with;
pub use template::{ProxyPathTemplate, ProxyPathTemplateError};

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
/// The protocol of a proxy, with the options that only exist for that protocol.
pub enum ProxyProtocol {
    /// An HTTP proxy.
    Http {
        /// The HTTP version spoken to it; `None` over TLS negotiates one with ALPN, and
        /// means HTTP/1.1 in plaintext.
        version: Option<Version>,
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
/// The MASQUE methods an HTTP proxy offers, each `Some` when it offers that one.
///
/// MASQUE is a family: CONNECT-UDP ([RFC 9298]) is the one rama speaks, CONNECT-IP
/// ([RFC 9484]) and others join it as siblings here.
///
/// [RFC 9298]: https://datatracker.ietf.org/doc/html/rfc9298
/// [RFC 9484]: https://datatracker.ietf.org/doc/html/rfc9484
pub struct Masque {
    /// UDP tunnels over HTTP, [RFC 9298].
    ///
    /// [RFC 9298]: https://datatracker.ietf.org/doc/html/rfc9298
    pub connect_udp: Option<ConnectUdp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// CONNECT-UDP ([RFC 9298]) as one proxy offers it.
///
/// [RFC 9298]: https://datatracker.ietf.org/doc/html/rfc9298
pub struct ConnectUdp {
    /// Where the tunnels live on the proxy.
    pub template: ProxyPathTemplate,
}

impl Default for ConnectUdp {
    fn default() -> Self {
        Self {
            template: ProxyPathTemplate::connect_udp_default(),
        }
    }
}

impl ProxyProtocol {
    pub const HTTP: Self = Self::Http {
        version: Some(Version::HTTP_11),
        secure: false,
        masque: None,
    };

    pub const HTTPS: Self = Self::Http {
        version: None,
        secure: true,
        masque: None,
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

    /// The MASQUE methods this proxy offers, if it offers any.
    #[must_use]
    pub fn masque_methods(&self) -> Option<&Masque> {
        match self {
            Self::Http { masque, .. } => masque.as_ref(),
            Self::Socks5 { .. } | Self::Other(_) => None,
        }
    }

    /// Whether the proxy offers any MASQUE method.
    #[must_use]
    pub fn is_masque(&self) -> bool {
        self.masque_methods().is_some()
    }

    /// The proxy's CONNECT-UDP, if it tunnels UDP.
    #[must_use]
    pub fn connect_udp(&self) -> Option<&ConnectUdp> {
        self.masque_methods()?.connect_udp.as_ref()
    }

    /// Whether the proxy tunnels UDP with CONNECT-UDP.
    #[must_use]
    pub fn supports_connect_udp(&self) -> bool {
        self.connect_udp().is_some()
    }

    #[must_use]
    pub fn http_version(&self) -> Option<Version> {
        match self {
            Self::Http { version, .. } => *version,
            Self::Socks5 { .. } | Self::Other(_) => None,
        }
    }

    /// Speak `version` to this proxy, exactly: nothing negotiates it away.
    ///
    /// Ignored by a protocol that is not HTTP.
    #[must_use]
    pub fn with_http_version(mut self, version: Version) -> Self {
        self.set_http_version(version);
        self
    }

    /// See [`Self::with_http_version`].
    pub fn set_http_version(&mut self, version: Version) -> &mut Self {
        if let Self::Http {
            version: current, ..
        } = self
        {
            *current = Some(version);
        }
        self
    }

    /// The URI scheme naming this protocol.
    #[must_use]
    pub fn to_protocol(&self) -> Protocol {
        match self {
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
        } else if protocol == Protocol::SOCKS5 {
            Self::SOCKS5
        } else if protocol == Protocol::SOCKS5H {
            Self::SOCKS5H
        } else {
            Self::Other(protocol)
        }
    }
}

impl ProxyAddress {
    generate_set_and_with! {
        /// Speak `version` to this proxy, exactly; see [`ProxyProtocol::with_http_version`].
        pub fn http_version(mut self, version: Version) -> Self {
            self.protocol.set_http_version(version);
            self
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
        // Without a scheme the protocol is HTTP, which has no path to offer tunnels on.
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
                scheme.is_some().then(|| protocol.to_protocol())?.proxy_default_port()
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
        write!(f, "{}://", self.protocol.scheme())?;
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
        if let Some(connect_udp) = self.protocol.connect_udp()
            && !connect_udp.template.is_connect_udp_default()
        {
            connect_udp.template.fmt(f)?;
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
    fn the_udp_option_offers_connect_udp_on_the_default_template() {
        let addr: ProxyAddress = "h3+udp://proxy.example".parse().unwrap();
        assert_eq!(addr.address.port, 443);
        assert_eq!(addr.protocol.http_version(), Some(Version::HTTP_3));
        assert!(
            addr.protocol
                .connect_udp()
                .unwrap()
                .template
                .is_connect_udp_default()
        );
        assert_eq!(addr.to_string(), "h3+udp://proxy.example:443");

        let explicit: ProxyAddress =
            "h3://proxy.example:443/.well-known/masque/udp/{target_host}/{target_port}/"
                .parse()
                .unwrap();
        assert_eq!(explicit, addr);
    }

    #[test]
    fn a_path_is_the_template_of_connect_udp() {
        let addr: ProxyAddress =
            "https://user:pass@proxy.example:8443/masque?h={target_host}&p={target_port}"
                .parse()
                .unwrap();
        assert_eq!(addr.protocol.http_version(), None);
        assert_eq!(
            addr.protocol
                .connect_udp()
                .map(|connect_udp| connect_udp.template.as_str()),
            Some("/masque?h={target_host}&p={target_port}")
        );
        assert!(matches!(addr.credential, Some(ProxyCredential::Basic(_))));

        for plain in ["https://proxy.example:443", "https://proxy.example:443/"] {
            let addr: ProxyAddress = plain.parse().unwrap();
            assert_eq!(addr.protocol, ProxyProtocol::HTTPS, "{plain}");
        }
    }

    #[test]
    fn masque_is_a_family_of_methods() {
        let connect_udp: ProxyAddress = "h3+udp://proxy.example".parse().unwrap();
        assert!(connect_udp.protocol.is_masque());
        assert!(connect_udp.protocol.supports_connect_udp());

        // A proxy offering a MASQUE method rama does not speak yet offers no CONNECT-UDP.
        let other_method = ProxyAddress {
            protocol: ProxyProtocol::Http {
                version: Some(Version::HTTP_3),
                secure: true,
                masque: Some(Masque { connect_udp: None }),
            },
            ..connect_udp
        };
        assert!(other_method.protocol.is_masque());
        assert!(!other_method.protocol.supports_connect_udp());
        assert_eq!(other_method.to_string(), "h3://proxy.example:443");

        assert!(!ProxyProtocol::HTTPS.is_masque());
        assert!(!ProxyProtocol::SOCKS5.supports_connect_udp());
    }

    #[test]
    fn the_scheme_names_the_http_version() {
        for (s, version) in [
            ("http://proxy.example:8080", Some(Version::HTTP_11)),
            ("h2c://proxy.example:8080", Some(Version::HTTP_2)),
            ("https://proxy.example:8443", None),
            ("h1://proxy.example:8443", Some(Version::HTTP_11)),
            ("h2://proxy.example:8443", Some(Version::HTTP_2)),
            ("h3://proxy.example:8443", Some(Version::HTTP_3)),
            ("h3+udp://proxy.example", Some(Version::HTTP_3)),
        ] {
            let addr: ProxyAddress = s.parse().unwrap();
            assert_eq!(addr.protocol.http_version(), version, "{s}");
        }
    }

    #[test]
    fn proxy_addresses_round_trip() {
        for s in [
            "http://proxy.example:8080",
            "h2c://proxy.example:8080",
            "https://proxy.example:8443",
            "h1://proxy.example:8443",
            "h2://proxy.example:8443",
            "h3://u:p@proxy.example:8443",
            "h3+udp://proxy.example:443",
            "https+udp://proxy.example:443",
            "h2c+udp://proxy.example:8080",
            "h2://127.0.0.1:443/x/{target_host}/{target_port}{?session}",
            "h3://u:p@[::1]:4433/masque?h={target_host}&p={target_port}",
            "http://proxy.example:8080/x/{target_host}/{target_port}",
            "socks5://proxy.example:1080",
            "socks5+udp://proxy.example:1080",
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
        for s in [
            " http://proxy.example:8080",
            "https+h2://proxy.example:8443",
            "h3+udp+udp://proxy.example:443",
            "socks5+h2://proxy.example:1080",
            "socks5h+tcp://proxy.example:1080",
        ] {
            assert!(s.parse::<ProxyAddress>().is_err(), "{s}");
        }
    }

    #[test]
    fn a_version_only_changes_on_the_address_when_it_speaks_http() {
        let socks: ProxyAddress = "socks5://proxy.example:1080".parse().unwrap();
        let unchanged = socks.clone().with_http_version(Version::HTTP_2);
        assert_eq!(unchanged, socks);
    }

    #[test]
    fn invalid_proxy_path_templates_are_rejected() {
        for s in [
            "https://proxy.example/foo",
            "https://proxy.example/{target_host}",
            "h3://proxy.example/{target_host}/{+target_port}",
            "h3://proxy.example/{target_host}/{target_port}#x",
            "socks5://proxy.example/{target_host}/{target_port}/",
            "h3://proxy.example/{target_host/{target_port}",
        ] {
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
