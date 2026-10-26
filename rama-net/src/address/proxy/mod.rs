use core::{fmt::Display, str::FromStr};

use rama_core::{
    error::{BoxError, BoxErrorExt as _, ErrorContext, ErrorExt as _},
    telemetry::tracing,
};

use super::Authority;

mod template;
use crate::{
    Protocol,
    address::{HostWithOptPort, HostWithPort},
    proto::try_to_extract_protocol_from_uri_scheme,
    std::string::String,
    user::ProxyCredential,
};
pub use template::{ProxyPathTemplate, ProxyPathTemplateError};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

    /// CONNECT-UDP path template of a [`Protocol::MASQUE`] proxy.
    ///
    /// `None` is the RFC 9298 default
    /// ([`ProxyPathTemplate::CONNECT_UDP_DEFAULT`]); other protocols leave it `None`.
    pub template: Option<ProxyPathTemplate>,
}

impl TryFrom<&str> for ProxyAddress {
    type Error = BoxError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let slice = value.as_bytes();

        let (mut protocol, size) = try_to_extract_protocol_from_uri_scheme(slice)
            .context("extract protocol from proxy address scheme")?;
        let slice = &slice[size..];

        // The authority never contains '/', so a path starts at the first one.
        let (slice, path) = match slice.iter().position(|&b| b == b'/') {
            Some(index) => (&slice[..index], &value[size + index..]),
            None => (slice, ""),
        };
        let template = if path.is_empty() || path == "/" {
            None
        } else {
            // A path is only meaningful as a MASQUE template; it makes the route MASQUE.
            if protocol
                .as_ref()
                .is_some_and(|p| !p.is_masque() && *p != Protocol::HTTPS)
            {
                return Err(BoxError::from_static_str(
                    "a proxy path template requires the masque or https scheme",
                )
                .context_debug_field("protocol", protocol));
            }
            protocol = Some(Protocol::MASQUE);
            let template = ProxyPathTemplate::try_new(path).context("parse proxy path template")?;
            (!template.is_connect_udp_default()).then_some(template)
        };

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
                protocol
                    .as_ref()
                    .and_then(Protocol::proxy_default_port)
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
            template,
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
        self.address.fmt(f)?;
        if let Some(template) = &self.template {
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
                protocol: None,
                address: HostWithPort::local_ipv4(8080),
                credential: None,
                template: None,
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
                template: None,
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
                template: None,
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
                template: None,
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
                template: None,
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
                template: None,
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
                template: None,
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
                template: None,
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
                template: None,
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
                template: None,
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
                template: None,
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
            ("proxy.io:8080", None),
            ("127.0.0.1:8080", None),
            ("[::1]:8080", None),
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
    fn masque_proxy_addresses() {
        let addr: ProxyAddress = "masque://proxy.example".parse().unwrap();
        assert_eq!(addr.protocol, Some(Protocol::MASQUE));
        assert_eq!(addr.address.port, 443);
        assert_eq!(addr.template, None);
        assert_eq!(addr.to_string(), "masque://proxy.example:443");

        let addr: ProxyAddress =
            "masque://user:pass@proxy.example:8443/masque?h={target_host}&p={target_port}"
                .parse()
                .unwrap();
        assert_eq!(addr.protocol, Some(Protocol::MASQUE));
        assert_eq!(
            addr.template.as_ref().map(ProxyPathTemplate::as_str),
            Some("/masque?h={target_host}&p={target_port}")
        );
        assert!(matches!(addr.credential, Some(ProxyCredential::Basic(_))));
    }

    #[test]
    fn https_proxy_with_a_template_is_masque() {
        let addr: ProxyAddress = "https://proxy.example/masque{?target_host,target_port}"
            .parse()
            .unwrap();
        assert_eq!(addr.protocol, Some(Protocol::MASQUE));
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
            assert_eq!(addr.protocol, Some(Protocol::HTTPS), "{plain}");
            assert_eq!(addr.template, None, "{plain}");
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
