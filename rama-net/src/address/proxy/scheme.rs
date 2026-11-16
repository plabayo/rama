use core::fmt::{self, Display};

use rama_core::error::{BoxError, ErrorContext as _};

use super::{ConnectUdp, Masque, ProxyPathTemplate, ProxyProtocol};
use crate::{Protocol, http::Version};

const H1: &str = "h1";
const H2: &str = "h2";
const H2C: &str = "h2c";
const H3: &str = "h3";
const UDP: &str = "udp";

impl ProxyProtocol {
    /// Parse the scheme of a proxy address, such as `https`, `h3+udp` or `socks5h+udp`.
    ///
    /// The scheme names how a proxy is reached: `http` (HTTP/1.1) and `h2c` (HTTP/2) in
    /// plaintext, `https` over TLS with the version negotiated by ALPN, and `h1`, `h2` or
    /// `h3` over TLS with that version. The `udp` option says the proxy relays UDP as well:
    /// with CONNECT-UDP for an HTTP proxy, with UDP ASSOCIATE for a SOCKS5 one.
    pub fn try_from_scheme(scheme: &str) -> Result<Self, BoxError> {
        Self::try_from_scheme_and_path(scheme, "")
    }

    /// [`Self::try_from_scheme`] with the path of the proxy address: the template an HTTP
    /// proxy offers its CONNECT-UDP tunnels on.
    pub fn try_from_scheme_and_path(scheme: &str, path: &str) -> Result<Self, BoxError> {
        let mut parts = scheme.split('+');
        let name = parts.next().unwrap_or_default();
        let mut udp = false;
        for option in parts {
            if udp || !option.eq_ignore_ascii_case(UDP) {
                return Err(BoxError::from(format!(
                    "unknown proxy scheme option: {option}"
                )));
            }
            udp = true;
        }

        let template = if path.is_empty() || path == "/" {
            None
        } else {
            Some(ProxyPathTemplate::try_new(path).context("parse proxy path template")?)
        };

        match Self::from_scheme_name(name)? {
            Self::Http {
                version, secure, ..
            } => {
                let connect_udp = match template {
                    Some(template) => Some(ConnectUdp { template }),
                    None => udp.then(ConnectUdp::default),
                };
                Ok(Self::Http {
                    version,
                    secure,
                    masque: connect_udp.map(|connect_udp| Masque {
                        connect_udp: Some(connect_udp),
                    }),
                })
            }
            Self::Socks5 { remote_dns, .. } if template.is_none() => {
                Ok(Self::Socks5 { remote_dns, udp })
            }
            _ if template.is_some() => Err(BoxError::from(format!(
                "a proxy path template requires an HTTP proxy scheme, not {scheme}"
            ))),
            _ if udp => Err(BoxError::from(format!(
                "the udp option requires an HTTP or SOCKS5 proxy scheme, not {scheme}"
            ))),
            protocol => Ok(protocol),
        }
    }

    fn from_scheme_name(name: &str) -> Result<Self, BoxError> {
        let http = |version, secure| Self::Http {
            version: Some(version),
            secure,
            masque: None,
        };
        Ok(if name.eq_ignore_ascii_case(H1) {
            http(Version::HTTP_11, true)
        } else if name.eq_ignore_ascii_case(H2) {
            http(Version::HTTP_2, true)
        } else if name.eq_ignore_ascii_case(H2C) {
            http(Version::HTTP_2, false)
        } else if name.eq_ignore_ascii_case(H3) {
            http(Version::HTTP_3, true)
        } else {
            Self::from(Protocol::try_from(name).context("parse the protocol of a proxy scheme")?)
        })
    }

    /// The scheme naming this protocol in a proxy address; see [`Self::try_from_scheme`].
    #[must_use]
    pub fn scheme(&self) -> impl Display {
        Scheme(self)
    }
}

struct Scheme<'a>(&'a ProxyProtocol);

impl Display for Scheme<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ProxyProtocol::Http {
                version, secure, ..
            } => {
                let name = match (*secure, *version) {
                    (false, Some(Version::HTTP_2)) => H2C,
                    (false, _) => Protocol::HTTP_SCHEME,
                    (true, Some(Version::HTTP_11)) => H1,
                    (true, Some(Version::HTTP_2)) => H2,
                    (true, Some(Version::HTTP_3)) => H3,
                    (true, _) => Protocol::HTTPS_SCHEME,
                };
                f.write_str(name)?;
                if self
                    .0
                    .connect_udp()
                    .is_some_and(|connect_udp| connect_udp.template.is_connect_udp_default())
                {
                    write!(f, "+{UDP}")?;
                }
            }
            ProxyProtocol::Socks5 { udp, .. } => {
                f.write_str(self.0.to_protocol().as_str())?;
                if *udp {
                    write!(f, "+{UDP}")?;
                }
            }
            ProxyProtocol::Other(protocol) => f.write_str(protocol.as_str())?,
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http(version: Option<Version>, secure: bool) -> ProxyProtocol {
        ProxyProtocol::Http {
            version,
            secure,
            masque: None,
        }
    }

    fn with_udp(protocol: ProxyProtocol) -> ProxyProtocol {
        match protocol {
            ProxyProtocol::Http {
                version, secure, ..
            } => ProxyProtocol::Http {
                version,
                secure,
                masque: Some(Masque {
                    connect_udp: Some(ConnectUdp::default()),
                }),
            },
            ProxyProtocol::Socks5 { remote_dns, .. } => ProxyProtocol::Socks5 {
                remote_dns,
                udp: true,
            },
            other @ ProxyProtocol::Other(_) => other,
        }
    }

    #[test]
    fn a_scheme_names_how_a_proxy_is_reached() {
        for (scheme, protocol) in [
            ("http", http(Some(Version::HTTP_11), false)),
            ("h2c", http(Some(Version::HTTP_2), false)),
            ("https", http(None, true)),
            ("h1", http(Some(Version::HTTP_11), true)),
            ("h2", http(Some(Version::HTTP_2), true)),
            ("h3", http(Some(Version::HTTP_3), true)),
            ("socks5", ProxyProtocol::SOCKS5),
            ("socks5h", ProxyProtocol::SOCKS5H),
            ("h3+udp", with_udp(http(Some(Version::HTTP_3), true))),
            ("https+udp", with_udp(http(None, true))),
            ("h2c+udp", with_udp(http(Some(Version::HTTP_2), false))),
            ("socks5+udp", with_udp(ProxyProtocol::SOCKS5)),
            ("socks5h+udp", with_udp(ProxyProtocol::SOCKS5H)),
        ] {
            assert_eq!(
                ProxyProtocol::try_from_scheme(scheme).unwrap(),
                protocol,
                "{scheme}"
            );
            assert_eq!(protocol.scheme().to_string(), scheme, "{scheme}");
        }
    }

    #[test]
    fn a_path_offers_connect_udp_on_that_template() {
        let template = "/t/{target_host}/{target_port}/";
        for scheme in ["https", "h2", "h3", "h3+udp", "http"] {
            let protocol = ProxyProtocol::try_from_scheme_and_path(scheme, template).unwrap();
            assert_eq!(
                protocol.connect_udp().map(|udp| udp.template.as_str()),
                Some(template),
                "{scheme}"
            );
            assert_eq!(
                protocol.http_version(),
                ProxyProtocol::try_from_scheme(scheme)
                    .unwrap()
                    .http_version(),
                "{scheme}"
            );
        }
    }

    #[test]
    fn invalid_schemes_are_refused() {
        for scheme in [
            "https+h2",
            "h3+udp+udp",
            "socks5+h2",
            "socks5h+tcp",
            "warp+udp",
        ] {
            assert!(
                ProxyProtocol::try_from_scheme(scheme).is_err(),
                "{scheme} parsed"
            );
        }
        ProxyProtocol::try_from_scheme_and_path("socks5", "/t/{target_host}/{target_port}/")
            .unwrap_err();
    }
}
