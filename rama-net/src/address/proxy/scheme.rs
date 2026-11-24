use core::fmt::{self, Display};

use rama_core::error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _};

use rama_utils::{macros::match_ignore_ascii_case_str, str::smol_str::SmolStr};

use super::{ProxyPathTemplate, ProxyProtocol};
use crate::{Protocol, http::Version, transport::TransportProtocol};

const H1: &str = "h1";
const H2: &str = "h2";
const H2C: &str = "h2c";
const H3: &str = "h3";
const TCP: &str = "tcp";
const TLS: &str = "tls";
const UDP: &str = "udp";

impl ProxyProtocol {
    /// Parse the scheme of a proxy address, such as `https`, `h3+udp` or `socks5h+tls`.
    ///
    /// A scheme is a base protocol, followed by options after `+` in any order:
    ///
    /// | base | proxy |
    /// |---|---|
    /// | `http` | HTTP/1.1, plaintext |
    /// | `h2c` | HTTP/2, plaintext |
    /// | `https` | HTTP over TLS: HTTP/3 when the proxy advertises it, else ALPN over TCP |
    /// | `h1`, `h2` | HTTP/1.1 or HTTP/2 over TLS, over TCP |
    /// | `h3` | HTTP/3, over QUIC |
    /// | `socks5` | SOCKS5, target names resolved locally |
    /// | `socks5h` | SOCKS5, target names resolved by the proxy |
    ///
    /// | option | on | meaning |
    /// |---|---|---|
    /// | `+udp` | HTTP | also CONNECT-UDP, on the default template |
    /// | `+udp` | SOCKS5 | UDP ASSOCIATE only |
    /// | `+tcp` | SOCKS5 | CONNECT only |
    /// | `+tls` | SOCKS5 | TLS to the proxy; with UDP ASSOCIATE only the control connection |
    ///
    /// A protocol with a secure name of its own uses that name, so an HTTP proxy has no
    /// `+tls`: it is `https`, `h1`, `h2` or `h3`. An HTTP proxy carries TCP with CONNECT,
    /// and UDP or IP with MASQUE only when its address says where the tunnels are: `+udp`,
    /// or a path as the template (see [`Self::try_from_scheme_and_path`]).
    ///
    /// Any other scheme is a [`Self::Custom`] protocol, kept as is and not interpreted.
    ///
    /// Not every protocol round-trips through its scheme: a plaintext HTTP proxy with no
    /// version prints as `http`, which parses back as HTTP/1.1, and a custom template
    /// lives in the path of the address, not in its scheme.
    pub fn try_from_scheme(scheme: &str) -> Result<Self, BoxError> {
        Self::try_from_scheme_and_path(scheme, "")
    }

    /// [`Self::try_from_scheme`] with the path of the proxy address: the template an HTTP
    /// proxy offers its MASQUE tunnels on.
    pub fn try_from_scheme_and_path(scheme: &str, path: &str) -> Result<Self, BoxError> {
        let mut parts = scheme.split('+');
        let name = parts.next().unwrap_or_default();
        let mut only = None;
        let mut tls = false;
        for option in parts {
            let duplicate = match_ignore_ascii_case_str! {
                match(option) {
                    "tcp" => only.replace(TransportProtocol::Tcp).is_some(),
                    "udp" => only.replace(TransportProtocol::Udp).is_some(),
                    "tls" => core::mem::replace(&mut tls, true),
                    _ => {
                        return Err(BoxError::from_static_str("unknown proxy scheme option")
                            .context_str_field("option", SmolStr::new(option)));
                    }
                }
            };
            if duplicate {
                return Err(
                    BoxError::from_static_str("proxy scheme option given more than once")
                        .context_str_field("scheme", SmolStr::new(scheme)),
                );
            }
        }

        let path_template = if path.is_empty() || path == "/" {
            None
        } else {
            Some(ProxyPathTemplate::try_new(path).context("parse proxy path template")?)
        };

        match Self::from_scheme_name(name)? {
            Self::Http { .. } if tls => Err(BoxError::from_static_str(
                "an HTTP proxy names TLS with its scheme: use https, h1, h2 or h3 instead of +tls",
            )
            .context_str_field("scheme", SmolStr::new(scheme))),
            Self::Http {
                version, secure, ..
            } if only != Some(TransportProtocol::Tcp) => {
                let path_template = match (only, path_template) {
                    (Some(_), Some(_)) => {
                        return Err(BoxError::from_static_str(
                            "`+udp` already means the default CONNECT-UDP template: use either `+udp` or a path template, not both",
                        )
                        .context_str_field("scheme", SmolStr::new(scheme)));
                    }
                    (Some(_), None) => Some(ProxyPathTemplate::connect_udp_default()),
                    (None, path_template) => path_template,
                };
                Ok(Self::Http {
                    version,
                    secure,
                    path_template,
                })
            }
            Self::Socks5 { remote_dns, .. } if path_template.is_none() => Ok(Self::Socks5 {
                remote_dns,
                transport: only,
                secure: tls,
            }),
            Self::Custom(custom) if only.is_none() && !tls && path_template.is_none() => {
                Ok(Self::Custom(custom))
            }
            _ if path_template.is_some() => Err(BoxError::from_static_str(
                "a proxy path template requires an HTTP proxy scheme",
            )
            .context_str_field("scheme", SmolStr::new(scheme))),
            _ => Err(
                BoxError::from_static_str("scheme options require a SOCKS5 proxy scheme")
                    .context_str_field("scheme", SmolStr::new(scheme)),
            ),
        }
    }

    fn from_scheme_name(name: &str) -> Result<Self, BoxError> {
        let http = |version, secure| Self::Http {
            version: Some(version),
            secure,
            path_template: None,
        };
        let protocol = Protocol::try_from(name).context("parse the protocol of a proxy scheme")?;
        Ok(match_ignore_ascii_case_str! {
            match(protocol.as_str()) {
                "h1" => http(Version::HTTP_11, true),
                "h2" => http(Version::HTTP_2, true),
                "h2c" => http(Version::HTTP_2, false),
                "h3" => http(Version::HTTP_3, true),
                "http" => Self::HTTP,
                "https" => Self::HTTPS,
                "socks5" => Self::SOCKS5,
                "socks5h" => Self::SOCKS5H,
                "masque" => return Err(BoxError::from_static_str(
                    "masque is not a proxy scheme: use h3+udp:// or an http scheme with a path template",
                )),
                _ => Self::Custom(SmolStr::new(protocol.as_str())),
            }
        })
    }
}

/// Writes the scheme naming this protocol in a proxy address; see
/// [`ProxyProtocol::try_from_scheme`].
impl Display for ProxyProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http {
                version,
                secure,
                path_template,
            } => {
                f.write_str(match (*secure, *version) {
                    (false, Some(Version::HTTP_2)) => H2C,
                    (false, _) => Protocol::HTTP_SCHEME,
                    (true, Some(Version::HTTP_11)) => H1,
                    (true, Some(Version::HTTP_2)) => H2,
                    (true, Some(Version::HTTP_3)) => H3,
                    (true, _) => Protocol::HTTPS_SCHEME,
                })?;
                if path_template
                    .as_ref()
                    .is_some_and(ProxyPathTemplate::is_connect_udp_default)
                {
                    write!(f, "+{UDP}")?;
                }
                Ok(())
            }
            Self::Socks5 {
                remote_dns,
                transport,
                secure,
            } => {
                f.write_str(if *remote_dns {
                    Protocol::SOCKS5H_SCHEME
                } else {
                    Protocol::SOCKS5_SCHEME
                })?;
                match transport {
                    Some(TransportProtocol::Tcp) => write!(f, "+{TCP}")?,
                    Some(TransportProtocol::Udp) => write!(f, "+{UDP}")?,
                    None => {}
                }
                if *secure {
                    write!(f, "+{TLS}")?;
                }
                Ok(())
            }
            Self::Custom(scheme) => f.write_str(scheme),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http(version: Option<Version>, secure: bool) -> ProxyProtocol {
        ProxyProtocol::Http {
            version,
            secure,
            path_template: None,
        }
    }

    fn socks5(remote_dns: bool, transport: Option<TransportProtocol>) -> ProxyProtocol {
        ProxyProtocol::Socks5 {
            remote_dns,
            transport,
            secure: false,
        }
    }

    fn socks5_tls(remote_dns: bool, transport: Option<TransportProtocol>) -> ProxyProtocol {
        ProxyProtocol::Socks5 {
            remote_dns,
            transport,
            secure: true,
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
            ("socks5+tcp", socks5(false, Some(TransportProtocol::Tcp))),
            ("socks5+udp", socks5(false, Some(TransportProtocol::Udp))),
            ("socks5h+udp", socks5(true, Some(TransportProtocol::Udp))),
            ("socks5+tls", socks5_tls(false, None)),
            (
                "socks5h+udp+tls",
                socks5_tls(true, Some(TransportProtocol::Udp)),
            ),
            (
                "h3+udp",
                ProxyProtocol::Http {
                    version: Some(Version::HTTP_3),
                    secure: true,
                    path_template: Some(ProxyPathTemplate::connect_udp_default()),
                },
            ),
        ] {
            assert_eq!(
                ProxyProtocol::try_from_scheme(scheme).unwrap(),
                protocol,
                "{scheme}"
            );
            assert_eq!(protocol.to_string(), scheme, "{scheme}");
        }
    }

    #[test]
    fn a_path_is_the_masque_template() {
        for (path, udp) in [
            ("/t/{target_host}/{target_port}/", true),
            ("/t/ip/{target}/{ipproto}/", false),
            ("/.well-known/masque/ip/", false),
        ] {
            for scheme in ["https", "h2", "h3", "http"] {
                let protocol = ProxyProtocol::try_from_scheme_and_path(scheme, path).unwrap();
                assert_eq!(
                    protocol.path_template().map(ProxyPathTemplate::as_str),
                    Some(path),
                    "{scheme}"
                );
                assert_eq!(
                    protocol.carries(TransportProtocol::Udp),
                    udp,
                    "{scheme} {path}"
                );
                assert_eq!(
                    protocol.path_template().unwrap().is_connect_ip(),
                    !udp,
                    "{scheme} {path}"
                );
            }
        }
    }

    #[test]
    fn options_are_accepted_in_any_order() {
        assert_eq!(
            ProxyProtocol::try_from_scheme("socks5h+tls+udp").unwrap(),
            socks5_tls(true, Some(TransportProtocol::Udp)),
        );
    }

    #[test]
    fn an_http_proxy_names_tls_with_its_scheme() {
        for scheme in ["http+tls", "h2c+tls", "https+tls", "h3+tls"] {
            let error = ProxyProtocol::try_from_scheme(scheme)
                .unwrap_err()
                .to_string();
            assert!(error.contains("https"), "{scheme}: {error}");
        }
    }

    #[test]
    fn invalid_schemes_are_refused() {
        for scheme in [
            "https+h2",
            "h3+tcp",
            "h3+udp+udp",
            "socks5+udp+udp",
            "socks5+tcp+udp",
            "socks5+tls+tls",
            "socks5+h2",
            "warp+udp",
        ] {
            assert!(
                ProxyProtocol::try_from_scheme(scheme).is_err(),
                "{scheme} parsed"
            );
        }
        let masque = ProxyProtocol::try_from_scheme("masque")
            .unwrap_err()
            .to_string();
        assert!(masque.contains("h3+udp"), "{masque}");
        ProxyProtocol::try_from_scheme_and_path("masque", "/t/{target_host}/{target_port}/")
            .unwrap_err();
        ProxyProtocol::try_from_scheme_and_path("socks5", "/t/{target_host}/{target_port}/")
            .unwrap_err();
        ProxyProtocol::try_from_scheme_and_path("h3", "/t/{target_host}/").unwrap_err();
        ProxyProtocol::try_from_scheme_and_path("h3+udp", "/t/{target_host}/{target_port}/")
            .unwrap_err();
    }
}
