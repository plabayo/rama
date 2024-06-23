use crate::error::{ErrorContext, OpaqueError};
use crate::http::header::{CF_CONNECTING_IP, CLIENT_IP, TRUE_CLIENT_IP, X_CLIENT_IP, X_REAL_IP};
use crate::http::headers::Header;
use crate::http::{HeaderName, HeaderValue};
use crate::net::forwarded::{ForwardedElement, NodeId};
use paste::paste;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientAddr {
    ip: IpAddr,
    port: Option<u16>,
}

impl fmt::Display for ClientAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.port {
            Some(port) => match &self.ip {
                IpAddr::V6(ip) => write!(f, "[{ip}]:{port}"),
                IpAddr::V4(ip) => write!(f, "{ip}:{port}"),
            },
            None => self.ip.fmt(f),
        }
    }
}

impl std::str::FromStr for ClientAddr {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(ip) = s.parse() {
            // first try host alone, as it is most common,
            // and also prevents IPv6 to be seen by default with port
            return Ok(ClientAddr { ip, port: None });
        }

        let (s, port) = try_to_split_num_port_from_str(s);
        let ip = try_to_parse_str_to_ip(s).context("parse forwarded ip")?;

        match ip {
            IpAddr::V6(_) if port.is_some() && !s.starts_with('[') => Err(
                OpaqueError::from_display("missing brackets for IPv6 address with port"),
            ),
            _ => Ok(ClientAddr { ip, port }),
        }
    }
}

fn try_to_parse_str_to_ip(value: &str) -> Option<IpAddr> {
    if value.starts_with('[') || value.ends_with(']') {
        let value = value
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))?;
        Some(IpAddr::V6(value.parse::<Ipv6Addr>().ok()?))
    } else {
        value.parse::<IpAddr>().ok()
    }
}

fn try_to_split_num_port_from_str(s: &str) -> (&str, Option<u16>) {
    if let Some(colon) = s.as_bytes().iter().rposition(|c| *c == b':') {
        match s[colon + 1..].parse() {
            Ok(port) => (&s[..colon], Some(port)),
            Err(_) => (s, None),
        }
    } else {
        (s, None)
    }
}

macro_rules! exotic_forward_ip_headers {
    (
        $(
            #[doc = $desc:literal]
            #[header = $header:ident]
            $(#[$outer:meta])*
            pub struct $name:ident;
        )+
    ) => {
        $(
            #[derive(Debug, Clone, PartialEq, Eq)]
            #[doc = $desc]
            $(#[$outer])*
            pub struct $name(ClientAddr);

            impl Header for $name {
                fn name() -> &'static HeaderName {
                    &$header
                }

                fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(
                    values: &mut I,
                ) -> Result<Self, headers::Error> {
                    Ok($name(
                        values
                            .next()
                            .and_then(|value| value.to_str().ok().and_then(|s| s.parse().ok()))
                            .ok_or_else(crate::http::headers::Error::invalid)?,
                    ))
                }

                fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
                    let s = self.0.to_string();
                    values.extend(Some(HeaderValue::from_str(&s).unwrap()))
                }
            }

            impl super::ForwardHeader for $name {
                fn try_from_forwarded<'a, I>(input: I) -> Option<Self>
                where
                    I: IntoIterator<Item = &'a ForwardedElement>,
                {
                    let node = input
                        .into_iter()
                        .next()?
                        .ref_forwarded_for()?;
                    let ip = node.ip()?;
                    let port = node.port();
                    Some($name(ClientAddr { ip, port }))
                }
            }

            paste! {
                impl IntoIterator for $name {
                    type Item = ForwardedElement;
                    type IntoIter = [<$name Iterator>];

                    fn into_iter(self) -> Self::IntoIter {
                        [<$name Iterator>](Some(self.0))
                    }
                }

                #[derive(Debug, Clone)]
                #[doc = concat!("An iterator over the `", stringify!($name), "` header's elements.")]
                pub struct [<$name Iterator>](Option<ClientAddr>);

                impl Iterator for [<$name Iterator>] {
                    type Item = ForwardedElement;

                    fn next(&mut self) -> Option<Self::Item> {
                        self.0.take().map(|addr| {
                            let node: NodeId = (addr.ip, addr.port).into();
                            ForwardedElement::forwarded_for(node)
                        })
                    }
                }
            }
        )+
    };
}

exotic_forward_ip_headers! {
    #[doc = "CF-Connecting-IP provides the client IP address connecting to Cloudflare to the origin web server."]
    #[header = CF_CONNECTING_IP]
    pub struct CFConnectingIp;

    #[doc = "True-Client-IP provides the original client IP address to the origin web server (Cloudflare Enterprise)."]
    #[header = TRUE_CLIENT_IP]
    pub struct TrueClientIp;

    #[doc = "X-Real-Ip is used by some proxy software to set the real client Ip Address (known to them)."]
    #[header = X_REAL_IP]
    pub struct XRealIp;


    #[doc = "Client-Ip is used by some proxy software to set the real client Ip Address (known to them)."]
    #[header = CLIENT_IP]
    pub struct ClientIp;

    #[doc = "X-Client-Ip is used by some proxy software to set the real client Ip Address (known to them)."]
    #[header = X_CLIENT_IP]
    pub struct XClientIp;
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_headers {
        ($($ty: ident),+ ; $name: ident, $input: expr, $expected: literal) => {
            #[test]
            fn $name() {
                $(
                    assert_eq!(
                        $ty::decode(
                            &mut $input
                                .into_iter()
                                .map(|s| HeaderValue::from_bytes(s.as_bytes()).unwrap())
                                .collect::<Vec<_>>()
                                .iter()
                        )
                        .unwrap(),
                        $ty($expected.parse().unwrap()),
                    );
                )+
            }
        };
    }

    macro_rules! test_header {
        ($name: ident, $input: expr, $expected: literal) => {
            test_headers!(CFConnectingIp, TrueClientIp, XRealIp, ClientIp, XClientIp; $name, $input, $expected);
        };
    }

    // Tests from the Docs
    test_header!(test1, vec!["203.0.113.195"], "203.0.113.195");
    test_header!(test2, vec!["203.0.113.195:80"], "203.0.113.195:80");
    test_header!(
        test3,
        vec!["2001:db8:85a3:8d3:1319:8a2e:370:7348"],
        "2001:db8:85a3:8d3:1319:8a2e:370:7348"
    );
    test_header!(
        test4,
        vec!["[2001:db8:85a3:8d3:1319:8a2e:370:7348]:8080"],
        "[2001:db8:85a3:8d3:1319:8a2e:370:7348]:8080"
    );

    macro_rules! symmetric_test_header {
        ($name: ident) => {
            for input in [
                $name("127.0.0.1:8080".parse().unwrap()),
                $name(
                    "[2001:db8:85a3:8d3:1319:8a2e:370:7348]:8080"
                        .parse()
                        .unwrap(),
                ),
                $name("203.0.113.195".parse().unwrap()),
                $name("203.0.113.195:80".parse().unwrap()),
            ] {
                let mut values = Vec::new();
                input.encode(&mut values);
                assert_eq!($name::decode(&mut values.iter()).unwrap(), input);
            }
        };
    }

    #[test]
    fn test_symmetry_encode() {
        symmetric_test_header!(CFConnectingIp);
        symmetric_test_header!(TrueClientIp);
        symmetric_test_header!(XRealIp);
        symmetric_test_header!(ClientIp);
        symmetric_test_header!(XClientIp);
    }
}
