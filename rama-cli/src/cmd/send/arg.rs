use clap::ValueEnum;
use rama::{
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    net::address::Domain,
};
use std::{fmt, net::IpAddr, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(super) enum TlsVersion {
    #[value(name = TlsVersion::NAME_V10)]
    V10,
    #[value(name = TlsVersion::NAME_V11)]
    V11,
    #[value(name = TlsVersion::NAME_V12)]
    V12,
    #[value(name = TlsVersion::NAME_V13)]
    V13,
}

impl TlsVersion {
    const NAME_V10: &'static str = "1.0";
    const NAME_V11: &'static str = "1.1";
    const NAME_V12: &'static str = "1.2";
    const NAME_V13: &'static str = "1.3";
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V10 => Self::NAME_V10,
            Self::V11 => Self::NAME_V11,
            Self::V12 => Self::NAME_V12,
            Self::V13 => Self::NAME_V13,
        }
        .fmt(f)
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub(super) struct ResolveArg {
    pub(super) host: Option<Domain>,
    pub(super) port: Option<u16>,
    pub(super) addresses: Vec<IpAddr>,
}

impl FromStr for ResolveArg {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut arg = Self {
            host: None,
            port: None,
            addresses: Vec::new(),
        };

        let (raw_host, s) = s.split_once(':').context("split host part")?;
        if !raw_host.is_empty() && raw_host != "*" {
            let host: Domain = raw_host.parse().context("parse host as domain")?;
            if !host
                .suffix()
                .map(|suffix| suffix.chars().all(|c| c.is_alphabetic() || c == '.'))
                .unwrap_or_default()
            {
                return Err(
                    BoxError::from("invalid domain (suffix not found or invalid)")
                        .context_field("host", host),
                );
            }
            arg.host = Some(host);
        }

        let (raw_port, s) = s.split_once(':').context("split port part")?;
        if !raw_port.is_empty() && raw_port != "*" {
            arg.port = Some(raw_port.parse().context("parse port as u16")?);
        }

        for raw_ip in s.split(',') {
            arg.addresses
                .push(raw_ip.parse().context("parse raw addr str as ip")?);
        }

        if arg.addresses.is_empty() {
            return Err(BoxError::from(
                "no addresses found while at least one is required",
            ));
        }

        Ok(arg)
    }
}

#[cfg(test)]
mod tests {
    use rama::net::address::SocketAddress;

    use super::*;

    #[test]
    fn test_resolve_arg_from_str() {
        for (input, expected_value) in [
            ("", None),
            (
                "::127.0.0.1",
                Some(ResolveArg {
                    host: None,
                    port: None,
                    addresses: vec![SocketAddress::local_ipv4(0).ip_addr],
                }),
            ),
            (
                "example.com::127.0.0.1",
                Some(ResolveArg {
                    host: Some(Domain::example()),
                    port: None,
                    addresses: vec![SocketAddress::local_ipv4(0).ip_addr],
                }),
            ),
            (
                "example.com:42:127.0.0.1",
                Some(ResolveArg {
                    host: Some(Domain::example()),
                    port: Some(42),
                    addresses: vec![SocketAddress::local_ipv4(0).ip_addr],
                }),
            ),
            (
                "localhost:42:127.0.0.1",
                Some(ResolveArg {
                    host: Some(Domain::tld_localhost()),
                    port: Some(42),
                    addresses: vec![SocketAddress::local_ipv4(0).ip_addr],
                }),
            ),
            (
                "venndb.internal:42:127.0.0.1",
                Some(ResolveArg {
                    host: Some(Domain::from_static("venndb.internal")),
                    port: Some(42),
                    addresses: vec![SocketAddress::local_ipv4(0).ip_addr],
                }),
            ),
            (
                "www.example.com:8080:::1",
                Some(ResolveArg {
                    host: Some(Domain::from_static("www.example.com")),
                    port: Some(8080),
                    addresses: vec![SocketAddress::local_ipv6(0).ip_addr],
                }),
            ),
            (
                "www.example.co.uk:8080:::1",
                Some(ResolveArg {
                    host: Some(Domain::from_static("www.example.co.uk")),
                    port: Some(8080),
                    addresses: vec![SocketAddress::local_ipv6(0).ip_addr],
                }),
            ),
            (
                "*:8080:::1",
                Some(ResolveArg {
                    host: None,
                    port: Some(8080),
                    addresses: vec![SocketAddress::local_ipv6(0).ip_addr],
                }),
            ),
            (
                "www.example.com:*:::1",
                Some(ResolveArg {
                    host: Some(Domain::from_static("www.example.com")),
                    port: None,
                    addresses: vec![SocketAddress::local_ipv6(0).ip_addr],
                }),
            ),
            (
                "*:*:::1",
                Some(ResolveArg {
                    host: None,
                    port: None,
                    addresses: vec![SocketAddress::local_ipv6(0).ip_addr],
                }),
            ),
            (
                "*::::1",
                Some(ResolveArg {
                    host: None,
                    port: None,
                    addresses: vec![SocketAddress::local_ipv6(0).ip_addr],
                }),
            ),
            (
                ":*:::1",
                Some(ResolveArg {
                    host: None,
                    port: None,
                    addresses: vec![SocketAddress::local_ipv6(0).ip_addr],
                }),
            ),
            (
                "www.example.com:8080:::1,127.0.0.1,127.0.0.2",
                Some(ResolveArg {
                    host: Some(Domain::from_static("www.example.com")),
                    port: Some(8080),
                    addresses: vec![
                        SocketAddress::local_ipv6(0).ip_addr,
                        SocketAddress::local_ipv4(0).ip_addr,
                        [127, 0, 0, 2].into(),
                    ],
                }),
            ),
            ("127.0.0.1:42:127.0.0.1", None),
            ("::1:42:127.0.0.1", None),
            ("42:example.com:127.0.0.1", None),
            ("127.0.0.1:42:example.com", None),
        ] {
            let result: Result<ResolveArg, _> = input.parse();
            match expected_value {
                Some(value) => assert_eq!(Some(value), result.ok(), "input: '{input}'"),
                None => assert!(result.is_err(), "expected error for input: '{input}'"),
            }
        }
    }
}
