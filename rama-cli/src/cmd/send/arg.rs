use clap::ValueEnum;
use rama::{
    error::{ErrorContext as _, OpaqueError},
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
pub(super) struct ResolveArg {
    pub(super) host: Option<Domain>,
    pub(super) port: Option<u16>,
    pub(super) addresses: Vec<IpAddr>,
}

impl FromStr for ResolveArg {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut arg = Self {
            host: None,
            port: None,
            addresses: Vec::new(),
        };

        let (raw_host, s) = s.split_once(':').context("split host part")?;
        if !raw_host.is_empty() && raw_host != "*" {
            arg.host = Some(raw_host.parse().context("parse host as domain")?);
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
            return Err(OpaqueError::from_display(
                "no addresses found while at least one is required",
            ));
        }

        Ok(arg)
    }
}
