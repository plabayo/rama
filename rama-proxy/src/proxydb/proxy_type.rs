use std::{fmt, str::FromStr};

use rama_core::error::{BoxError, BoxErrorExt as _};
use rama_utils::macros::{match_ignore_ascii_case_str, serde_str::impl_serde_str};

/// Where the IP of a [`Proxy`](super::Proxy) comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyType {
    /// An IP of a hosting provider.
    Datacenter,
    /// An IP a consumer ISP gives to a home connection.
    Residential,
    /// An IP of a mobile network.
    Mobile,
    /// A static IP hosted in a datacenter but registered to a consumer ISP.
    Isp,
}

impl ProxyType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Datacenter => "datacenter",
            Self::Residential => "residential",
            Self::Mobile => "mobile",
            Self::Isp => "isp",
        }
    }
}

impl fmt::Display for ProxyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProxyType {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match_ignore_ascii_case_str! {
            match(s) {
                "datacenter" => Ok(Self::Datacenter),
                "residential" => Ok(Self::Residential),
                "mobile" => Ok(Self::Mobile),
                "isp" => Ok(Self::Isp),
                _ => Err(BoxError::from_static_str("unknown proxy type")),
            }
        }
    }
}

impl_serde_str!(display ProxyType);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_proxy_type_round_trips_as_its_name() {
        for kind in [
            ProxyType::Datacenter,
            ProxyType::Residential,
            ProxyType::Mobile,
            ProxyType::Isp,
        ] {
            assert_eq!(kind.as_str().parse::<ProxyType>().unwrap(), kind);
            assert_eq!(
                kind.as_str().to_uppercase().parse::<ProxyType>().unwrap(),
                kind
            );
        }
        "hosting".parse::<ProxyType>().unwrap_err();
    }
}
