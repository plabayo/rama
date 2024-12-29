use std::fmt;
use std::str::FromStr;
use rama_core::error::{ErrorContext, OpaqueError};
use crate::address::{parse_utils, Domain};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainAddress {
    domain: Domain,
    port: u16,
}

impl DomainAddress {

    pub const fn new(domain: Domain, port: u16) -> Self {
        Self { domain, port }
    }

    pub fn domain(&self) -> &Domain {
        &self.domain
    }

    pub fn into_domain(self) -> Domain {
       self.domain
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn into_parts(self) -> (Domain, u16) {
        (self.domain, self.port)
    }
}

impl From<(Domain, u16)> for DomainAddress {
    #[inline]
    fn from((domain, port): (Domain, u16)) -> Self {
        Self::new(domain, port)
    }
}

impl fmt::Display for DomainAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.domain, self.port)
    }
}

impl FromStr for DomainAddress {
    type Err = OpaqueError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
       DomainAddress::try_from(s)
    }
}

impl TryFrom<&str> for DomainAddress {
    type Error = OpaqueError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
       let (domain, port) = parse_utils::split_port_from_str(s)?;
       let domain = Domain::from_str(domain)?;
       Ok(Self::new(domain, port))
    }
}

impl TryFrom<String> for DomainAddress {
    type Error = OpaqueError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let (domain, port) = parse_utils::split_port_from_str(&s)?;
        let domain = Domain::from_str(domain)?;
        Ok(Self::new(domain, port))
    }
}
impl TryFrom<Vec<u8>> for DomainAddress {
    type Error = OpaqueError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let s = String::from_utf8(bytes).context("parse domain_address from bytes")?;
        s.try_into()
    }
}

impl TryFrom<&[u8]> for DomainAddress {
    type Error = OpaqueError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let s = std::str::from_utf8(bytes).context("parse domain_address from bytes")?;
        s.try_into()
    }
}

impl serde::Serialize for DomainAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let address = self.to_string();
        address.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for DomainAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.try_into().map_err(serde::de::Error::custom)
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_address() {
        todo!()
    }
}

