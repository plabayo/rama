use serde::Deserialize;
use std::{collections::HashMap, net::SocketAddr};

/// A Static DNS resolver mapping that resolves host names to Socket addresses.
///
/// It is not meant to be created directly,
/// but instead it it used internally only to parse from the header.
#[derive(Debug, Clone)]
pub(crate) struct DnsMap {
    map: HashMap<String, SocketAddr>,
}

impl<'a> Deserialize<'a> for DnsMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        Ok(Self {
            map: HashMap::deserialize(deserializer)?,
        })
    }
}

impl DnsMap {
    /// Lookup a host name and return the IP address,
    /// if the host name is not found, return `None`.
    pub(crate) fn lookup_host(&self, host: impl AsRef<str>) -> Option<SocketAddr> {
        self.map.get(host.as_ref()).cloned()
    }
}
