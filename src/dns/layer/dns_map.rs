use serde::Deserialize;
use std::{collections::HashMap, net::SocketAddr};

use crate::net::address::Authority;

/// A Static DNS resolver mapping that resolves host names to Socket addresses.
///
/// It is not meant to be created directly,
/// but instead it it used internally only to parse from the header.
#[derive(Debug, Clone)]
pub(crate) struct DnsMap {
    map: HashMap<Authority, SocketAddr>,
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
    pub(crate) fn lookup_authority(&self, authority: &Authority) -> Option<SocketAddr> {
        self.map.get(authority).cloned()
    }
}
