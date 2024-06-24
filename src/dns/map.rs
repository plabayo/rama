use super::DnsService;
use crate::net::address::Authority;
use serde::Deserialize;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

/// A Static DNS resolver mapping that resolves host names to Socket addresses.
///
/// It is not meant to be created directly,
/// but instead it it used internally only to parse from the header.
#[derive(Debug, Clone)]
pub struct DnsMap {
    map: Arc<HashMap<Authority, Vec<SocketAddr>>>,
}

impl DnsMap {
    /// Creates a new `DnsMap` from a given map.
    pub fn new(map: HashMap<Authority, Vec<SocketAddr>>) -> Self {
        Self { map: Arc::new(map) }
    }
}

impl<'a> Deserialize<'a> for DnsMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let map = HashMap::deserialize(deserializer)?;
        Ok(Self::new(map))
    }
}

impl DnsService for DnsMap {
    type Resolver = std::vec::IntoIter<SocketAddr>;

    fn lookup(&self, authority: Authority) -> Self::Resolver {
        self.map
            .get(&authority)
            .cloned()
            .unwrap_or_default()
            .into_iter()
    }
}
