use super::{DnsResolver, DnsService};
use crate::{net::address::Authority, service::Context};
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

impl<State> DnsService<State> for DnsMap
where
    State: Send + Sync + 'static,
{
    fn lookup(&self, _ctx: &Context<State>, authority: Authority) -> impl DnsResolver {
        self.map
            .get(&authority)
            .cloned()
            .unwrap_or_default()
            .into_iter()
    }
}
