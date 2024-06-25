use crate::net::address::Domain;
use serde::Deserialize;
use std::{collections::HashMap, net::IpAddr};

mod layer;
#[doc(inline)]
pub use layer::DnsMapLayer;

mod service;
#[doc(inline)]
pub use service::DnsMapService;

/// A Static DNS resolver mapping that resolves domains to IP addresses.
///
/// It is not meant to be created directly,
/// but instead it it used internally only to parse from the header.
#[derive(Debug, Clone)]
pub(crate) struct DnsMap(pub(crate) HashMap<Domain, Vec<IpAddr>>);

impl<'a> Deserialize<'a> for DnsMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        Ok(Self(HashMap::deserialize(deserializer)?))
    }
}
