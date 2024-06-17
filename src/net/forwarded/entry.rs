use super::NodeId;
use crate::net::{
    address::{Authority, Host},
    Protocol,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A single entry in the [`Forwarded`] chain.
///
/// [`Forwarded`]: crate::net::forwarded::Forwarded
pub struct ForwardedEntry {
    by_node: Option<NodeId>,
    for_node: Option<NodeId>,
    authority: Option<ForwardedAuthority>,
    proto: Option<Protocol>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ForwardedAuthority {
    host: Host,
    port: Option<u16>,
}

impl ForwardedEntry {
    /// Create a new [`ForwardedEntry`] with the "host" parameter set
    /// using the given [`Host`].
    pub fn forwarded_host(host: Host) -> Self {
        Self {
            by_node: None,
            for_node: None,
            authority: Some(ForwardedAuthority { host, port: None }),
            proto: None,
        }
    }

    /// Sets the "host" parameter in this [`ForwardedEntry`] using
    /// the given [`Host`].
    pub fn set_forwarded_host(&mut self, host: Host) -> &mut Self {
        self.authority = Some(ForwardedAuthority { host, port: None });
        self
    }

    /// Create a new [`ForwardedEntry`] with the "host" parameter set
    /// using the given [`Authority`].
    pub fn forwarded_authority(authority: Authority) -> Self {
        let (host, port) = authority.into_parts();
        Self {
            by_node: None,
            for_node: None,
            authority: Some(ForwardedAuthority {
                host,
                port: Some(port),
            }),
            proto: None,
        }
    }

    /// Sets the "host" parameter in this [`ForwardedEntry`] using
    /// the given [`Authority`].
    pub fn set_authority(&mut self, authority: Authority) -> &mut Self {
        let (host, port) = authority.into_parts();
        self.authority = Some(ForwardedAuthority {
            host,
            port: Some(port),
        });
        self
    }

    /// Create a new [`ForwardedEntry`] with the "for" parameter
    /// set to the given valid node identifier. Examples are
    /// an Ip Address or Domain, with or without a port.
    pub fn forwarded_for(node_id: impl Into<NodeId>) -> Self {
        Self {
            by_node: None,
            for_node: Some(node_id.into()),
            authority: None,
            proto: None,
        }
    }

    /// Sets the "for" parameter for this [`ForwardedEntry`] using the given valid node identifier.
    /// Examples are an Ip Address or Domain, with or without a port.
    pub fn set_for(&mut self, node_id: impl Into<NodeId>) -> &mut Self {
        self.for_node = Some(node_id.into());
        self
    }

    /// Create a new [`ForwardedEntry`] with the "by" parameter
    /// set to the given valid node identifier. Examples are
    /// an Ip Address or Domain, with or without a port.
    pub fn forwarded_by(node_id: impl Into<NodeId>) -> Self {
        Self {
            by_node: Some(node_id.into()),
            for_node: None,
            authority: None,
            proto: None,
        }
    }

    /// Sets the "by" parameter for this [`ForwardedEntry`] usin the given valid node identifier.
    /// Examples are an Ip Address or Domain, with or without a port.
    pub fn set_by(&mut self, node_id: impl Into<NodeId>) -> &mut Self {
        self.by_node = Some(node_id.into());
        self
    }

    /// Create a new [`ForwardedEntry`] with the "proto" parameter
    /// set to the given valid/recognised [`Protocol`]
    pub fn forwarded_proto(protocol: Protocol) -> Self {
        Self {
            by_node: None,
            for_node: None,
            authority: None,
            proto: Some(protocol),
        }
    }

    /// Set the "proto" parameter to the given valid/recognised [`Protocol`].
    pub fn set_proto(&mut self, protocol: Protocol) -> &mut Self {
        self.proto = Some(protocol);
        self
    }
}
