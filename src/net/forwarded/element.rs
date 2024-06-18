use std::{collections::HashMap, net::IpAddr};

use super::NodeId;
use crate::{
    error::{ErrorContext, OpaqueError},
    net::{
        address::{Authority, Host},
        Protocol,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
/// A single entry in the [`Forwarded`] chain.
///
/// [`Forwarded`]: crate::net::forwarded::Forwarded
pub struct ForwardedElement {
    pub(super) by_node: Option<NodeId>,
    pub(super) for_node: Option<NodeId>,
    pub(super) authority: Option<ForwardedAuthority>,
    pub(super) proto: Option<Protocol>,

    // not expected, but if used these parameters (keys)
    // should be registered ideally also in
    // <https://www.iana.org/assignments/http-parameters/http-parameters.xhtml#forwarded>
    pub(super) extensions: Option<HashMap<String, ExtensionValue>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExtensionValue {
    pub(super) value: String,
    pub(super) quoted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ForwardedAuthority {
    pub(super) host: Host,
    pub(super) port: Option<u16>,
}

impl ForwardedElement {
    /// Create a new [`ForwardedElement`] with the "host" parameter set
    /// using the given [`Host`].
    pub fn forwarded_host(host: Host) -> Self {
        Self {
            by_node: None,
            for_node: None,
            authority: Some(ForwardedAuthority { host, port: None }),
            proto: None,
            extensions: None,
        }
    }

    /// Sets the "host" parameter in this [`ForwardedElement`] using
    /// the given [`Host`].
    pub fn set_forwarded_host(&mut self, host: Host) -> &mut Self {
        self.authority = Some(ForwardedAuthority { host, port: None });
        self
    }

    /// Create a new [`ForwardedElement`] with the "host" parameter set
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
            extensions: None,
        }
    }

    /// Sets the "host" parameter in this [`ForwardedElement`] using
    /// the given [`Authority`].
    pub fn set_authority(&mut self, authority: Authority) -> &mut Self {
        let (host, port) = authority.into_parts();
        self.authority = Some(ForwardedAuthority {
            host,
            port: Some(port),
        });
        self
    }

    /// Create a new [`ForwardedElement`] with the "for" parameter
    /// set to the given valid node identifier. Examples are
    /// an Ip Address or Domain, with or without a port.
    pub fn forwarded_for(node_id: impl Into<NodeId>) -> Self {
        Self {
            by_node: None,
            for_node: Some(node_id.into()),
            authority: None,
            proto: None,
            extensions: None,
        }
    }

    /// Sets the "for" parameter for this [`ForwardedElement`] using the given valid node identifier.
    /// Examples are an Ip Address or Domain, with or without a port.
    pub fn set_for(&mut self, node_id: impl Into<NodeId>) -> &mut Self {
        self.for_node = Some(node_id.into());
        self
    }

    /// Create a new [`ForwardedElement`] with the "by" parameter
    /// set to the given valid node identifier. Examples are
    /// an Ip Address or Domain, with or without a port.
    pub fn forwarded_by(node_id: impl Into<NodeId>) -> Self {
        Self {
            by_node: Some(node_id.into()),
            for_node: None,
            authority: None,
            proto: None,
            extensions: None,
        }
    }

    /// Sets the "by" parameter for this [`ForwardedElement`] usin the given valid node identifier.
    /// Examples are an Ip Address or Domain, with or without a port.
    pub fn set_by(&mut self, node_id: impl Into<NodeId>) -> &mut Self {
        self.by_node = Some(node_id.into());
        self
    }

    /// Create a new [`ForwardedElement`] with the "proto" parameter
    /// set to the given valid/recognised [`Protocol`]
    pub fn forwarded_proto(protocol: Protocol) -> Self {
        Self {
            by_node: None,
            for_node: None,
            authority: None,
            proto: Some(protocol),
            extensions: None,
        }
    }

    /// Set the "proto" parameter to the given valid/recognised [`Protocol`].
    pub fn set_proto(&mut self, protocol: Protocol) -> &mut Self {
        self.proto = Some(protocol);
        self
    }
}

impl std::str::FromStr for ForwardedElement {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!();
    }
}

impl std::str::FromStr for ForwardedAuthority {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (s, port) = try_to_split_num_port_from_str(s);
        let host = Host::try_from(s).context("parse forwarded host")?;

        match host {
            Host::Address(IpAddr::V6(_)) if port.is_some() && !s.starts_with('[') => Err(
                OpaqueError::from_display("missing brackets for host IPv6 address with port"),
            ),
            _ => Ok(ForwardedAuthority { host, port }),
        }
    }
}

fn try_to_split_num_port_from_str(s: &str) -> (&str, Option<u16>) {
    if let Some(colon) = s.as_bytes().iter().rposition(|c| *c == b':') {
        match s[colon + 1..].parse() {
            Ok(port) => (&s[..colon], Some(port)),
            Err(_) => (s, None),
        }
    } else {
        (s, None)
    }
}

#[cfg(test)]
mod tests {
    // TODO
}
