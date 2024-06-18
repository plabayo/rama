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
    by_node: Option<NodeId>,
    for_node: Option<NodeId>,
    authority: Option<ForwardedAuthority>,
    proto: Option<Protocol>,

    // not expected, but if used these parameters (keys)
    // should be registered ideally also in
    // <https://www.iana.org/assignments/http-parameters/http-parameters.xhtml#forwarded>
    extensions: Option<HashMap<String, ExtensionValue>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExtensionValue {
    value: String,
    quoted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForwardedAuthority {
    host: Host,
    port: Option<u16>,
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
        if s.is_empty() {
            return Err(OpaqueError::from_display(
                "empty str is not a valid Forwarded Element",
            ));
        }

        let mut el = ForwardedElement {
            by_node: None,
            for_node: None,
            authority: None,
            proto: None,
            extensions: None,
        };

        for pair_s in s.split(';') {
            let mut pair_it = pair_s.split('=').map(str::trim);

            let token = pair_it.next().ok_or_else(|| {
                OpaqueError::from_display("Forwarded Element pair is missing token")
            })?;
            let value = pair_it
                .next()
                .ok_or_else(|| OpaqueError::from_display("Forwarded Element is missing value"))?;

            if let Some(some) = pair_it.next() {
                return Err(OpaqueError::from_display(format!(
                    "Forwarded Element pair has more than two items, trailer: {some}"
                )));
            }

            let (value, value_quoted) = if value.starts_with('"') {
                let value = value
                    .strip_suffix('"')
                    .and_then(|value| value.strip_prefix('"'))
                    .ok_or_else(|| {
                        OpaqueError::from_display(format!(
                            "Forwarded Element pair has invalid quoted value: {value}"
                        ))
                    })?;
                (value, true)
            } else {
                (value, false)
            };

            // as defined in <https://datatracker.ietf.org/doc/html/rfc7239#section-4>:
            //
            // > Note that as ":" and "[]" are not valid characters in "token", IPv6
            // > addresses are written as "quoted-string"
            // >
            // > cfr: <https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6>
            // >
            // > remark: we do not apply any validation here
            if !value_quoted && value.contains(['[', ']', ':']) {
                return Err(OpaqueError::from_display(format!("Forwarded Element pair's value was expected to be a quoted string due to the chars it contains: {value}")));
            }

            match_ignore_ascii_case_str! {
                match(token) {
                    "for" => if el.for_node.is_some() {
                        return Err(OpaqueError::from_display("Forwarded Element can only contain one 'for' property"));
                    } else {
                        el.for_node = Some(NodeId::try_from(value).context("parse Forwarded Element 'for' node")?);
                    },
                    "host" => if el.authority.is_some() {
                        return Err(OpaqueError::from_display("Forwarded Element can only contain one 'host' property"));
                    } else {
                        el.authority = Some(value.parse().context("parse Forwarded Element 'host' authority")?);
                    },
                    "by" => if el.by_node.is_some() {
                        return Err(OpaqueError::from_display("Forwarded Element can only contain one 'by' property"));
                    } else {
                        el.by_node = Some(NodeId::try_from(value).context("parse Forwarded Element 'by' node")?);
                    },
                    "proto" => if el.proto.is_some() {
                        return Err(OpaqueError::from_display("Forwarded Element can only contain one 'proto' property"));
                    } else {
                        el.proto = Some(Protocol::try_from(value).context("parse Forwarded Element 'proto' protocol")?);
                    },
                    _ => {
                        // token and value validated according to https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6
                        if token.bytes().any(|b| !(32..127).contains(&b)) {
                            return Err(OpaqueError::from_display("Forwarded Element: invalid extension: token is not a valid Field Value Component"));
                        }
                        if value.bytes().any(|b| !(32..127).contains(&b)) {
                            return Err(OpaqueError::from_display("Forwarded Element: invalid extension: value is not a valid Field Value Component"));
                        }
                        el.extensions.get_or_insert_with(Default::default)
                            .insert(token.trim().to_owned(), ExtensionValue{
                                value: value.to_owned(),
                                quoted: value_quoted,
                            });
                    }
                }
            }
        }

        if el.for_node.is_none()
            && el.by_node.is_none()
            && el.authority.is_none()
            && el.proto.is_none()
        {
            return Err(OpaqueError::from_display(
                "invalid forwarded element: none of required properties are set",
            ));
        }

        Ok(el)
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
