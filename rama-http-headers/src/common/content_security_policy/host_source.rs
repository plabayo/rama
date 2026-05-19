use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use rama_net::Protocol;
use rama_net::address::Domain;
use rama_utils::macros::generate_set_and_with;

use crate::Error;

/// Port component of a CSP [`HostSource`].
///
/// Either a concrete port number or the `*` token which the spec allows
/// to mean "any port".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostSourcePort {
    /// A concrete port number, rendered as `:N`.
    Number(u16),
    /// The `*` wildcard, rendered as `:*`.
    Any,
}

impl fmt::Display for HostSourcePort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Number(n) => write!(f, "{n}"),
            Self::Any => f.write_str("*"),
        }
    }
}

/// A CSP `host-source` value: optional scheme, a [`Domain`] (which may
/// itself be a wildcard subdomain), optional port (concrete or `*`),
/// optional path.
///
/// Construct directly from a [`Domain`] for the common case, or via
/// [`HostSource::try_parse`] from a wire-format string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostSource {
    scheme: Option<Protocol>,
    host: Domain,
    port: Option<HostSourcePort>,
    path: Option<Cow<'static, str>>,
}

// TODO: replace the above with Uri? or something like it ,as this is a bit silly..

impl HostSource {
    /// Wrap a bare [`Domain`] — no scheme, port, or path.
    #[must_use]
    pub fn new(host: Domain) -> Self {
        Self {
            scheme: None,
            host,
            port: None,
            path: None,
        }
    }

    /// Parse a CSP host-source from its wire form
    /// (`[scheme://]host[:port][/path]`). Hosts with a leading `*.`
    /// wildcard, port `*`, and arbitrary path tails are all accepted.
    pub fn try_parse(s: &str) -> Result<Self, Error> {
        let (scheme, rest) = match s.find("://") {
            Some(idx) => {
                let proto = Protocol::try_from(&s[..idx]).map_err(|_err| Error::invalid())?;
                (Some(proto), &s[idx + 3..])
            }
            None => (None, s),
        };
        let (host_port, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], Some(Cow::Owned(rest[idx..].to_owned()))),
            None => (rest, None),
        };
        let (host_str, port) = match host_port.rfind(':') {
            Some(idx) => {
                let port_str = &host_port[idx + 1..];
                let parsed = if port_str == "*" {
                    Some(HostSourcePort::Any)
                } else {
                    let n: u16 = port_str.parse().map_err(|_err| Error::invalid())?;
                    Some(HostSourcePort::Number(n))
                };
                (&host_port[..idx], parsed)
            }
            None => (host_port, None),
        };
        let host = Domain::try_from(host_str).map_err(|_err| Error::invalid())?;
        Ok(Self {
            scheme,
            host,
            port,
            path,
        })
    }

    /// The optional scheme component.
    pub fn scheme(&self) -> Option<&Protocol> {
        self.scheme.as_ref()
    }

    /// The host (domain) component.
    pub fn host(&self) -> &Domain {
        &self.host
    }

    /// The optional port component.
    pub fn port(&self) -> Option<HostSourcePort> {
        self.port
    }

    /// The optional path component (kept verbatim, including the
    /// leading `/`).
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    generate_set_and_with! {
        /// Attach a scheme component (rendered as `<scheme>://…`).
        pub fn scheme(mut self, scheme: Protocol) -> Self {
            self.scheme = Some(scheme);
            self
        }
    }

    generate_set_and_with! {
        /// Attach a concrete port component.
        pub fn port(mut self, port: u16) -> Self {
            self.port = Some(HostSourcePort::Number(port));
            self
        }
    }

    generate_set_and_with! {
        /// Attach the `*` (any-port) component.
        pub fn any_port(mut self) -> Self {
            self.port = Some(HostSourcePort::Any);
            self
        }
    }

    generate_set_and_with! {
        /// Attach a path component (will be rendered verbatim — caller
        /// keeps the leading `/`).
        pub fn path(mut self, path: impl Into<Cow<'static, str>>) -> Self {
            self.path = Some(path.into());
            self
        }
    }
}

impl From<Domain> for HostSource {
    fn from(host: Domain) -> Self {
        Self::new(host)
    }
}

impl<'a> TryFrom<&'a str> for HostSource {
    type Error = Error;
    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        Self::try_parse(s)
    }
}

impl TryFrom<String> for HostSource {
    type Error = Error;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::try_parse(&s)
    }
}

impl FromStr for HostSource {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_parse(s)
    }
}

impl fmt::Display for HostSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(scheme) = &self.scheme {
            write!(f, "{}://", scheme.as_str())?;
        }
        write!(f, "{}", self.host)?;
        if let Some(port) = &self.port {
            write!(f, ":{port}")?;
        }
        if let Some(path) = &self.path {
            f.write_str(path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_domain_round_trips() {
        let h = HostSource::try_parse("example.com").unwrap();
        assert_eq!(h.to_string(), "example.com");
        assert_eq!(h.scheme(), None);
        assert_eq!(h.port(), None);
        assert_eq!(h.path(), None);
    }

    #[test]
    fn scheme_plus_host_round_trips() {
        let h = HostSource::try_parse("https://raw.githubusercontent.com").unwrap();
        assert_eq!(h.to_string(), "https://raw.githubusercontent.com");
        assert_eq!(h.scheme().unwrap().as_str(), "https");
    }

    #[test]
    fn full_form_round_trips() {
        let h = HostSource::try_parse("https://*.example.com:8443/api/*").unwrap();
        assert_eq!(h.to_string(), "https://*.example.com:8443/api/*");
        assert!(h.host().is_wildcard());
        assert_eq!(h.port(), Some(HostSourcePort::Number(8443)));
        assert_eq!(h.path(), Some("/api/*"));
    }

    #[test]
    fn any_port_round_trips() {
        let h = HostSource::try_parse("https://example.com:*").unwrap();
        assert_eq!(h.to_string(), "https://example.com:*");
        assert_eq!(h.port(), Some(HostSourcePort::Any));
    }

    #[test]
    fn builder_assembles_components() {
        let h = HostSource::new(Domain::from_static("example.com"))
            .with_scheme(Protocol::HTTPS)
            .with_port(8443)
            .with_path("/api/");
        assert_eq!(h.to_string(), "https://example.com:8443/api/");
    }

    #[test]
    fn rejects_malformed_scheme() {
        HostSource::try_parse("ht tp://example.com").unwrap_err();
    }

    #[test]
    fn rejects_malformed_port() {
        HostSource::try_parse("example.com:abc").unwrap_err();
        HostSource::try_parse("example.com:99999").unwrap_err();
    }
}
