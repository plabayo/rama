//! What a PAC script returns: an ordered list of proxies to try.

use std::fmt;
use std::str::FromStr;

use rama_core::error::{BoxError, BoxErrorExt, ErrorContext, ErrorExt};
use rama_core::telemetry::tracing;
use rama_net::{
    Protocol,
    address::{HostWithOptPort, HostWithPort, ProxyAddress},
    client::{ProxyRoute, ProxyRoutes},
};

/// One proxy instruction returned by a PAC script.
///
/// Unsupported tokens (`SOCKS`/`SOCKS4`, vendor extensions) are dropped
/// while parsing, so every directive here is one rama can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacDirective {
    /// Connect to the origin without a proxy.
    Direct,
    /// Proxy over http (`PROXY` / `HTTP` tokens).
    Proxy(HostWithPort),
    /// Proxy over https (`HTTPS` token).
    Https(HostWithPort),
    /// Proxy over socks5 (`SOCKS5` token).
    Socks5(HostWithPort),
}

impl PacDirective {
    /// Proxy over http, the `PROXY` directive.
    #[must_use]
    pub fn proxy(address: impl Into<HostWithPort>) -> Self {
        Self::Proxy(address.into())
    }

    /// Proxy over https, the `HTTPS` directive.
    #[must_use]
    pub fn https(address: impl Into<HostWithPort>) -> Self {
        Self::Https(address.into())
    }

    /// Proxy over socks5, the `SOCKS5` directive.
    #[must_use]
    pub fn socks5(address: impl Into<HostWithPort>) -> Self {
        Self::Socks5(address.into())
    }

    /// The [`ProxyAddress`] to route through, or `None` for
    /// [`PacDirective::Direct`].
    ///
    /// A `SOCKS5` directive becomes [`Protocol::SOCKS5H`]: the proxy
    /// resolves the name, as browsers do. Whether a name is resolved
    /// locally instead is the socks5 connector's configuration, not
    /// something a PAC script expresses.
    #[must_use]
    pub fn proxy_address(&self) -> Option<ProxyAddress> {
        let (protocol, address) = match self {
            Self::Direct => return None,
            Self::Proxy(address) => (Protocol::HTTP, address),
            Self::Https(address) => (Protocol::HTTPS, address),
            Self::Socks5(address) => (Protocol::SOCKS5H, address),
        };
        Some(ProxyAddress {
            protocol: Some(protocol),
            address: address.clone(),
            credential: None,
        })
    }

    /// The [`ProxyRoute`] this directive selects.
    #[must_use]
    pub fn into_proxy_route(self) -> ProxyRoute {
        match self.proxy_address() {
            Some(address) => ProxyRoute::Proxy(address),
            None => ProxyRoute::Direct,
        }
    }

    fn parse(token: &str) -> Result<Option<Self>, BoxError> {
        let mut parts = token.split_ascii_whitespace();
        let Some(keyword) = parts.next() else {
            return Ok(None);
        };

        let (build, default_port): (fn(HostWithPort) -> Self, u16) = if keyword
            .eq_ignore_ascii_case("DIRECT")
        {
            if let Some(unexpected) = parts.next() {
                return Err(BoxError::from_static_str("DIRECT takes no address")
                    .context_str_field("unexpected", unexpected));
            }
            return Ok(Some(Self::Direct));
        } else if keyword.eq_ignore_ascii_case("PROXY") || keyword.eq_ignore_ascii_case("HTTP") {
            (Self::Proxy, Protocol::HTTP_DEFAULT_PORT)
        } else if keyword.eq_ignore_ascii_case("HTTPS") {
            (Self::Https, Protocol::HTTPS_DEFAULT_PORT)
        } else if keyword.eq_ignore_ascii_case("SOCKS5") {
            (Self::Socks5, Protocol::SOCKS5_DEFAULT_PORT)
        } else {
            // browsers skip what they cannot serve (SOCKS4, vendor tokens)
            tracing::debug!(
                pac.directive = %token,
                "skipping unsupported pac directive",
            );
            return Ok(None);
        };

        let address = parts
            .next()
            .context("pac proxy directive is missing its address")?;
        if let Some(unexpected) = parts.next() {
            return Err(BoxError::from_static_str("trailing data in pac directive")
                .context_str_field("unexpected", unexpected));
        }

        // never `Uri::parse`: RFC 3986 reads `example.com:8080` as a scheme
        let address = HostWithOptPort::try_from(address)
            .context("parse pac proxy directive address")?
            .into_host_with_port_or(default_port);

        Ok(Some(build(address)))
    }
}

impl fmt::Display for PacDirective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => f.write_str("DIRECT"),
            Self::Proxy(address) => write!(f, "PROXY {address}"),
            Self::Https(address) => write!(f, "HTTPS {address}"),
            Self::Socks5(address) => write!(f, "SOCKS5 {address}"),
        }
    }
}

/// The ordered proxy list a PAC script returned: try each in turn,
/// falling back to the next when one is unreachable.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PacDirectives(Vec<PacDirective>);

impl PacDirectives {
    /// The given directives, in the order they should be tried.
    #[must_use]
    pub fn new(directives: impl IntoIterator<Item = PacDirective>) -> Self {
        directives.into_iter().collect()
    }

    /// A list that only goes [`PacDirective::Direct`].
    #[must_use]
    pub fn direct() -> Self {
        Self(vec![PacDirective::Direct])
    }

    /// The directives, in the order the script returned them.
    #[must_use]
    pub fn as_slice(&self) -> &[PacDirective] {
        &self.0
    }

    /// Returns `true` if the script returned nothing usable.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The number of directives.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// The first directive, if any.
    #[must_use]
    pub fn first(&self) -> Option<&PacDirective> {
        self.0.first()
    }

    /// The ordered [`ProxyRoutes`] this list selects, ready to hand to a
    /// [`ProxyRoutesConnector`][rama_net::client::ProxyRoutesConnector].
    #[must_use]
    pub fn into_proxy_routes(self) -> ProxyRoutes {
        self.0
            .into_iter()
            .map(PacDirective::into_proxy_route)
            .collect()
    }

    /// Iterate the proxies to try, skipping [`PacDirective::Direct`].
    pub fn proxy_addresses(&self) -> impl Iterator<Item = ProxyAddress> + '_ {
        self.0.iter().filter_map(PacDirective::proxy_address)
    }
}

impl FromStr for PacDirectives {
    type Err = BoxError;

    /// Parse the `;`-separated string a PAC script returned.
    ///
    /// Unsupported tokens are skipped; a string with no usable directive
    /// at all is an error, as routing on it would be a guess.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut directives = Vec::new();
        for token in s.split(';') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if let Some(directive) = PacDirective::parse(token)? {
                directives.push(directive);
            }
        }

        if directives.is_empty() {
            return Err(BoxError::from_static_str("no supported pac directive")
                .context_str_field("result", s));
        }
        Ok(Self(directives))
    }
}

impl fmt::Display for PacDirectives {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, directive) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{directive}")?;
        }
        Ok(())
    }
}

impl FromIterator<PacDirective> for PacDirectives {
    fn from_iter<I: IntoIterator<Item = PacDirective>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl IntoIterator for PacDirectives {
    type Item = PacDirective;
    type IntoIter = std::vec::IntoIter<PacDirective>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a PacDirectives {
    type Item = &'a PacDirective;
    type IntoIter = std::slice::Iter<'a, PacDirective>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rama_net::address::{Domain, Host};

    fn host_port(host: &'static str, port: u16) -> HostWithPort {
        HostWithPort::new(Host::Name(Domain::from_static(host)), port)
    }

    #[test]
    fn parse_directive_table() {
        for (input, expected) in [
            ("DIRECT", vec![PacDirective::Direct]),
            ("direct", vec![PacDirective::Direct]),
            (
                "PROXY p.example:8080",
                vec![PacDirective::Proxy(host_port("p.example", 8080))],
            ),
            // per-token default ports
            (
                "PROXY p.example",
                vec![PacDirective::Proxy(host_port("p.example", 80))],
            ),
            (
                "HTTP p.example",
                vec![PacDirective::Proxy(host_port("p.example", 80))],
            ),
            (
                "HTTPS p.example",
                vec![PacDirective::Https(host_port("p.example", 443))],
            ),
            (
                "SOCKS5 p.example",
                vec![PacDirective::Socks5(host_port("p.example", 1080))],
            ),
            // ordered fallback list, tolerant of spacing
            (
                "PROXY a:1;SOCKS5 b:2 ;  DIRECT",
                vec![
                    PacDirective::Proxy(host_port("a", 1)),
                    PacDirective::Socks5(host_port("b", 2)),
                    PacDirective::Direct,
                ],
            ),
            // unsupported tokens are skipped, not fatal
            ("SOCKS legacy:1080; DIRECT", vec![PacDirective::Direct]),
            (
                "SOCKS4 legacy:1080; PROXY a:1",
                vec![PacDirective::Proxy(host_port("a", 1))],
            ),
            ("; ; DIRECT ;", vec![PacDirective::Direct]),
        ] {
            let directives: PacDirectives = input.parse().unwrap_or_else(|err| {
                panic!("`{input}` should parse: {err}");
            });
            assert_eq!(directives.as_slice(), expected, "input: `{input}`");
        }
    }

    #[test]
    fn parse_rejects_unusable_results() {
        for input in [
            "",
            "   ",
            // nothing rama can act on
            "SOCKS legacy:1080",
            "GARBAGE",
            // structurally broken
            "PROXY",
            "DIRECT p.example:8080",
            "PROXY a:1 b:2",
            "PROXY :8080",
        ] {
            let result = input.parse::<PacDirectives>();
            assert!(result.is_err(), "`{input}` should not parse: {result:?}");
        }
    }

    #[test]
    fn parse_ipv6_proxy_address() {
        let directives: PacDirectives = "PROXY [::1]:8080".parse().unwrap();
        let expected = HostWithPort::new(Host::Address("::1".parse().unwrap()), 8080);
        assert_eq!(directives.as_slice(), [PacDirective::Proxy(expected)]);
    }

    #[test]
    fn display_round_trips() {
        for input in [
            "DIRECT",
            "PROXY p.example:8080",
            "HTTPS p.example:443",
            "SOCKS5 p.example:1080",
            "PROXY a:1; SOCKS5 b:2; DIRECT",
        ] {
            let directives: PacDirectives = input.parse().unwrap();
            assert_eq!(directives.to_string(), input);
            // and the rendered form parses back to the same value
            assert_eq!(
                directives.to_string().parse::<PacDirectives>().unwrap(),
                directives
            );
        }
    }

    #[test]
    fn directives_become_ordered_proxy_routes() {
        let directives: PacDirectives = "PROXY a:1; SOCKS5 b:2; DIRECT".parse().unwrap();
        let routes = directives.into_proxy_routes();

        let routes: Vec<&ProxyRoute> = routes.iter().collect();
        assert_eq!(routes.len(), 3);
        assert!(matches!(routes[0], ProxyRoute::Proxy(_)));
        assert_eq!(
            routes[1].proxy_address().and_then(|a| a.protocol.clone()),
            Some(Protocol::SOCKS5H),
        );
        // DIRECT keeps its place in the fallback order
        assert_eq!(routes[2], &ProxyRoute::Direct);
    }

    #[test]
    fn a_direct_only_result_is_a_single_direct_route() {
        let directives: PacDirectives = "DIRECT".parse().unwrap();
        let routes = directives.into_proxy_routes();
        assert_eq!(routes.as_slice(), [ProxyRoute::Direct]);
        // and it does not claim precedence over a configured route
        assert!(!routes.overwrite());
    }

    #[test]
    fn proxy_address_protocol_matrix() {
        for (input, expected) in [
            ("PROXY a:1", Some(Protocol::HTTP)),
            ("HTTP a:1", Some(Protocol::HTTP)),
            ("HTTPS a:1", Some(Protocol::HTTPS)),
            ("SOCKS5 a:1", Some(Protocol::SOCKS5H)),
        ] {
            let directives: PacDirectives = input.parse().unwrap();
            let address = directives.first().unwrap().proxy_address().unwrap();
            assert_eq!(address.protocol, expected, "input: `{input}`");
            assert!(address.credential.is_none());
        }

        assert!(PacDirective::Direct.proxy_address().is_none());
    }
}
