use crate::Request;

use rama_core::{extensions::Extensions, telemetry::tracing};
use rama_net::{
    address::{Domain, IntoDomain},
    http::RequestContext,
};

#[derive(Debug, Clone)]
/// Matcher based on the (sub)domain of the request's URI.
pub struct DomainMatcher {
    domain: Domain,
    sub: bool,
}

impl DomainMatcher {
    /// create a new domain matcher to match on an exact URI host match.
    ///
    /// If the host is an Ip it will not match.
    #[must_use]
    pub fn exact(domain: impl IntoDomain) -> Self {
        Self {
            domain: domain.into_domain(),
            sub: false,
        }
    }
    /// create a new domain matcher to match on a subdomain of the URI host match.
    ///
    /// Note that a domain is also a subdomain of itself, so this will also
    /// include all matches that [`Self::exact`] would capture.
    #[must_use]
    pub fn sub(domain: impl IntoDomain) -> Self {
        Self {
            domain: domain.into_domain(),
            sub: true,
        }
    }
}

impl<Body> rama_core::matcher::Matcher<Request<Body>> for DomainMatcher {
    fn matches(&self, _: Option<&Extensions>, req: &Request<Body>) -> bool {
        let host = {
            let req_ctx = match RequestContext::try_from(req) {
                Ok(req_ctx) => req_ctx,
                Err(err) => {
                    tracing::error!("DomainMatcher: failed to lazy-make the request ctx: {err:?}");
                    return false;
                }
            };
            req_ctx.authority.host
        };

        // IP-first: pct-encoded IP literals (`%31%32%37.0.0.1`) promote
        // to both Domain (the digits-and-dots form passes the shallow
        // Domain validator) AND IpAddr. The Domain match would be wrong
        // for IP hosts. Filter them out first.
        if host.try_as_ip().is_ok() {
            tracing::trace!("DomainMatcher: host is an IP — no match");
            return false;
        }
        // Pct-encoded reg-names that decode to a domain get matched too.
        // Non-promotable hosts (sub-delim reg-name, IPvFuture) never match.
        let Ok(domain) = host.try_into_domain() else {
            tracing::trace!("DomainMatcher: host is not a domain — no match");
            return false;
        };
        if self.sub {
            tracing::trace!("DomainMatcher: ({}).is_parent_of({})", self.domain, domain);
            self.domain.is_parent_of(&domain)
        } else {
            tracing::trace!("DomainMatcher: ({}) == ({})", self.domain, domain);
            self.domain == domain
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Request;
    use rama_core::matcher::Matcher as _;

    fn req_with_host(host_header: &str) -> Request<()> {
        // Build with a path-only URI and set the Host header — that's
        // the lane `RequestContext` uses for authority lookup, and
        // unlike `http::Uri` it accepts pct-encoded reg-names there.
        Request::builder()
            .uri("/")
            .header("host", host_header)
            .body(())
            .unwrap()
    }

    #[test]
    fn plain_domain_matches() {
        let m = DomainMatcher::exact(rama_net::address::Domain::from_static("example.com"));
        assert!(m.matches(None, &req_with_host("example.com")));
    }

    #[test]
    fn pct_encoded_reg_name_matches_via_bridge() {
        // `exa%6Dple.com` pct-decodes to `example.com` — bridge takes
        // us from `Host::Uninterpreted` to `Domain` for matching.
        let m = DomainMatcher::exact(rama_net::address::Domain::from_static("example.com"));
        assert!(m.matches(None, &req_with_host("exa%6Dple.com")));
    }

    #[test]
    fn ip_host_does_not_match_domain() {
        // IP-first: an IP literal must not match a domain matcher,
        // even though the shallow Domain validator accepts it.
        let m = DomainMatcher::exact(rama_net::address::Domain::from_static("127.0.0.1"));
        assert!(!m.matches(None, &req_with_host("127.0.0.1")));
    }

    #[test]
    fn pct_encoded_ip_does_not_match_domain() {
        // Regression: `%31%32%37.0.0.1` pct-decodes to `127.0.0.1`,
        // which both Domain and IpAddr promotion accept. The IP-first
        // filter must catch this before the domain match runs.
        let m = DomainMatcher::exact(rama_net::address::Domain::from_static("127.0.0.1"));
        assert!(!m.matches(None, &req_with_host("%31%32%37.0.0.1")));
    }

    #[test]
    fn subdomain_match() {
        let m = DomainMatcher::sub(rama_net::address::Domain::from_static("example.com"));
        assert!(m.matches(None, &req_with_host("api.example.com")));
        assert!(m.matches(None, &req_with_host("example.com")));
        assert!(!m.matches(None, &req_with_host("other.example")));
    }
}
