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
