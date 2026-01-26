use crate::Request;

use rama_core::{
    extensions::{Extensions, ExtensionsRef},
    telemetry::tracing,
};
use rama_net::{
    address::{Domain, Host, IntoDomain},
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
    fn matches(&self, ext: Option<&mut Extensions>, req: &Request<Body>) -> bool {
        let host = if let Some(req_ctx) = req.extensions().get::<RequestContext>() {
            req_ctx.authority.host.clone()
        } else {
            let req_ctx = match RequestContext::try_from(req) {
                Ok(req_ctx) => req_ctx,
                Err(err) => {
                    tracing::error!("DomainMatcher: failed to lazy-make the request ctx: {err:?}");
                    return false;
                }
            };
            let host = req_ctx.authority.host.clone();
            if let Some(ext) = ext {
                ext.insert(req_ctx);
            }
            host
        };
        match host {
            Host::Name(domain) => {
                if self.sub {
                    tracing::trace!("DomainMatcher: ({}).is_parent_of({})", self.domain, domain);
                    self.domain.is_parent_of(&domain)
                } else {
                    tracing::trace!("DomainMatcher: ({}) == ({})", self.domain, domain);
                    self.domain == domain
                }
            }
            Host::Address(_) => {
                tracing::trace!("DomainMatcher: ignore request host address");
                false
            }
        }
    }
}
