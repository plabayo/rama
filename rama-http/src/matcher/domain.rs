use crate::Request;
use rama_core::{Context, context::Extensions};
use rama_net::address::{Domain, Host};
use rama_net::http::RequestContext;

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
    pub fn exact(domain: Domain) -> Self {
        Self { domain, sub: false }
    }
    /// create a new domain matcher to match on a subdomain of the URI host match.
    ///
    /// Note that a domain is also a subdomain of itself, so this will also
    /// include all matches that [`Self::exact`] would capture.
    pub fn sub(domain: Domain) -> Self {
        Self { domain, sub: true }
    }
}

impl<State, Body> rama_core::matcher::Matcher<State, Request<Body>> for DomainMatcher {
    fn matches(
        &self,
        ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        let host = match ctx.get::<RequestContext>() {
            Some(req_ctx) => req_ctx.authority.host().clone(),
            None => {
                let req_ctx: RequestContext = match (ctx, req).try_into() {
                    Ok(req_ctx) => req_ctx,
                    Err(err) => {
                        tracing::error!(error = %err, "DomainMatcher: failed to lazy-make the request ctx");
                        return false;
                    }
                };
                let host = req_ctx.authority.host().clone();
                if let Some(ext) = ext {
                    ext.insert(req_ctx);
                }
                host
            }
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
