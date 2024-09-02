use crate::{
    context::Extensions,
    http::{Request, RequestContext},
    net::address::{Domain, Host},
    Context,
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

impl<State, Body> crate::matcher::Matcher<State, Request<Body>> for DomainMatcher {
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
                    Err(_) => return false,
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
                    self.domain.is_parent_of(&domain)
                } else {
                    self.domain == domain
                }
            }
            Host::Address(_) => false,
        }
    }
}
