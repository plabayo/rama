use crate::{
    http::{Request, RequestContext},
    net::address::{Domain, Host},
    service::{context::Extensions, Context},
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

impl<State, Body> crate::service::Matcher<State, Request<Body>> for DomainMatcher {
    fn matches(
        &self,
        _ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        let host = ctx
            .get::<RequestContext>()
            .map(|ctx| ctx.authority.as_ref().map(|auth| auth.host().clone()))
            .unwrap_or_else(|| {
                RequestContext::from((ctx, req)).authority.map(|auth| {
                    let (host, _) = auth.into_parts();
                    host
                })
            });

        match host {
            Some(Host::Name(domain)) => {
                if self.sub {
                    self.domain.is_parent_of(&domain)
                } else {
                    self.domain == domain
                }
            }
            _ => false,
        }
    }
}
