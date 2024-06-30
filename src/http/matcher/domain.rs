use crate::{
    http::{Request, RequestContext},
    net::address::{Domain, Host},
    service::{context::Extensions, Context},
};

#[derive(Debug, Clone)]
/// Matcher based on the (sub)domain of the request's URI.
pub struct DomainMatcher(Domain);

impl DomainMatcher {
    /// create a new domain matcher to match on an exact URI host match.
    pub fn new(domain: Domain) -> Self {
        Self(domain)
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
            Some(Host::Name(domain)) => self.0.is_parent_of(&domain),
            _ => false,
        }
    }
}
