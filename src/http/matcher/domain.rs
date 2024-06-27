use crate::{
    http::{Request, RequestContext},
    service::{context::Extensions, Context},
};
use std::cmp::Ordering;

#[derive(Debug, Clone)]
/// Matcher based on the (sub)domain of the request's URI.
pub struct DomainMatcher {
    domain: String,
    sub: bool,
}

impl DomainMatcher {
    /// create a new domain matcher to match on an exact URI host match.
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into().to_lowercase(),
            sub: false,
        }
    }

    /// create a new domain matcher to match on a subdomain URI host match.
    pub fn sub(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into().to_lowercase(),
            sub: true,
        }
    }

    /// Create an new domain matcher to match private domains.
    ///
    /// As proposed in
    /// <https://itp.cdn.icann.org/en/files/security-and-stability-advisory-committee-ssac-reports/sac-113-en.pdf>.
    ///
    /// In specific this means that it will match on any domain with the TLD `.internal`.
    pub fn private() -> Self {
        Self::sub("internal")
    }

    pub(crate) fn matches_host(&self, host: &str) -> bool {
        let domain = self.domain.as_str();
        match host.len().cmp(&domain.len()) {
            Ordering::Equal => domain.eq_ignore_ascii_case(host),
            Ordering::Greater => {
                if !self.sub {
                    return false;
                }
                let n = host.len() - domain.len();
                let dot_char = host.chars().nth(n - 1);
                let host_parent = &host[n..];
                dot_char == Some('.') && domain.eq_ignore_ascii_case(host_parent)
            }
            Ordering::Less => false,
        }
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
            .map(|ctx| ctx.authority.as_ref().map(|auth| auth.host().to_string()))
            .unwrap_or_else(|| {
                RequestContext::from((ctx, req)).authority.map(|auth| {
                    let (host, _) = auth.into_parts();
                    host.to_string()
                })
            });

        match host {
            Some(host) => self.matches_host(host.as_ref()),
            None => false,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn matchest_host_match() {
        let test_cases = vec![
            (DomainMatcher::new("www.example.com"), "www.example.com"),
            (DomainMatcher::new("www.example.com"), "WwW.ExamplE.COM"),
            (DomainMatcher::sub("example.com"), "www.example.com"),
            (DomainMatcher::sub("example.com"), "m.example.com"),
            (DomainMatcher::sub("example.com"), "www.EXAMPLE.com"),
            (DomainMatcher::sub("example.com"), "M.example.com"),
        ];
        for (matcher, host) in test_cases.into_iter() {
            assert!(
                matcher.matches_host(host),
                "({:?}).matches_host({})",
                matcher,
                host
            );
        }
    }

    #[test]
    fn matchest_host_no_match() {
        let test_cases = vec![
            (DomainMatcher::new("www.example.com"), "www.example.co"),
            (DomainMatcher::new("www.example.com"), "www.ejemplo.com"),
            (DomainMatcher::new("www.example.com"), "www3.example.com"),
            (DomainMatcher::sub("w.example.com"), "www.example.com"),
            (DomainMatcher::sub("gel.com"), "kegel.com"),
        ];
        for (matcher, host) in test_cases.into_iter() {
            assert!(
                !matcher.matches_host(host),
                "!({:?}).matches_host({})",
                matcher,
                host
            );
        }
    }

    #[test]
    fn private_domain_match() {
        let test_cases = vec![
            (DomainMatcher::private(), "foo.internal"),
            (DomainMatcher::private(), "www.example.internal"),
            (DomainMatcher::private(), "www.example.INTERNAL"),
        ];
        for (matcher, host) in test_cases.into_iter() {
            assert!(
                matcher.matches_host(host),
                "({:?}).matches_host({})",
                matcher,
                host
            );
        }
    }

    #[test]
    fn private_domain_no_match() {
        let test_cases = vec![
            (DomainMatcher::private(), "foo.internals"),
            (DomainMatcher::private(), "www.example.internals"),
            (DomainMatcher::private(), "foo.internal.com"),
            (DomainMatcher::private(), "foo.internal."),
        ];
        for (matcher, host) in test_cases.into_iter() {
            assert!(
                !matcher.matches_host(host),
                "!({:?}).matches_host({})",
                matcher,
                host
            );
        }
    }
}
