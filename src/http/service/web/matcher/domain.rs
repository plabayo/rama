use super::Matcher;
use crate::{
    http::Request,
    service::{context::Extensions, Context},
};
use std::cmp::Ordering;

#[derive(Debug, Clone)]
/// Filter based on the (sub)domain of the request's URI.
pub struct DomainFilter {
    domain: String,
    sub: bool,
}

impl DomainFilter {
    /// create a new domain filter to filter on an exact URI host match.
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into().to_lowercase(),
            sub: false,
        }
    }

    /// create a new domain filter to filter on a subdomain URI host match.
    pub fn sub(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into().to_lowercase(),
            sub: true,
        }
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

impl<State> Matcher<State> for DomainFilter {
    fn matches(&self, _ext: &mut Extensions, _ctx: &Context<State>, req: &Request) -> bool {
        let host = match req.uri().host() {
            Some(host) => host,
            None => return false,
        };
        self.matches_host(host)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn matchest_host_match() {
        let test_cases = vec![
            (DomainFilter::new("www.example.com"), "www.example.com"),
            (DomainFilter::new("www.example.com"), "WwW.ExamplE.COM"),
            (DomainFilter::sub("example.com"), "www.example.com"),
            (DomainFilter::sub("example.com"), "m.example.com"),
            (DomainFilter::sub("example.com"), "www.EXAMPLE.com"),
            (DomainFilter::sub("example.com"), "M.example.com"),
        ];
        for (filter, host) in test_cases.into_iter() {
            assert!(
                filter.matches_host(host),
                "({:?}).matches_host({})",
                filter,
                host
            );
        }
    }

    #[test]
    fn matchest_host_no_match() {
        let test_cases = vec![
            (DomainFilter::new("www.example.com"), "www.example.co"),
            (DomainFilter::new("www.example.com"), "www.ejemplo.com"),
            (DomainFilter::new("www.example.com"), "www3.example.com"),
            (DomainFilter::sub("w.example.com"), "www.example.com"),
            (DomainFilter::sub("gel.com"), "kegel.com"),
        ];
        for (filter, host) in test_cases.into_iter() {
            assert!(
                !filter.matches_host(host),
                "!({:?}).matches_host({})",
                filter,
                host
            );
        }
    }
}
