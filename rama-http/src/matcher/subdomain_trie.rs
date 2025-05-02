use trie_rs::TrieBuilder;
use crate::Request;
use rama_core::{Context, context::Extensions, matcher::Matcher};
use rama_net::http::RequestContext;
use rama_net::address::{Host};

#[derive(Debug, Clone)]
pub struct SubdomainTrieMatcher {
    trie: trie_rs::Trie<u8>,
}

impl SubdomainTrieMatcher {
    pub fn new<I, S>(domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut builder = TrieBuilder::new();
        for domain in domains {
            let reversed = reverse_domain(domain.as_ref());
            builder.push(reversed.as_bytes());
        }
        let trie = builder.build();
        Self { trie }
    }

    pub fn is_match(&self, domain: &str) -> bool {
        let reversed = reverse_domain(domain);
        let domain_parts = reversed.split('.');

        let mut prefix = String::new();

        for part in domain_parts {
            prefix.push_str(part);
            prefix.push('.');

            if self.trie.exact_match(prefix.as_bytes()) {
                return true;
            }
        }
        
        false
    }

}

fn reverse_domain(domain: &str) -> String {
    let from = domain.strip_prefix('.').unwrap_or(domain);
    let mut domain = from.split('.').rev().collect::<Vec<&str>>().join(".");
    domain.push('.');
    domain
}

impl<State, Body> Matcher<State, Request<Body>> for SubdomainTrieMatcher {
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
                    Ok(rc) => rc,
                    Err(err) => {
                        tracing::error!(error = %err, "SubdomainTrieMatcher: failed to extract request context");
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
                let is_match = self.is_match(domain.as_str());
                tracing::trace!("SubdomainTrieMatcher: matching '{}' => {}", domain, is_match);
                is_match
            }
            Host::Address(_) => {
                tracing::trace!("SubdomainTrieMatcher: ignoring numeric address");
                false
            }
        }
    }
}

impl FromIterator<String> for SubdomainTrieMatcher {
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        let domains: Vec<String> = iter.into_iter().collect();

        SubdomainTrieMatcher::new(domains)
    }
}

impl<'a> FromIterator<&'a str> for SubdomainTrieMatcher {
    fn from_iter<I: IntoIterator<Item = &'a str>>(iter: I) -> Self {
        let domains: Vec<&str> = iter.into_iter().collect();

        SubdomainTrieMatcher::new(domains)
    }
}

#[cfg(test)]
mod subdomain_trie_tests {
    use super::*;

    #[test]
    fn test_reverse_domain() {
        assert_eq!(reverse_domain("example.com"), "com.example.");
        assert_eq!(reverse_domain(".example.com"), "com.example.");
        assert_eq!(reverse_domain("sub.example.com"), "com.example.sub.");
    }

    #[test]
    fn test_trie_matching() {
        let matcher = SubdomainTrieMatcher::new(vec!["example.com", "sub.domain.org"]);
        assert!(matcher.is_match("example.com"));
        assert!(matcher.is_match(".example.com"));
        assert!(matcher.is_match("sub.domain.org"));
        assert!(matcher.is_match("sub.example.com"));
        assert!(!matcher.is_match("domain.org"));
        assert!(!matcher.is_match("other.com"));
    }

    #[test]
    fn test_from_iterator_string() {
        let domains: Vec<String> = vec!["example.com".to_string(), "sub.domain.org".to_string()];
        let matcher: SubdomainTrieMatcher = domains.into_iter().collect();

        assert!(matcher.is_match("example.com"));
    }

    #[test]
    fn test_from_iterator_str() {
        let domains: Vec<&str> = vec!["example.com", "sub.domain.org"];
        let matcher: SubdomainTrieMatcher = domains.into_iter().collect();

        assert!(matcher.is_match("example.com"));
    }

    #[test]
    fn test_path_matching_with_trie() {
        let domains: Vec<String> = vec!["example.com".to_string(), "sub.domain.org".to_string()];
        let matcher: SubdomainTrieMatcher = domains.into_iter().collect();

        let path = "sub.example.com";

        let request = Request::builder().uri(path).body(()).unwrap();
        let ctx = Context::default();

        assert!(matcher.matches(None, &ctx, &request));
    }

    #[test]
    fn test_non_matching_path() {
        let domains: Vec<String> = vec!["example.com".to_string()];
        let matcher: SubdomainTrieMatcher = domains.into_iter().collect();

        let path = "nonmatching.com";

        let request = Request::builder().uri(path).body(()).unwrap();
        let ctx = Context::default();

        assert!(!matcher.matches(None, &ctx, &request));
    }
}

