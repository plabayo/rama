use crate::Request;
use rama_core::telemetry::tracing;
use rama_core::{Context, context::Extensions, matcher::Matcher};
use rama_net::address::{DomainTrie, Host};
use rama_net::http::RequestContext;

#[derive(Debug, Clone)]
/// A matcher that matches subdomains.
///
/// Note that a domain is considered also a suddomain of itself.
pub struct SubdomainTrieMatcher {
    trie: DomainTrie<()>,
}

impl SubdomainTrieMatcher {
    /// Create a new [`SubdomainTrieMatcher`].
    pub fn new<I, S>(domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut trie = DomainTrie::new();
        trie.insert_domain_iter(domains, ());
        Self { trie }
    }

    // Returns true if a domain is a subdomain of any domain lineage in this [`SubdomainTrieMatcher`].
    pub fn is_match(&self, domain: impl AsRef<str>) -> bool {
        self.trie.is_match_parent(domain)
    }
}

impl<State, Body> Matcher<State, Request<Body>> for SubdomainTrieMatcher {
    fn matches(
        &self,
        ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        req: &Request<Body>,
    ) -> bool {
        let match_authority = |ctx: &RequestContext| match ctx.authority.host() {
            Host::Name(domain) => {
                let is_match = self.is_match(domain.as_str());
                tracing::trace!(
                    "SubdomainTrieMatcher: matching domain = {}, matched = {}",
                    domain,
                    is_match
                );
                is_match
            }
            Host::Address(address) => {
                tracing::trace!("SubdomainTrieMatcher: ignoring numeric address: {address}",);
                false
            }
        };

        match ctx.get() {
            Some(req_ctx) => match_authority(req_ctx),
            None => {
                let req_ctx: RequestContext = match (ctx, req).try_into() {
                    Ok(rc) => rc,
                    Err(err) => {
                        tracing::debug!(
                            "SubdomainTrieMatcher: failed to extract request context: {err:?}",
                        );
                        return false;
                    }
                };
                let is_match = match_authority(&req_ctx);
                if let Some(ext) = ext {
                    ext.insert(req_ctx);
                }
                is_match
            }
        }
    }
}

impl<S> FromIterator<S> for SubdomainTrieMatcher
where
    S: AsRef<str>,
{
    #[inline]
    fn from_iter<I: IntoIterator<Item = S>>(iter: I) -> Self {
        SubdomainTrieMatcher::new(iter)
    }
}

#[cfg(test)]
mod subdomain_trie_tests {
    use super::*;

    #[test]
    fn test_trie_matching() {
        let matcher = SubdomainTrieMatcher::new(vec!["example.com", "sub.domain.org"]);
        assert!(matcher.is_match("example.com"));
        assert!(matcher.is_match(".example.com"));
        assert!(matcher.is_match("sub.domain.org"));
        assert!(matcher.is_match("sub.example.com"));
        assert!(!matcher.is_match("domain.org"));
        assert!(!matcher.is_match("other.com"));
        assert!(!matcher.is_match(""));
        assert!(!matcher.is_match("localhost"));
    }

    #[test]
    fn test_path_matching_with_trie() {
        let domains: Vec<String> = vec!["example.com".to_owned(), "sub.domain.org".to_owned()];
        let matcher: SubdomainTrieMatcher = domains.into_iter().collect();

        let path = "sub.example.com";

        let request = Request::builder().uri(path).body(()).unwrap();
        let ctx = Context::default();

        assert!(matcher.matches(None, &ctx, &request));
    }

    #[test]
    fn test_non_matching_path() {
        let domains: Vec<String> = vec!["example.com".to_owned()];
        let matcher: SubdomainTrieMatcher = domains.into_iter().collect();

        let path = "nonmatching.com";

        let request = Request::builder().uri(path).body(()).unwrap();
        let ctx = Context::default();

        assert!(!matcher.matches(None, &ctx, &request));
    }
}
