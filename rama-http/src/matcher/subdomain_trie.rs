use crate::Request;
use radix_trie::Trie;
use rama_core::{Context, context::Extensions, matcher::Matcher};
use rama_net::address::Host;
use rama_net::http::RequestContext;

#[derive(Debug, Clone)]
pub struct SubdomainTrieMatcher {
    trie: Trie<String, ()>,
}

impl SubdomainTrieMatcher {
    pub fn new<I, S>(domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut trie = Trie::new();
        for domain in domains {
            let reversed = reverse_domain(domain.as_ref());
            trie.insert(reversed, ());
        }
        Self { trie }
    }

    // Checks if the reversed domain has an ancestor in the trie.
    //
    // The domain is reversed to match the way Radix Tries store domains. `get_ancestor` is used
    // to check if any prefix of the reversed domain exists in the trie, indicating a match.
    pub fn is_match(&self, domain: impl AsRef<str>) -> bool {
        let reversed = reverse_domain(domain.as_ref());
        self.trie.get_ancestor(&reversed).is_some()
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
                tracing::trace!(
                    %address,
                    "SubdomainTrieMatcher: ignoring numeric address",
                );
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
                            error = %err,
                            "SubdomainTrieMatcher: failed to extract request context",
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
    fn test_reverse_domain() {
        assert_eq!(reverse_domain("example.com"), "com.example.");
        assert_eq!(reverse_domain(".example.com"), "com.example.");
        assert_eq!(reverse_domain("sub.example.com"), "com.example.sub.");
        assert_eq!(reverse_domain("localhost"), "localhost.");
        assert_eq!(reverse_domain(""), ".");
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
