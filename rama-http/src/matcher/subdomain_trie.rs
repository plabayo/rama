use crate::Request;
use rama_core::telemetry::tracing;
use rama_core::{extensions::Extensions, matcher::Matcher};
use rama_net::address::{AsDomainRef, DomainTrie, Host};
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
    ///
    /// Every input domain is registered as a **subtree** entry — i.e. it
    /// matches the apex itself plus every descendant. Inputs already in
    /// wildcard form (`"*.foo.bar"`) are accepted as-is; bare inputs
    /// (`"foo.bar"`) are promoted to subtree internally.
    pub fn new<I, S>(domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsDomainRef,
    {
        let mut trie = DomainTrie::new();
        for d in domains {
            // Always promote to wildcard form so the trie stores this as a
            // subtree entry — that's what "subdomain trie" means.
            let wildcard = match d.as_wildcard_parent() {
                Some(_) => d.to_domain(),
                None => match d.to_domain().try_as_wildcard() {
                    Ok(w) => w,
                    Err(_) => continue, // domain too long to wildcard
                },
            };
            trie.insert_domain(wildcard, ());
        }
        Self { trie }
    }

    // Returns true if a domain is a subdomain of any domain lineage in this [`SubdomainTrieMatcher`].
    pub fn is_match(&self, domain: impl AsDomainRef) -> bool {
        self.trie.is_match(domain)
    }
}

impl<Body> Matcher<Request<Body>> for SubdomainTrieMatcher {
    fn matches(&self, _: Option<&Extensions>, req: &Request<Body>) -> bool {
        let req_ctx = match RequestContext::try_from(req) {
            Ok(rc) => rc,
            Err(err) => {
                tracing::debug!("SubdomainTrieMatcher: failed to extract request context: {err:?}",);
                return false;
            }
        };

        match req_ctx.authority.host {
            Host::Name(ref domain) => {
                let is_match = self.is_match(domain);
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
        }
    }
}

impl<S> FromIterator<S> for SubdomainTrieMatcher
where
    S: AsDomainRef,
{
    #[inline]
    fn from_iter<I: IntoIterator<Item = S>>(iter: I) -> Self {
        Self::new(iter)
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
        assert!(!matcher.is_match("localhost"));
    }

    #[test]
    fn test_path_matching_with_trie() {
        let domains = ["example.com", "sub.domain.org"];
        let matcher: SubdomainTrieMatcher = domains.into_iter().collect();

        let path = "sub.example.com";

        let request = Request::builder().uri(path).body(()).unwrap();
        assert!(matcher.matches(None, &request));
    }

    #[test]
    fn test_non_matching_path() {
        let domains = ["example.com"];
        let matcher: SubdomainTrieMatcher = domains.into_iter().collect();

        let path = "nonmatching.com";

        let request = Request::builder().uri(path).body(()).unwrap();
        assert!(!matcher.matches(None, &request));
    }
}
