use crate::Request;
use rama_core::telemetry::tracing;
use rama_core::{extensions::Extensions, matcher::Matcher};
use rama_http_types::RequestContext;
use rama_net::address::{AsDomainRef, DomainTrie};

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
    /// Every input domain is registered as a **subtree** entry — it matches
    /// the apex itself plus every descendant. Inputs already in wildcard
    /// form (`"*.foo.bar"`) pass through; bare inputs (`"foo.bar"`) are
    /// promoted to `*.foo.bar` first. Inputs that can't be made into a
    /// valid wildcard (e.g. exceeding the length cap) are silently skipped.
    pub fn new<I, S>(domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsDomainRef,
    {
        let mut trie = DomainTrie::new();
        for d in domains {
            if let Ok(w) = d.to_wildcard() {
                trie.insert_domain(w, ());
            }
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

        // IP-first: pct-encoded IP literals (`%31%32%37.0.0.1`) can
        // promote to both Domain and IpAddr (shallow Domain validator
        // accepts digits-and-dots). The Domain match would be wrong for
        // IP hosts. Filter them out first.
        if req_ctx.authority.host.try_as_ip().is_ok() {
            tracing::trace!("SubdomainTrieMatcher: host is an IP — no match");
            return false;
        }
        // Pct-encoded reg-names that decode to a domain participate.
        // Non-promotable hosts (sub-delim, IPvFuture) don't.
        let Ok(domain) = req_ctx.authority.host.try_as_domain() else {
            tracing::trace!("SubdomainTrieMatcher: host is not a domain — no match");
            return false;
        };
        let is_match = self.is_match(domain.as_ref());
        tracing::trace!(
            "SubdomainTrieMatcher: matching domain = {}, matched = {}",
            domain,
            is_match
        );
        is_match
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
    use crate::Uri;

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

        let request = Request::builder()
            .uri(Uri::parse_authority_form(path).unwrap())
            .body(())
            .unwrap();
        assert!(matcher.matches(None, &request));
    }

    #[test]
    fn test_non_matching_path() {
        let domains = ["example.com"];
        let matcher: SubdomainTrieMatcher = domains.into_iter().collect();

        let path = "nonmatching.com";

        let request = Request::builder()
            .uri(Uri::parse_authority_form(path).unwrap())
            .body(())
            .unwrap();
        assert!(!matcher.matches(None, &request));
    }

    fn req_with_host(host_header: &str) -> Request<()> {
        Request::builder()
            .uri("/")
            .header("host", host_header)
            .body(())
            .unwrap()
    }

    #[test]
    fn pct_encoded_reg_name_matches_via_bridge() {
        // `exa%6Dple.com` pct-decodes to `example.com` — the subdomain
        // trie includes a `sub.example.com` style entry which should
        // match the bridged domain.
        let matcher: SubdomainTrieMatcher = ["example.com"].into_iter().collect();
        assert!(matcher.matches(None, &req_with_host("exa%6Dple.com")));
    }

    #[test]
    fn ip_host_does_not_match() {
        let matcher: SubdomainTrieMatcher = ["127.0.0.1"].into_iter().collect();
        assert!(!matcher.matches(None, &req_with_host("127.0.0.1")));
        // Regression: pct-encoded IP that bridges to a digits-and-dots
        // string the shallow Domain validator accepts. Must be filtered
        // out by the IP-first check.
        assert!(!matcher.matches(None, &req_with_host("%31%32%37.0.0.1")));
    }
}
