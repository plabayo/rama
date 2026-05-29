use std::sync::Arc;

use rama::net::address::{AsDomainRef, Domain, DomainTrie};

#[derive(Debug, Clone)]
pub struct DomainExclusionList {
    no_mitm_domains: Arc<DomainTrie<()>>,
}

impl DomainExclusionList {
    pub fn new<I, S>(domains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let domains: Vec<Domain> = domains
            .into_iter()
            .filter_map(|domain| Domain::try_from(domain.as_ref().to_owned()).ok())
            .collect();
        let mut no_mitm_domains = DomainTrie::new();
        no_mitm_domains.insert_domain_iter(domains.iter().cloned(), ());
        Self {
            no_mitm_domains: Arc::new(no_mitm_domains),
        }
    }

    /// `domain` matches if it is stored exactly, OR any ancestor
    /// of it is stored as a wildcard (`*.example.com`). Use the
    /// `*.` prefix when constructing the list to opt into subtree
    /// matching.
    #[inline(always)]
    pub fn is_excluded(&self, domain: impl AsDomainRef) -> bool {
        self.no_mitm_domains.is_match(domain)
    }
}

impl Default for DomainExclusionList {
    fn default() -> Self {
        Self::new([
            // Captive-portal probes. MITM'ing these breaks
            // network-onboarding flows in the host OS.
            "detectportal.firefox.com",
            "connectivitycheck.gstatic.com",
            "captive.apple.com",
            // High-traffic dev/CDN endpoints. Excluded so the
            // promote-cutover demo fires often during normal
            // browsing: each of these moves the per-flow data
            // path back to Swift's direct kernel↔NWConnection
            // forwarder once the Rust side's HTTP/TLS peek
            // decides it doesn't need to MITM. Wildcards
            // (`*.foo.com`) cover every subdomain.
            "*.github.com",
            "*.githubusercontent.com",
            "*.googleapis.com",
            "*.gstatic.com",
            "*.cloudflare.com",
            "*.jsdelivr.net",
        ])
    }
}
