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

    #[inline(always)]
    pub fn is_excluded(&self, domain: impl AsDomainRef) -> bool {
        self.no_mitm_domains.is_match_exact(domain)
    }
}

impl Default for DomainExclusionList {
    fn default() -> Self {
        Self::new([
            "detectportal.firefox.com",
            "connectivitycheck.gstatic.com",
            "captive.apple.com",
        ])
    }
}
