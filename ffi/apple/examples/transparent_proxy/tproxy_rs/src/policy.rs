use std::sync::Arc;

use rama::net::address::{AsDomainRef, DomainTrie};

#[derive(Debug, Clone)]
pub struct DomainExclusionList {
    no_mitm_domains: Arc<DomainTrie<()>>,
}

impl DomainExclusionList {
    #[inline(always)]
    pub fn is_excluded(&self, domain: impl AsDomainRef) -> bool {
        self.no_mitm_domains.is_match_exact(domain)
    }
}

impl Default for DomainExclusionList {
    fn default() -> Self {
        Self {
            no_mitm_domains: Arc::new(
                [
                    "detectportal.firefox.com",
                    "connectivitycheck.gstatic.com",
                    "captive.apple.com",
                ]
                .into_iter()
                .map(|domain| (domain, ()))
                .collect(),
            ),
        }
    }
}
