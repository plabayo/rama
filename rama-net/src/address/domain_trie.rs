use radix_trie::{Trie, TrieCommon};
use std::fmt;

/// An efficient radix tree that can be used to match (sub)domains.
pub struct DomainTrie<T> {
    trie: Trie<String, T>,
}

impl<T: fmt::Debug> fmt::Debug for DomainTrie<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DomainTrie")
            .field("trie", &self.trie)
            .finish()
    }
}

impl<T: Clone> Clone for DomainTrie<T> {
    fn clone(&self) -> Self {
        Self {
            trie: self.trie.clone(),
        }
    }
}

impl<T> Default for DomainTrie<T> {
    fn default() -> Self {
        Self {
            trie: Default::default(),
        }
    }
}

impl<T> DomainTrie<T> {
    #[inline]
    /// Create a new [`DomainTrie`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Consume `self` and insert the given domain paired with the input value `T`.
    ///
    /// This overwrites any existing value already in the tree for that (trie) node.
    #[must_use]
    pub fn with_insert_domain(mut self, domain: impl AsRef<str>, value: T) -> Self {
        let reversed = reverse_domain(domain.as_ref());
        self.trie.insert(reversed, value);
        self
    }

    /// Insert the given domain paired with the input value `T`.
    ///
    /// This overwrites any existing value already in the tree for that (trie) node.
    pub fn insert_domain(&mut self, domain: impl AsRef<str>, value: T) -> &mut Self {
        let reversed = reverse_domain(domain.as_ref());
        self.trie.insert(reversed, value);
        self
    }

    /// Consume `self` and insert the given domains paired with the input value `T`.
    ///
    /// This overwrites any existing value already in the tree for that (trie) node.
    #[must_use]
    pub fn with_insert_domain_iter<I, S>(mut self, domains: I, value: T) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        T: Clone,
    {
        self.insert_domain_iter(domains, value);
        self
    }

    /// Insert the given domains paired with the input value `T`.
    ///
    /// This overwrites any existing value already in the tree for that (trie) node.
    pub fn insert_domain_iter<I, S>(&mut self, domains: I, value: T) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        T: Clone,
    {
        let mut iter = domains.into_iter();
        if let Some(mut prev) = iter.next() {
            for curr in iter {
                let reversed = reverse_domain(prev.as_ref());
                self.trie.insert(reversed, value.clone());
                prev = curr;
            }
            let reversed = reverse_domain(prev.as_ref());
            self.trie.insert(reversed, value);
        }

        self
    }

    /// Extend this [`DomainTrie`] with the given pairs.
    pub fn extend<I, S>(&mut self, iter: I) -> &mut Self
    where
        I: IntoIterator<Item = (S, T)>,
        S: AsRef<str>,
    {
        for (domain, value) in iter {
            self.insert_domain(domain, value);
        }
        self
    }

    #[inline]
    /// Returns true if the input domain is a subdomain of
    /// at least one node found in this [`DomainTrie`].
    pub fn is_match_parent(&self, domain: impl AsRef<str>) -> bool {
        self.match_parent(domain).is_some()
    }

    /// Returns the value for the most specific node found in the [`DomainTrie`]
    /// which is the exact domain or parent domain for a domain in this trie.
    ///
    /// Use [`Self::match_exact`] (first) in case you prefer an exact match instead.
    pub fn match_parent(&self, domain: impl AsRef<str>) -> Option<&T> {
        let reversed = reverse_domain(domain.as_ref());
        self.trie.get_ancestor(&reversed).and_then(|n| n.value())
    }

    #[inline]
    /// Returns true if the input domain is an exact domain
    /// stored in this [`DomainTrie`].
    pub fn is_match_exact(&self, domain: impl AsRef<str>) -> bool {
        self.match_exact(domain).is_some()
    }

    /// Returns the value that is stored for a given exact domain as stored in this trie.
    pub fn match_exact(&self, domain: impl AsRef<str>) -> Option<&T> {
        let reversed = reverse_domain(domain.as_ref());
        self.trie.get(&reversed)
    }

    /// Iterate over the domains and values stored in this Trie.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &T)> {
        self.trie.iter().map(|(s, v)| (s.as_ref(), v))
    }
}

fn reverse_domain(domain: &str) -> String {
    let from = domain.trim_matches('.');
    let mut domain = from.split('.').rev().collect::<Vec<&str>>().join(".");
    domain.push('.');
    domain
}

impl<S, T> FromIterator<(S, T)> for DomainTrie<T>
where
    S: AsRef<str>,
{
    #[inline]
    fn from_iter<I: IntoIterator<Item = (S, T)>>(iter: I) -> Self {
        let mut trie = Self::default();
        trie.extend(iter);
        trie
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_reverse_domain() {
        assert_eq!(reverse_domain("example.com."), "com.example.");
        assert_eq!(reverse_domain("example.com.."), "com.example.");
        assert_eq!(reverse_domain("example.com"), "com.example.");
        assert_eq!(reverse_domain(".example.com"), "com.example.");
        assert_eq!(reverse_domain("..example.com"), "com.example.");
        assert_eq!(reverse_domain(".example.com."), "com.example.");
        assert_eq!(reverse_domain("...example.com..."), "com.example.");
        assert_eq!(reverse_domain("sub.example.com"), "com.example.sub.");
        assert_eq!(reverse_domain("localhost"), "localhost.");
        assert_eq!(reverse_domain(""), ".");
    }

    #[test]
    fn test_trie_most_specific_matching_parent() {
        let matcher = DomainTrie::new()
            .with_insert_domain("bar.example.com", "bar")
            .with_insert_domain("example.com", "root")
            .with_insert_domain("foo.bar.example.com", "foo.bar");
        assert_eq!(Some(&"root"), matcher.match_parent("example.com"));
        assert_eq!(Some(&"bar"), matcher.match_parent("bar.example.com"));
        assert_eq!(Some(&"bar"), matcher.match_parent("baz.bar.example.com"));
        assert_eq!(
            Some(&"foo.bar"),
            matcher.match_parent("foo.bar.example.com")
        );
        assert_eq!(Some(&"bar"), matcher.match_parent("bazfoo.bar.example.com"));
        assert_eq!(
            Some(&"foo.bar"),
            matcher.match_parent("baz.foo.bar.example.com")
        );
    }

    #[test]
    fn test_trie_matching_parent() {
        let matcher =
            DomainTrie::new().with_insert_domain_iter(["example.com", "sub.domain.org"], ());

        assert!(matcher.is_match_parent("example.com"));
        assert!(matcher.is_match_parent(".example.com"));
        assert!(matcher.is_match_parent("sub.domain.org"));
        assert!(matcher.is_match_parent("sub.example.com"));
        assert!(matcher.is_match_parent("foo.sub.example.com"));
        assert!(matcher.is_match_parent("foo.bar.sub.example.com"));
        assert!(!matcher.is_match_parent("domain.org"));
        assert!(!matcher.is_match_parent("other.com"));
        assert!(!matcher.is_match_parent(""));
        assert!(!matcher.is_match_parent("localhost"));
    }

    #[test]
    fn test_trie_matching_exact() {
        let matcher =
            DomainTrie::new().with_insert_domain_iter(["example.com", "sub.domain.org"], ());

        assert!(matcher.is_match_exact("example.com"));
        assert!(matcher.is_match_exact(".example.com"));
        assert!(matcher.is_match_exact("sub.domain.org"));
        assert!(!matcher.is_match_exact("sub.example.com"));
        assert!(!matcher.is_match_exact("foo.sub.example.com"));
        assert!(!matcher.is_match_exact("foo.bar.sub.example.com"));
        assert!(!matcher.is_match_exact("domain.org"));
        assert!(!matcher.is_match_exact("other.com"));
        assert!(!matcher.is_match_exact(""));
        assert!(!matcher.is_match_exact("localhost"));
    }
}
