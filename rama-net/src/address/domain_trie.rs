use radix_trie::{Trie, TrieCommon};
use rama_utils::str::smol_str::SmolStrBuilder;
use std::fmt;

use crate::address::{AsDomainRef, Domain};

/// An efficient radix tree that can be used to match (sub)domains.
///
/// Each inserted entry is either an **exact** entry or a **subtree** entry,
/// inferred from the input:
///
/// - `"example.com"` — exact: matches only the domain `example.com` itself.
/// - `"*.example.com"` — subtree: matches `example.com` and every name
///   under it (`foo.example.com`, `a.b.example.com`, …).
///
/// Both modes can coexist at the same name: inserting `example.com` and
/// later `*.example.com` (or vice versa) leaves both values addressable.
#[derive(Debug, Clone)]
pub struct DomainTrie<T> {
    trie: Trie<String, NodeData<T>>,
}

/// Per-node storage. `exact` is set by inserting `"name"`; `subtree` is set
/// by inserting `"*.name"`. Both may be set simultaneously.
#[derive(Debug, Clone)]
struct NodeData<T> {
    exact: Option<T>,
    subtree: Option<T>,
}

impl<T> NodeData<T> {
    fn empty() -> Self {
        Self {
            exact: None,
            subtree: None,
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

/// Result of [`DomainTrie::match_parent`].
#[non_exhaustive]
pub struct DomainParentMatch<'a, T> {
    pub value: &'a T,
    pub is_exact: bool,
}

impl<T: fmt::Debug> fmt::Debug for DomainParentMatch<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DomainParentMatch")
            .field("value", &self.value)
            .field("is_exact", &self.is_exact)
            .finish()
    }
}

impl<T: PartialEq> PartialEq for DomainParentMatch<'_, T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value && self.is_exact == other.is_exact
    }
}

impl<T: PartialEq + Eq> Eq for DomainParentMatch<'_, T> {}

/// Rich result of [`DomainTrie::get`].
///
/// `value` is the stored value; `kind` says whether the hit was the exact
/// stored name or a subtree-of match, in which case it also carries the
/// stored apex (so callers can synthesize the wildcard form via
/// `apex.try_as_wildcard()` if they need it).
#[non_exhaustive]
pub struct DomainMatch<'a, T> {
    pub value: &'a T,
    pub kind: MatchKind,
}

/// Discriminator for [`DomainMatch::kind`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchKind {
    /// The query equaled the stored name and an exact entry was registered
    /// for it.
    Exact,
    /// The query was the apex itself or a descendant of it, and a subtree
    /// entry (`"*.apex"`) was registered for the apex.
    Subtree {
        /// The stored apex domain. The wildcard form is
        /// `apex.try_as_wildcard().unwrap()`.
        apex: Domain,
    },
}

impl<T: fmt::Debug> fmt::Debug for DomainMatch<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DomainMatch")
            .field("value", &self.value)
            .field("kind", &self.kind)
            .finish()
    }
}

impl<T: PartialEq> PartialEq for DomainMatch<'_, T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value && self.kind == other.kind
    }
}

impl<T: PartialEq + Eq> Eq for DomainMatch<'_, T> {}

impl<T> DomainTrie<T> {
    #[inline]
    /// Create a new [`DomainTrie`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Determine if the Trie contains 0 key-value pairs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.trie.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.trie.len()
    }

    /// Consume `self` and insert the given domain paired with the input value.
    ///
    /// See [`Self::insert_domain`] for the matching semantics (wildcard
    /// `*.x` is stored as subtree at `x`; plain `x` is stored as exact).
    #[must_use]
    pub fn with_insert_domain(mut self, domain: impl AsDomainRef, value: T) -> Self {
        self.insert_domain(domain, value);
        self
    }

    /// Insert the given domain paired with the input value.
    ///
    /// Dispatch:
    ///
    /// - If the input is a wildcard (`"*.foo.bar"`), the `*.` prefix is
    ///   stripped and the value is stored as a **subtree** entry at
    ///   `foo.bar` — it matches `foo.bar` and every domain under it.
    /// - Otherwise the value is stored as an **exact** entry — only the
    ///   stored name matches.
    ///
    /// Inserting at a name that already has a value of the same kind
    /// overwrites it. Exact and subtree slots at the same name are
    /// independent.
    pub fn insert_domain(&mut self, domain: impl AsDomainRef, value: T) -> &mut Self {
        let s = domain.domain_as_str();
        let (apex, is_subtree) = match s.strip_prefix("*.") {
            Some(rest) => (rest, true),
            None => (s, false),
        };
        let reversed = reverse_domain(apex);
        if let Some(node) = self.trie.get_mut(&reversed) {
            node.merge_from(value, is_subtree);
        } else {
            let mut node = NodeData::empty();
            node.merge_from(value, is_subtree);
            self.trie.insert(reversed, node);
        }
        self
    }

    /// Consume `self` and insert the given domains paired with the input value.
    ///
    /// Each domain is dispatched through [`Self::insert_domain`].
    #[must_use]
    pub fn with_insert_domain_iter<I, S>(mut self, domains: I, value: T) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsDomainRef,
        T: Clone,
    {
        self.insert_domain_iter(domains, value);
        self
    }

    /// Insert the given domains paired with the input value.
    pub fn insert_domain_iter<I, S>(&mut self, domains: I, value: T) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsDomainRef,
        T: Clone,
    {
        let mut iter = domains.into_iter();
        if let Some(mut prev) = iter.next() {
            for curr in iter {
                self.insert_domain(prev, value.clone());
                prev = curr;
            }
            self.insert_domain(prev, value);
        }
        self
    }

    /// Extend this [`DomainTrie`] with the given pairs.
    pub fn extend<I, S>(&mut self, iter: I) -> &mut Self
    where
        I: IntoIterator<Item = (S, T)>,
        S: AsDomainRef,
    {
        for (domain, value) in iter {
            self.insert_domain(domain, value);
        }
        self
    }

    #[inline]
    /// Returns true if the input domain matches at least one entry in this
    /// trie (exact entry on exact key, or subtree entry on ancestor).
    pub fn is_match_parent(&self, domain: impl AsDomainRef) -> bool {
        self.match_parent(domain).is_some()
    }

    /// Returns the value for the most-specific entry that matches `domain`.
    ///
    /// "Matches" is mode-aware:
    /// - An **exact** entry at name `N` matches only the query `N`.
    /// - A **subtree** entry at name `N` matches `N` and every descendant.
    ///
    /// `is_exact` on the returned [`DomainParentMatch`] is `true` iff the
    /// query equals the stored name.
    pub fn match_parent(&self, domain: impl AsDomainRef) -> Option<DomainParentMatch<'_, T>> {
        let mut key = reverse_domain(domain.domain_as_str());
        let mut is_exact = true;
        loop {
            if let Some(node) = self.trie.get(&key) {
                let slot = if is_exact {
                    node.exact.as_ref().or(node.subtree.as_ref())
                } else {
                    node.subtree.as_ref()
                };
                if let Some(value) = slot {
                    return Some(DomainParentMatch { value, is_exact });
                }
            }
            // Truncate to the next ancestor by dropping the rightmost label.
            // key looks like "com.example.foo." — drop trailing "." then
            // everything after the previous ".".
            if !truncate_to_parent(&mut key) {
                return None;
            }
            is_exact = false;
        }
    }

    /// Look up `domain` and return a [`DomainMatch`] describing the most-
    /// specific entry that matches it, along with whether the match was
    /// exact or via a subtree apex.
    ///
    /// Same matching rules as [`Self::match_parent`]:
    /// - exact entries match only their stored name,
    /// - subtree entries match their apex plus every descendant.
    ///
    /// Returns `None` if no entry matches.
    pub fn get(&self, domain: impl AsDomainRef) -> Option<DomainMatch<'_, T>> {
        let mut key = reverse_domain(domain.domain_as_str());
        // Track the "apex" key separately so we can recover the stored apex
        // domain when we hit a subtree slot.
        let mut is_first = true;
        loop {
            if let Some(node) = self.trie.get(&key) {
                if is_first && let Some(value) = node.exact.as_ref() {
                    return Some(DomainMatch {
                        value,
                        kind: MatchKind::Exact,
                    });
                }
                if let Some(value) = node.subtree.as_ref() {
                    return Some(DomainMatch {
                        value,
                        kind: MatchKind::Subtree {
                            apex: reversed_key_to_domain(&key),
                        },
                    });
                }
            }
            if !truncate_to_parent(&mut key) {
                return None;
            }
            is_first = false;
        }
    }

    #[inline]
    /// Returns `true` if `domain` is stored as an exact (or subtree-apex)
    /// entry in this trie.
    pub fn is_match_exact(&self, domain: impl AsDomainRef) -> bool {
        self.match_exact(domain).is_some()
    }

    /// Returns the value stored for the exact `domain` (either its
    /// `exact` slot, or its `subtree` slot if `exact` is unset).
    pub fn match_exact(&self, domain: impl AsDomainRef) -> Option<&T> {
        let key = reverse_domain(domain.domain_as_str());
        self.trie
            .get(&key)
            .and_then(|n| n.exact.as_ref().or(n.subtree.as_ref()))
    }

    /// Iterate over the domains and values stored in this Trie.
    ///
    /// Each stored entry yields one item per slot that is set: a subtree
    /// entry yields the apex domain as a wildcard `"*.apex"`, an exact
    /// entry yields the apex itself.
    pub fn iter(&self) -> impl Iterator<Item = (Domain, &T)> {
        self.trie.iter().flat_map(|(s, node)| {
            let apex = reversed_key_to_domain(s);
            let exact = node.exact.as_ref().map(|v| (apex.clone(), v));
            let subtree = node.subtree.as_ref().map(|v| {
                // Build the "*.apex" form via the builder so the result is a
                // properly-validated Domain.
                let wildcard = apex.try_as_wildcard().unwrap_or_else(|_| apex.clone());
                (wildcard, v)
            });
            exact.into_iter().chain(subtree)
        })
    }
}

impl<T> NodeData<T> {
    fn merge_from(&mut self, value: T, is_subtree: bool) {
        if is_subtree {
            self.subtree = Some(value);
        } else {
            self.exact = Some(value);
        }
    }
}

/// Reverse a domain's labels and append the boundary `.` token used by the
/// radix tree to prevent prefix collisions (so `"gel.com"` doesn't match
/// `"kegel.com"`).
///
/// Result for `"example.com"` is `"com.example."`.
fn reverse_domain(domain: &str) -> String {
    let from = domain.trim_matches('.');
    // Pre-cap: same byte count as input + one trailing dot.
    let mut out = String::with_capacity(from.len() + 1);
    let mut parts = from.split('.').rev();
    if let Some(first) = parts.next() {
        out.push_str(first);
    }
    for part in parts {
        out.push('.');
        out.push_str(part);
    }
    out.push('.');
    out
}

/// In-place truncation: turn `"com.example.foo."` into `"com.example."`.
/// Returns `false` if there is no further ancestor (single-label or empty).
fn truncate_to_parent(key: &mut String) -> bool {
    // Drop trailing '.' (always present in our keys).
    if key.pop() != Some('.') {
        return false;
    }
    match key.rfind('.') {
        Some(pos) => {
            key.truncate(pos + 1);
            true
        }
        None => {
            // No more dots — was a single-label name. Walking up from a
            // single label has no ancestor.
            key.clear();
            false
        }
    }
}

/// Reverse a stored reversed-form key back into a `Domain`.
fn reversed_key_to_domain(reversed: &str) -> Domain {
    let from = reversed.trim_matches('.');
    let mut builder = SmolStrBuilder::new();
    let mut iter = from.split('.').rev();
    if let Some(part) = iter.next() {
        builder.push_str(part);
    }
    for part in iter {
        builder.push('.');
        builder.push_str(part);
    }
    // Safety: every key in the trie came from a validated Domain via
    // `insert_domain`, so reversing the labels yields a valid Domain again.
    unsafe { Domain::from_maybe_borrowed_unchecked(builder.finish()) }
}

impl<S, T> FromIterator<(S, T)> for DomainTrie<T>
where
    S: AsDomainRef,
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
    fn exact_does_not_match_descendants() {
        // Bare insert is exact-only.
        let m = DomainTrie::new().with_insert_domain("example.com", "v");
        assert_eq!(
            m.match_parent("example.com"),
            Some(DomainParentMatch {
                value: &"v",
                is_exact: true
            })
        );
        assert_eq!(m.match_parent("foo.example.com"), None);
        assert_eq!(m.match_parent("bar.foo.example.com"), None);
    }

    #[test]
    fn wildcard_matches_apex_and_descendants() {
        // Wildcard input *.x stores subtree at x.
        let m = DomainTrie::new().with_insert_domain("*.example.com", "v");
        assert_eq!(
            m.match_parent("example.com"),
            Some(DomainParentMatch {
                value: &"v",
                is_exact: true
            })
        );
        assert_eq!(
            m.match_parent("foo.example.com"),
            Some(DomainParentMatch {
                value: &"v",
                is_exact: false
            })
        );
        assert_eq!(
            m.match_parent("a.b.example.com"),
            Some(DomainParentMatch {
                value: &"v",
                is_exact: false
            })
        );
        assert_eq!(m.match_parent("example.org"), None);
    }

    #[test]
    fn exact_and_subtree_coexist_at_same_name() {
        let mut m = DomainTrie::new();
        m.insert_domain("example.com", "exact");
        m.insert_domain("*.example.com", "subtree");

        // exact-key query prefers the exact slot
        assert_eq!(
            m.match_parent("example.com"),
            Some(DomainParentMatch {
                value: &"exact",
                is_exact: true
            })
        );
        // descendant query falls back to subtree
        assert_eq!(
            m.match_parent("foo.example.com"),
            Some(DomainParentMatch {
                value: &"subtree",
                is_exact: false
            })
        );
    }

    #[test]
    fn deepest_exact_does_not_shadow_higher_subtree() {
        // The radix_trie quirk: an exact-only deeper node should not block
        // a subtree match higher up.
        let mut m = DomainTrie::new();
        m.insert_domain("*.example.com", "subtree");
        m.insert_domain("api.example.com", "exact-deep");

        // Direct exact hit:
        assert_eq!(
            m.match_parent("api.example.com"),
            Some(DomainParentMatch {
                value: &"exact-deep",
                is_exact: true
            })
        );
        // Descendant of the exact-only node — should NOT match the
        // exact-deep value; must fall back to the subtree higher up.
        assert_eq!(
            m.match_parent("v1.api.example.com"),
            Some(DomainParentMatch {
                value: &"subtree",
                is_exact: false
            })
        );
    }

    #[test]
    fn most_specific_subtree_wins() {
        let m = DomainTrie::new()
            .with_insert_domain("*.example.com", "outer")
            .with_insert_domain("*.bar.example.com", "inner");

        assert_eq!(
            m.match_parent("foo.bar.example.com"),
            Some(DomainParentMatch {
                value: &"inner",
                is_exact: false
            })
        );
        assert_eq!(
            m.match_parent("bar.example.com"),
            Some(DomainParentMatch {
                value: &"inner",
                is_exact: true
            })
        );
        assert_eq!(
            m.match_parent("baz.example.com"),
            Some(DomainParentMatch {
                value: &"outer",
                is_exact: false
            })
        );
    }

    #[test]
    fn match_exact_only_hits_stored_name() {
        let m = DomainTrie::new()
            .with_insert_domain("example.com", "v1")
            .with_insert_domain("*.other.com", "v2");
        assert_eq!(m.match_exact("example.com"), Some(&"v1"));
        assert_eq!(m.match_exact("other.com"), Some(&"v2"));
        // descendants don't count for match_exact
        assert_eq!(m.match_exact("foo.example.com"), None);
        assert_eq!(m.match_exact("foo.other.com"), None);
    }

    #[test]
    fn no_label_boundary_confusion() {
        let m = DomainTrie::new().with_insert_domain("*.example.com", "v");
        // bazfoo.bar.example.com is a descendant of example.com — should match.
        assert_eq!(
            m.match_parent("bazfoo.bar.example.com"),
            Some(DomainParentMatch {
                value: &"v",
                is_exact: false
            })
        );
        // gel.com is NOT a descendant of kegel.com.
        let m2 = DomainTrie::new().with_insert_domain("*.kegel.com", "v");
        assert_eq!(m2.match_parent("gel.com"), None);
    }

    #[test]
    fn get_returns_kind_exact_for_exact_entry() {
        let m = DomainTrie::new().with_insert_domain("example.com", "v");
        let hit = m.get("example.com").unwrap();
        assert_eq!(hit.value, &"v");
        assert_eq!(hit.kind, MatchKind::Exact);
        assert!(m.get("foo.example.com").is_none());
    }

    #[test]
    fn get_returns_kind_subtree_with_apex_for_subtree_entry() {
        let m = DomainTrie::new().with_insert_domain("*.example.com", "v");
        let hit_apex = m.get("example.com").unwrap();
        let hit_child = m.get("a.b.example.com").unwrap();
        assert_eq!(hit_apex.value, &"v");
        assert_eq!(
            hit_apex.kind,
            MatchKind::Subtree {
                apex: Domain::from_static("example.com")
            }
        );
        assert_eq!(hit_child.value, &"v");
        assert_eq!(
            hit_child.kind,
            MatchKind::Subtree {
                apex: Domain::from_static("example.com")
            }
        );
        // And the wildcard form is recoverable.
        if let MatchKind::Subtree { apex } = &hit_child.kind {
            assert_eq!(
                apex.try_as_wildcard().unwrap(),
                Domain::from_static("*.example.com")
            );
        }
    }

    #[test]
    fn get_prefers_exact_over_subtree_at_same_name() {
        let mut m = DomainTrie::new();
        m.insert_domain("example.com", "exact");
        m.insert_domain("*.example.com", "subtree");
        let hit = m.get("example.com").unwrap();
        assert_eq!(hit.value, &"exact");
        assert_eq!(hit.kind, MatchKind::Exact);
        // Descendant still gets subtree.
        let hit_child = m.get("foo.example.com").unwrap();
        assert_eq!(hit_child.value, &"subtree");
        assert!(matches!(hit_child.kind, MatchKind::Subtree { .. }));
    }

    #[test]
    fn get_does_not_let_exact_node_shadow_higher_subtree() {
        let mut m = DomainTrie::new();
        m.insert_domain("*.example.com", "subtree");
        m.insert_domain("api.example.com", "exact-deep");

        let hit = m.get("v1.api.example.com").unwrap();
        assert_eq!(hit.value, &"subtree");
        assert_eq!(
            hit.kind,
            MatchKind::Subtree {
                apex: Domain::from_static("example.com")
            }
        );
    }

    #[test]
    fn iter_emits_apex_and_wildcard_forms() {
        let m = DomainTrie::new()
            .with_insert_domain("example.com", "exact")
            .with_insert_domain("*.other.com", "subtree");

        let mut out: Vec<_> = m.iter().map(|(d, v)| (d.to_string(), *v)).collect();
        out.sort();
        assert_eq!(
            out,
            vec![
                ("*.other.com".to_owned(), "subtree"),
                ("example.com".to_owned(), "exact"),
            ]
        );
    }
}
