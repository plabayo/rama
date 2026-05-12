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

    /// Returns `true` if `domain` matches at least one entry in this trie.
    ///
    /// Cheaper than `self.get(domain).is_some()` — does not build the
    /// `MatchKind::Subtree { apex }` payload for subtree hits.
    pub fn is_match(&self, domain: impl AsDomainRef) -> bool {
        let mut key = reverse_domain(domain.domain_as_str());
        let mut is_first = true;
        loop {
            if let Some(node) = self.trie.get(&key) {
                if is_first && node.exact.is_some() {
                    return true;
                }
                if node.subtree.is_some() {
                    return true;
                }
            }
            if !truncate_to_parent(&mut key) {
                return false;
            }
            is_first = false;
        }
    }

    /// Returns the value for the most-specific entry that matches `domain`,
    /// without computing the apex for subtree matches.
    ///
    /// Cheaper than [`Self::get`] when the caller doesn't need the apex.
    /// Matching rules are identical to `get`.
    pub fn get_value(&self, domain: impl AsDomainRef) -> Option<&T> {
        let mut key = reverse_domain(domain.domain_as_str());
        let mut is_first = true;
        loop {
            if let Some(node) = self.trie.get(&key) {
                if is_first && let Some(v) = node.exact.as_ref() {
                    return Some(v);
                }
                if let Some(v) = node.subtree.as_ref() {
                    return Some(v);
                }
            }
            if !truncate_to_parent(&mut key) {
                return None;
            }
            is_first = false;
        }
    }

    /// Look up `domain` and return a [`DomainMatch`] describing the most-
    /// specific entry that matches it, along with whether the match was
    /// exact or via a subtree apex.
    ///
    /// Matching rules:
    /// - **Exact** entries match only their stored name.
    /// - **Subtree** entries match their apex plus every descendant.
    ///
    /// For exact-only lookups, use
    /// `get(d).filter(|m| matches!(m.kind, MatchKind::Exact))`.
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

    /// Returns the value stored for the exact `domain` (either its
    /// `exact` slot, or its `subtree` slot if `exact` is unset).
    ///
    /// Single-key direct lookup — not the same as [`Self::get`], which
    /// walks ancestors.
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
/// radix tree to prevent prefix collisions.
///
/// Result for `"example.com"` is `"com.example."`.
///
/// # Why the trailing `.` is load-bearing
///
/// `radix_trie` matches byte prefixes. Without the sentinel, a stored
/// reversed key like `"com.example"` would be a byte-prefix of a query like
/// `"com.examplea"` (because `"examplea"` byte-starts with `"example"`),
/// so `get_ancestor("com.examplea")` would falsely return the entry stored
/// for `example.com` as an ancestor of `examplea.com`. The trailing `.`
/// forces a mismatch at the label boundary (byte 11: `.` vs `a`), keeping
/// the match strictly per-label. **Do not remove it.** The
/// `regression_no_byte_prefix_false_match` test in this module guards it.
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
    if let Some(pos) = key.rfind('.') {
        key.truncate(pos + 1);
        true
    } else {
        // No more dots — was a single-label name. Walking up from a single
        // label has no ancestor.
        key.clear();
        false
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

    fn exact_match<'a>(value: &'a &'static str) -> DomainMatch<'a, &'static str> {
        DomainMatch {
            value,
            kind: MatchKind::Exact,
        }
    }

    fn subtree_match<'a>(
        value: &'a &'static str,
        apex: &'static str,
    ) -> DomainMatch<'a, &'static str> {
        DomainMatch {
            value,
            kind: MatchKind::Subtree {
                apex: Domain::from_static(apex),
            },
        }
    }

    #[test]
    fn exact_does_not_match_descendants() {
        // Bare insert is exact-only.
        let m = DomainTrie::new().with_insert_domain("example.com", "v");
        assert_eq!(m.get("example.com"), Some(exact_match(&"v")));
        assert!(m.get("foo.example.com").is_none());
        assert!(m.get("bar.foo.example.com").is_none());
    }

    #[test]
    fn wildcard_matches_apex_and_descendants() {
        let m = DomainTrie::new().with_insert_domain("*.example.com", "v");
        assert_eq!(
            m.get("example.com"),
            Some(subtree_match(&"v", "example.com"))
        );
        assert_eq!(
            m.get("foo.example.com"),
            Some(subtree_match(&"v", "example.com"))
        );
        assert_eq!(
            m.get("a.b.example.com"),
            Some(subtree_match(&"v", "example.com"))
        );
        assert!(m.get("example.org").is_none());
    }

    #[test]
    fn exact_and_subtree_coexist_at_same_name() {
        let mut m = DomainTrie::new();
        m.insert_domain("example.com", "exact");
        m.insert_domain("*.example.com", "subtree");

        assert_eq!(m.get("example.com"), Some(exact_match(&"exact")));
        assert_eq!(
            m.get("foo.example.com"),
            Some(subtree_match(&"subtree", "example.com"))
        );
    }

    #[test]
    fn deepest_exact_does_not_shadow_higher_subtree() {
        let mut m = DomainTrie::new();
        m.insert_domain("*.example.com", "subtree");
        m.insert_domain("api.example.com", "exact-deep");

        assert_eq!(m.get("api.example.com"), Some(exact_match(&"exact-deep")));
        // Descendant of the exact-only node — falls back to subtree higher up.
        assert_eq!(
            m.get("v1.api.example.com"),
            Some(subtree_match(&"subtree", "example.com"))
        );
    }

    #[test]
    fn most_specific_subtree_wins() {
        let m = DomainTrie::new()
            .with_insert_domain("*.example.com", "outer")
            .with_insert_domain("*.bar.example.com", "inner");

        assert_eq!(
            m.get("foo.bar.example.com"),
            Some(subtree_match(&"inner", "bar.example.com"))
        );
        assert_eq!(
            m.get("bar.example.com"),
            Some(subtree_match(&"inner", "bar.example.com"))
        );
        assert_eq!(
            m.get("baz.example.com"),
            Some(subtree_match(&"outer", "example.com"))
        );
    }

    #[test]
    fn is_match_shortcut() {
        let m = DomainTrie::new()
            .with_insert_domain("example.com", "v1")
            .with_insert_domain("*.other.com", "v2");
        assert!(m.is_match("example.com"));
        assert!(!m.is_match("foo.example.com"));
        assert!(m.is_match("other.com"));
        assert!(m.is_match("any.thing.other.com"));
        assert!(!m.is_match("nope.org"));
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
            m.get("bazfoo.bar.example.com"),
            Some(subtree_match(&"v", "example.com"))
        );
        // gel.com is NOT a descendant of kegel.com.
        let m2 = DomainTrie::new().with_insert_domain("*.kegel.com", "v");
        assert!(m2.get("gel.com").is_none());
    }

    /// Regression guard for the trailing-`.` sentinel in `reverse_domain`.
    ///
    /// `examplea.com` is NOT a descendant of `example.com`, but its reversed
    /// form `"com.examplea"` has `"com.example"` as a byte-prefix. Without
    /// the sentinel the radix_trie would falsely return the entry stored
    /// for `*.example.com` here. If this test starts passing without the
    /// sentinel being present in `reverse_domain`, the sentinel was removed
    /// (silently breaking correctness) — re-add it.
    #[test]
    fn regression_no_byte_prefix_false_match() {
        let m = DomainTrie::new().with_insert_domain("*.example.com", "v");
        // Single-label sibling whose reversed form byte-extends "example".
        assert!(m.get("examplea.com").is_none());
        // Same shape, but as a deeper descendant — sentinel must still fire.
        assert!(m.get("foo.examplea.com").is_none());

        // Sanity: a label that *prepends* a char (different at the start of
        // the label, not the end) was never at risk — included so the
        // regression test documents the contrast.
        assert!(m.get("aexample.com").is_none());
        assert!(m.get("foo.aexample.com").is_none());

        // And the legitimate match still works.
        assert_eq!(
            m.get("foo.example.com"),
            Some(subtree_match(&"v", "example.com"))
        );
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
