//! Matching of parsed selectors against an element tree.
//!
//! The matcher walks a complex selector right-to-left and is allocation-
//! free: name, class, id and attribute comparisons all operate on borrowed
//! string slices supplied by the [`SelectorSubject`] implementation.

use super::ast::{
    AttributeSelector, Combinator, ComplexSelector, Compound, NthType, Selector, SelectorPart,
};

/// A read-only view of an element, providing exactly what the selector
/// matcher needs. Implement it for your own tree to match selectors
/// against it, or use the in-memory [`Dom`](super::Dom).
///
/// `Self` is expected to be a cheap handle (e.g. an index into an arena),
/// since [`parent`](SelectorSubject::parent) returns it by value.
///
/// Attribute and tag names are matched ASCII case-insensitively (per HTML),
/// while class names, ids and attribute *values* are case-sensitive by
/// default. The `name` passed to [`attribute`](SelectorSubject::attribute)
/// is already ASCII-lowercased.
pub trait SelectorSubject: Sized {
    /// The element's tag name (any ASCII case).
    fn local_name(&self) -> &str;

    /// The value of the attribute with the given (ASCII-lowercased) name.
    fn attribute(&self, name: &str) -> Option<&str>;

    /// The element's parent, if any.
    fn parent(&self) -> Option<Self>;

    /// The element's 1-based position among all element siblings
    /// (for `:nth-child`). A root element returns `1`.
    fn nth_child_index(&self) -> usize;

    /// The element's 1-based position among element siblings of the same
    /// type (for `:nth-of-type`). A root element returns `1`.
    fn nth_of_type_index(&self) -> usize;

    /// Whether the element has the given (case-sensitive) id.
    ///
    /// Defaults to an exact comparison against the `id` attribute.
    fn has_id(&self, id: &str) -> bool {
        self.attribute("id") == Some(id)
    }

    /// Whether the element has the given (case-sensitive) class.
    ///
    /// Defaults to scanning the whitespace-separated `class` attribute.
    fn has_class(&self, class: &str) -> bool {
        self.attribute("class")
            .is_some_and(|value| value.split_ascii_whitespace().any(|c| c == class))
    }
}

impl Selector {
    /// Returns whether `subject` matches this selector.
    pub fn matches<S: SelectorSubject>(&self, subject: &S) -> bool {
        self.selectors.iter().any(|c| complex_matches(c, subject))
    }
}

fn complex_matches<S: SelectorSubject>(complex: &ComplexSelector, subject: &S) -> bool {
    match_from(&complex.parts, complex.parts.len() - 1, subject) == MatchResult::Matched
}

/// Outcome of matching a compound-prefix of a complex selector at an element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchResult {
    Matched,
    /// No match here; an enclosing descendant combinator may try a higher
    /// ancestor.
    NotMatched,
    /// No match here nor at any ancestor, so every enclosing descendant scan
    /// can stop too.
    NotMatchedGlobally,
}

/// Matches `parts[..=idx]` against `subject` as the right-most compound,
/// recursing leftward through the combinators.
fn match_from<S: SelectorSubject>(parts: &[SelectorPart], idx: usize, subject: &S) -> MatchResult {
    let part = &parts[idx];
    if !compound_matches(&part.compound, subject) {
        return MatchResult::NotMatched;
    }
    if idx == 0 {
        return MatchResult::Matched;
    }

    let Some(combinator) = part.combinator else {
        return MatchResult::NotMatched;
    };
    let mut candidate = subject.parent();
    while let Some(node) = candidate {
        match match_from(parts, idx - 1, &node) {
            MatchResult::NotMatched if combinator == Combinator::Descendant => {
                candidate = node.parent();
            }
            result => return result,
        }
    }
    // Out of ancestors: any other placement of the compounds to the right sits
    // higher and sees a subset of them, so stop re-walking ancestor chains.
    MatchResult::NotMatchedGlobally
}

fn compound_matches<S: SelectorSubject>(compound: &Compound, subject: &S) -> bool {
    if let Some(name) = &compound.name
        && !name.matches(subject.local_name())
    {
        return false;
    }
    if let Some(id) = &compound.id
        && !subject.has_id(id)
    {
        return false;
    }
    if !compound.classes.iter().all(|c| subject.has_class(c)) {
        return false;
    }
    if !compound
        .attributes
        .iter()
        .all(|a| attribute_matches(a, subject))
    {
        return false;
    }
    for nth in &compound.nth {
        let index = match nth.ty {
            NthType::Child => subject.nth_child_index(),
            NthType::OfType => subject.nth_of_type_index(),
        };
        if !nth.matches_index(index) {
            return false;
        }
    }
    // `:not(...)` — must match none of the negated compounds.
    !compound
        .negations
        .iter()
        .any(|neg| compound_matches(neg, subject))
}

fn attribute_matches<S: SelectorSubject>(selector: &AttributeSelector, subject: &S) -> bool {
    subject
        .attribute(&selector.name)
        .is_some_and(|actual| selector.matches_value(actual.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::{SelectorSubject, compound_matches};
    use crate::protocols::html::selector::ast::{Combinator, SelectorPart};
    use crate::protocols::html::selector::{Dom, NodeId, Selector};

    /// Exhaustive backtracking reference: every ancestor is tried for every
    /// descendant combinator, without pruning.
    fn exhaustive_match<S: SelectorSubject>(
        parts: &[SelectorPart],
        idx: usize,
        subject: &S,
    ) -> bool {
        if !compound_matches(&parts[idx].compound, subject) {
            return false;
        }
        if idx == 0 {
            return true;
        }
        match parts[idx].combinator {
            Some(Combinator::Child) => subject
                .parent()
                .is_some_and(|parent| exhaustive_match(parts, idx - 1, &parent)),
            Some(Combinator::Descendant) => {
                let mut ancestor = subject.parent();
                while let Some(node) = ancestor {
                    if exhaustive_match(parts, idx - 1, &node) {
                        return true;
                    }
                    ancestor = node.parent();
                }
                false
            }
            None => false,
        }
    }

    /// Every tree on `n` nodes whose parents precede their children.
    fn parent_arrays(n: usize) -> Vec<Vec<Option<usize>>> {
        let mut trees = vec![vec![None]];
        for i in 1..n {
            trees = trees
                .into_iter()
                .flat_map(|tree| {
                    (0..i).map(move |parent| {
                        let mut tree = tree.clone();
                        tree.push(Some(parent));
                        tree
                    })
                })
                .collect();
        }
        trees
    }

    /// Complex selectors of one to four compounds over `a` / `b` (plus `*` in
    /// the shorter ones), joined by every mix of child and descendant.
    fn selector_matrix() -> Vec<Selector> {
        let mut all: Vec<String> = vec!["a".into(), "b".into(), "*".into()];
        let mut frontier = all.clone();
        for len in 2..=4 {
            let compounds: &[&str] = if len < 3 {
                &["a", "b", "*"]
            } else {
                &["a", "b"]
            };
            frontier = frontier
                .iter()
                .flat_map(|prefix| {
                    [" ", " > "].into_iter().flat_map(move |combinator| {
                        compounds
                            .iter()
                            .map(move |compound| format!("{prefix}{combinator}{compound}"))
                    })
                })
                .collect();
            all.extend_from_slice(&frontier);
        }
        all.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn pruned_matching_agrees_with_exhaustive_backtracking() {
        let selectors = selector_matrix();
        for parents in parent_arrays(5) {
            for labels in 0u32..(1 << parents.len()) {
                let mut dom = Dom::new();
                let mut ids: Vec<NodeId> = Vec::with_capacity(parents.len());
                for (i, parent) in parents.iter().enumerate() {
                    let name = if labels & (1 << i) == 0 { "a" } else { "b" };
                    let id = match parent {
                        None => dom.create(name),
                        Some(p) => dom.append(ids[*p], name),
                    };
                    ids.push(id);
                }
                for selector in &selectors {
                    for &id in &ids {
                        let element = dom.element(id);
                        let expected = selector.selectors.iter().any(|complex| {
                            exhaustive_match(&complex.parts, complex.parts.len() - 1, &element)
                        });
                        assert_eq!(
                            selector.matches(&element),
                            expected,
                            "`{selector}` at {id:?} in tree {parents:?} labelled {labels:#b}"
                        );
                    }
                }
            }
        }
    }
}
