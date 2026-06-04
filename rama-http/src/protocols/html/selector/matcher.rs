//! Matching of parsed selectors against an element tree.
//!
//! The matcher walks a complex selector right-to-left and is allocation-
//! free: name, class, id and attribute comparisons all operate on borrowed
//! string slices supplied by the [`SelectorSubject`] implementation.

use super::ast::{
    AttributeOperator, AttributeSelector, CaseSensitivity, Combinator, ComplexSelector, Compound,
    NthType, Selector, SelectorPart,
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
    match_from(&complex.parts, complex.parts.len() - 1, subject)
}

/// Matches `parts[..=idx]` against `subject` as the right-most compound,
/// recursing leftward through the combinators.
fn match_from<S: SelectorSubject>(parts: &[SelectorPart], idx: usize, subject: &S) -> bool {
    let part = &parts[idx];
    if !compound_matches(&part.compound, subject) {
        return false;
    }
    if idx == 0 {
        return true;
    }

    let Some(combinator) = part.combinator else {
        return false;
    };
    match combinator {
        Combinator::Child => subject
            .parent()
            .is_some_and(|parent| match_from(parts, idx - 1, &parent)),
        Combinator::Descendant => {
            let mut ancestor = subject.parent();
            while let Some(node) = ancestor {
                if match_from(parts, idx - 1, &node) {
                    return true;
                }
                ancestor = node.parent();
            }
            false
        }
    }
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
    let Some(actual) = subject.attribute(&selector.name) else {
        return false;
    };
    let expected = &*selector.value;
    let ci = matches!(selector.case, CaseSensitivity::AsciiCaseInsensitive);
    match selector.operator {
        None => true,
        Some(AttributeOperator::Equals) => str_eq(actual, expected, ci),
        Some(AttributeOperator::Includes) => {
            !expected.is_empty()
                && !expected.contains(char::is_whitespace)
                && actual
                    .split_ascii_whitespace()
                    .any(|token| str_eq(token, expected, ci))
        }
        Some(AttributeOperator::DashMatch) => {
            str_eq(actual, expected, ci)
                || (actual.len() > expected.len()
                    && starts_with(actual, expected, ci)
                    && actual.as_bytes().get(expected.len()) == Some(&b'-'))
        }
        Some(AttributeOperator::Prefix) => {
            !expected.is_empty() && starts_with(actual, expected, ci)
        }
        Some(AttributeOperator::Suffix) => !expected.is_empty() && ends_with(actual, expected, ci),
        Some(AttributeOperator::Substring) => {
            !expected.is_empty() && contains(actual, expected, ci)
        }
    }
}

fn str_eq(a: &str, b: &str, case_insensitive: bool) -> bool {
    if case_insensitive {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

fn starts_with(haystack: &str, needle: &str, case_insensitive: bool) -> bool {
    match haystack.as_bytes().get(..needle.len()) {
        Some(head) => bytes_eq(head, needle.as_bytes(), case_insensitive),
        None => false,
    }
}

fn ends_with(haystack: &str, needle: &str, case_insensitive: bool) -> bool {
    let Some(start) = haystack.len().checked_sub(needle.len()) else {
        return false;
    };
    match haystack.as_bytes().get(start..) {
        Some(tail) => bytes_eq(tail, needle.as_bytes(), case_insensitive),
        None => false,
    }
}

fn contains(haystack: &str, needle: &str, case_insensitive: bool) -> bool {
    if case_insensitive {
        let h = haystack.as_bytes();
        let n = needle.as_bytes();
        if n.len() > h.len() {
            return false;
        }
        (0..=h.len() - n.len()).any(|i| match h.get(i..i + n.len()) {
            Some(window) => bytes_eq(window, n, true),
            None => false,
        })
    } else {
        haystack.contains(needle)
    }
}

fn bytes_eq(a: &[u8], b: &[u8], case_insensitive: bool) -> bool {
    if case_insensitive {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}
