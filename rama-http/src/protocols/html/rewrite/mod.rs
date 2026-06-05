//! Selector-driven HTML rewriting.
//!
//! The public entry point is [`HtmlRewriter`] (and the [`rewrite_str`]
//! one-shot). Internally, a streaming selector matcher is fed start/end tags
//! as they are tokenized and reports, at each start tag, which registered
//! selectors match the element being opened — without building a DOM. It
//! maintains an open-element stack and, per selector, two bitmasks:
//!
//!   * `completed` — which compound-prefixes are matched ending at this
//!     element (a child combinator reads its parent's `completed`);
//!   * `desc_ready` — which prefixes are available to descendants (a
//!     descendant combinator reads its ancestor's `desc_ready`).
//!
//! It underpins the selector-driven [`HtmlRewriter`].

use super::selector::Selector;
use super::selector::ast::{Combinator, ComplexSelector, Compound, NthType};
use super::tokenizer::{LocalNameHash, StartTag};

mod element;
mod rewriter;

#[cfg(test)]
mod tests;

pub use self::element::{Element, ElementContentHandler, HandlerResult};
pub use self::rewriter::{ElementContentHandlers, HtmlRewriter, rewrite_str};

/// Selectors with more compounds than this can't be represented in the
/// `u64` match bitmask; they simply never match (absurd in practice).
const MAX_COMPOUNDS: usize = 63;

// HTML void elements (the current WHATWG list): they never have children, so
// they are not pushed onto the open-element stack.
//
// This mirrors the compile-time list in `rama-http-macros` (`is_void_tag`);
// the two can't share a single const across the proc-macro/runtime boundary
// (that crate only depends on proc-macro libraries). `param` is intentionally
// absent — it is obsolete and not a void element in the current spec.
const VOID_AREA: LocalNameHash = LocalNameHash::from_static(b"area");
const VOID_BASE: LocalNameHash = LocalNameHash::from_static(b"base");
const VOID_BR: LocalNameHash = LocalNameHash::from_static(b"br");
const VOID_COL: LocalNameHash = LocalNameHash::from_static(b"col");
const VOID_EMBED: LocalNameHash = LocalNameHash::from_static(b"embed");
const VOID_HR: LocalNameHash = LocalNameHash::from_static(b"hr");
const VOID_IMG: LocalNameHash = LocalNameHash::from_static(b"img");
const VOID_INPUT: LocalNameHash = LocalNameHash::from_static(b"input");
const VOID_LINK: LocalNameHash = LocalNameHash::from_static(b"link");
const VOID_META: LocalNameHash = LocalNameHash::from_static(b"meta");
const VOID_SOURCE: LocalNameHash = LocalNameHash::from_static(b"source");
const VOID_TRACK: LocalNameHash = LocalNameHash::from_static(b"track");
const VOID_WBR: LocalNameHash = LocalNameHash::from_static(b"wbr");

/// Whether `name` is an HTML void element. A `match` over the precomputed
/// name hashes lets the compiler build a decision tree (a handful of integer
/// compares), rather than a runtime slice scan.
fn is_void(name: LocalNameHash) -> bool {
    matches!(
        name,
        VOID_AREA
            | VOID_BASE
            | VOID_BR
            | VOID_COL
            | VOID_EMBED
            | VOID_HR
            | VOID_IMG
            | VOID_INPUT
            | VOID_LINK
            | VOID_META
            | VOID_SOURCE
            | VOID_TRACK
            | VOID_WBR
    )
}

/// Per-selector NFA state carried by an open element.
#[derive(Debug, Clone, Copy)]
struct SelectorState {
    /// Bit `j` set ⇒ the first `j` compounds matched ending at this element.
    completed: u64,
    /// Bit `i` set ⇒ prefix `i` is available to descendants (for descendant
    /// combinators).
    desc_ready: u64,
}

impl SelectorState {
    const ROOT: Self = Self {
        completed: 1,
        desc_ready: 1,
    };
}

/// An open element on the matching stack.
#[derive(Debug)]
struct Frame {
    name: LocalNameHash,
    child_count: usize,
    type_counts: Vec<(LocalNameHash, usize)>,
}

impl Frame {
    fn new(name: LocalNameHash) -> Self {
        Self {
            name,
            child_count: 0,
            type_counts: Vec::new(),
        }
    }

    fn type_count(&self, name: LocalNameHash) -> usize {
        self.type_counts
            .iter()
            .find(|(n, _)| *n == name)
            .map_or(0, |(_, c)| *c)
    }

    fn record_child(&mut self, name: LocalNameHash, track_type: bool) {
        self.child_count += 1;
        // Per-type counts are only needed (and only allocate) when some
        // selector uses `:nth-of-type`.
        if track_type {
            if let Some(entry) = self.type_counts.iter_mut().find(|(n, _)| *n == name) {
                entry.1 += 1;
            } else {
                self.type_counts.push((name, 1));
            }
        }
    }
}

/// Matches a fixed set of selectors against a stream of start/end tags.
///
/// Internal to the rewriter; not part of the public API.
#[derive(Debug)]
pub(crate) struct SelectorMatcher {
    /// All complex selectors, flattened from the registered [`Selector`]s.
    selectors: Vec<ComplexSelector>,
    /// `owner[c]` is the index of the registered selector complex `c` came
    /// from (what [`SelectorMatcher::push_element`] reports).
    owner: Vec<usize>,
    stack: Vec<Frame>,
    /// Flat NFA state: row `r` (one per stack frame) holds `selectors.len()`
    /// entries at `[r * n .. (r + 1) * n]`.
    states: Vec<SelectorState>,
    /// Reused scratch for a child row.
    scratch: Vec<SelectorState>,
    /// Reused scratch for de-duplicating matched selector indices.
    matched: Vec<usize>,
    /// Whether any selector uses `:nth-of-type` (gates per-type counting,
    /// the only potential per-element allocation).
    tracks_type: bool,
}

impl SelectorMatcher {
    /// Builds a matcher for `selectors`. A start tag matching any complex
    /// selector of registered selector `i` reports `i`.
    #[must_use]
    pub(crate) fn new(selectors: &[Selector]) -> Self {
        let mut complexes = Vec::new();
        let mut owner = Vec::new();
        for (index, selector) in selectors.iter().enumerate() {
            for complex in &selector.selectors {
                complexes.push(complex.clone());
                owner.push(index);
            }
        }
        let n = complexes.len();
        let tracks_type = complexes.iter().any(complex_uses_nth_of_type);
        Self {
            selectors: complexes,
            owner,
            stack: vec![Frame::new(LocalNameHash::NONE)],
            states: vec![SelectorState::ROOT; n],
            scratch: Vec::with_capacity(n),
            matched: Vec::new(),
            tracks_type,
        }
    }

    /// Processes a start tag, invoking `on_match` once for each registered
    /// selector index that matches the element being opened.
    ///
    /// Returns `true` if the element opened a new scope (was pushed onto the
    /// stack) — i.e. it is neither void nor self-closing, so a matching end
    /// tag is expected. The rewriter uses this to keep its deferred-action
    /// stack in lockstep with the open-element stack.
    pub(crate) fn push_element(
        &mut self,
        tag: &StartTag<'_>,
        mut on_match: impl FnMut(usize),
    ) -> bool {
        let n = self.selectors.len();
        let name = tag.name_hash();
        let parent_index = self.stack.len() - 1;
        let parent = &self.stack[parent_index];
        let nth_child = parent.child_count + 1;
        // Only meaningful (and only computed) when a selector uses it.
        let nth_of_type = if self.tracks_type {
            parent.type_count(name) + 1
        } else {
            1
        };

        self.scratch.clear();
        self.matched.clear();
        let parent_row = parent_index * n;
        for s in 0..n {
            let parent_state = self.states[parent_row + s];
            let complex = &self.selectors[s];
            let (state, matched) =
                eval_selector(complex, parent_state, tag, nth_child, nth_of_type);
            if matched && !self.matched.contains(&self.owner[s]) {
                self.matched.push(self.owner[s]);
            }
            self.scratch.push(state);
        }
        for &index in &self.matched {
            on_match(index);
        }

        self.stack[parent_index].record_child(name, self.tracks_type);

        let opened = !is_void(name) && !tag.is_self_closing();
        if opened {
            self.stack.push(Frame::new(name));
            self.states.extend_from_slice(&self.scratch);
        }
        opened
    }

    /// Processes an end tag, popping the matching open element.
    ///
    /// Returns `true` if it closed an open scope (the top frame matched
    /// `name`); `false` for a stray/mismatched end tag that pops nothing.
    pub(crate) fn pop_element(&mut self, name: LocalNameHash) -> bool {
        if self.stack.len() > 1 && self.stack.last().is_some_and(|f| f.name == name) {
            self.stack.pop();
            let n = self.selectors.len();
            self.states.truncate(self.states.len() - n);
            true
        } else {
            false
        }
    }
}

fn complex_uses_nth_of_type(complex: &ComplexSelector) -> bool {
    complex
        .parts
        .iter()
        .any(|part| compound_uses_nth_of_type(&part.compound))
}

fn compound_uses_nth_of_type(compound: &Compound) -> bool {
    compound.nth.iter().any(|nth| nth.ty == NthType::OfType)
        || compound.negations.iter().any(compound_uses_nth_of_type)
}

/// Computes an element's NFA state for one complex selector, returning that
/// state and whether the whole selector matches the element.
fn eval_selector(
    complex: &ComplexSelector,
    parent: SelectorState,
    tag: &StartTag<'_>,
    nth_child: usize,
    nth_of_type: usize,
) -> (SelectorState, bool) {
    let k = complex.parts.len();
    if k == 0 || k > MAX_COMPOUNDS {
        return (SelectorState::ROOT, false);
    }

    // Which slots can be matched at this element (bit 0 always).
    let mut ready = 1u64;
    for i in 1..k {
        let bit = 1u64 << i;
        match complex.parts[i].combinator {
            Some(Combinator::Child) if parent.completed & bit != 0 => ready |= bit,
            Some(Combinator::Descendant) if parent.desc_ready & bit != 0 => ready |= bit,
            _ => {}
        }
    }

    // Which prefixes complete at this element (bit 0 = empty prefix).
    let mut completed = 1u64;
    for i in 0..k {
        if ready & (1u64 << i) != 0
            && compound_matches(&complex.parts[i].compound, tag, nth_child, nth_of_type)
        {
            completed |= 1u64 << (i + 1);
        }
    }
    let matched = completed & (1u64 << k) != 0;

    // What flows down to descendants (descendant combinators only).
    let mut desc_ready = 1u64;
    for i in 1..k {
        if complex.parts[i].combinator == Some(Combinator::Descendant) {
            let bit = 1u64 << i;
            if (completed | parent.desc_ready) & bit != 0 {
                desc_ready |= bit;
            }
        }
    }

    (
        SelectorState {
            completed,
            desc_ready,
        },
        matched,
    )
}

/// Whether a single compound selector matches the element `tag` (at the
/// given sibling positions). Combinators are handled by the caller.
fn compound_matches(
    compound: &Compound,
    tag: &StartTag<'_>,
    nth_child: usize,
    nth_of_type: usize,
) -> bool {
    if let Some(name) = &compound.name
        && !name.matches_bytes(tag.name())
    {
        return false;
    }
    if let Some(id) = &compound.id
        && attribute(tag, b"id") != Some(id.as_bytes())
    {
        return false;
    }
    for class in &compound.classes {
        let class = class.as_bytes();
        let present = attribute(tag, b"class")
            .is_some_and(|value| value.split(u8::is_ascii_whitespace).any(|c| c == class));
        if !present {
            return false;
        }
    }
    for attr in &compound.attributes {
        if !attribute(tag, attr.name.as_bytes()).is_some_and(|value| attr.matches_value(value)) {
            return false;
        }
    }
    for nth in &compound.nth {
        let index = match nth.ty {
            NthType::Child => nth_child,
            NthType::OfType => nth_of_type,
        };
        if !nth.matches_index(index) {
            return false;
        }
    }
    !compound
        .negations
        .iter()
        .any(|neg| compound_matches(neg, tag, nth_child, nth_of_type))
}

/// Looks up an attribute value by (ASCII case-insensitive) name.
fn attribute<'i>(tag: &StartTag<'i>, name: &[u8]) -> Option<&'i [u8]> {
    tag.attributes()
        .find(|attr| attr.name().eq_ignore_ascii_case(name))
        .map(|attr| attr.value())
}
