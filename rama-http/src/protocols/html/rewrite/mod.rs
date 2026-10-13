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
//! Ancestry comes from a model of the browser's stack of open elements (see
//! [`ScopeMode`]), which also decides how the tokenizer reads what follows a
//! start tag (raw text, CDATA), so the rewriter's view of where an element
//! ends cannot drift from the browser's. Attribute values are compared the
//! way browsers see them: character references decoded, class and id case
//! folded in quirks mode, and the values HTML treats case-insensitively
//! (`type`, `rel`, …) folded too.
//!
//! It underpins the selector-driven [`HtmlRewriter`].

use memchr::memchr;

use super::selector::Selector;
use super::selector::ast::{Combinator, ComplexSelector, Compound, NthType};
use super::tokenizer::{EndTag, StartTag, decode_attribute_value_into};

mod element;
mod rewriter;
mod tree;

pub use self::tree::ScopeMode;
use self::tree::{EndOutcome, OpenElements, Origin, Placement, StartPlan};

#[cfg(test)]
mod tests;

pub use self::element::{
    AttributeName, Element, ElementContentHandler, HandlerResult, InvalidAttributeName,
};
pub use self::rewriter::{ElementContentHandlers, HtmlRewriter, rewrite_str};

/// Selectors with more compounds than this can't be represented in the
/// `u64` match bitmask; they simply never match (absurd in practice).
const MAX_COMPOUNDS: usize = 63;

/// A complex selector's combinators as bit masks over its compounds: bit `i`
/// is set when compound `i` follows its predecessor by that combinator.
#[derive(Debug, Clone, Copy)]
struct Combinators {
    child: u64,
    descendant: u64,
    /// Bit `k` for `k` compounds: set in `completed` once the whole selector
    /// matched (0 for a selector too long to match).
    full: u64,
}

impl Combinators {
    fn of(complex: &ComplexSelector) -> Self {
        let k = complex.parts.len();
        let mut masks = Self {
            child: 0,
            descendant: 0,
            full: 0,
        };
        if k == 0 || k > MAX_COMPOUNDS {
            return masks;
        }
        masks.full = 1 << k;
        for (i, part) in complex.parts.iter().enumerate().skip(1) {
            match part.combinator {
                Some(Combinator::Child) => masks.child |= 1 << i,
                Some(Combinator::Descendant) => masks.descendant |= 1 << i,
                None => {}
            }
        }
        masks
    }
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

/// What a start tag did to the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pushed {
    /// No element: browsers drop the tag.
    Nothing,
    /// An element without children.
    Leaf,
    /// A new open element, at this frame index.
    Open(usize),
    /// An element that was already open, at this frame index; `claim` when
    /// the tag is the first to name it (only then is it matched).
    Merged { frame: usize, claim: bool },
}

/// The element a compound is matched against.
struct Candidate<'t, 'i> {
    tag: &'t StartTag<'i>,
    nth_child: usize,
    nth_of_type: usize,
    /// Class and id compare ASCII case-insensitively (a quirks-mode document).
    quirks: bool,
}

/// Matches a fixed set of selectors against a stream of start/end tags.
///
/// Internal to the rewriter; not part of the public API.
#[derive(Debug)]
pub(crate) struct SelectorMatcher {
    /// All complex selectors, flattened from the registered [`Selector`]s.
    selectors: Vec<ComplexSelector>,
    /// The combinators of each complex selector.
    combinators: Vec<Combinators>,
    /// `owner[c]` is the index of the registered selector complex `c` came
    /// from (what [`SelectorMatcher::push_element`] reports).
    owner: Vec<usize>,
    tree: OpenElements,
    /// Flat NFA state: row `r` holds `states_per_frame` ancestry states.
    states: Vec<SelectorState>,
    /// Single compounds do not need ancestry state.
    states_per_frame: usize,
    /// Reused scratch for a child row.
    scratch: Vec<SelectorState>,
    /// Reused scratch for de-duplicating matched selector indices.
    matched: Vec<usize>,
    /// The closed head's row, for tags browsers still insert into the head.
    head_row: Vec<SelectorState>,
    /// Reused scratch for decoding attribute values.
    decoded: Vec<u8>,
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
        let n = complexes
            .iter()
            .filter(|complex| complex.parts.len() != 1)
            .count();
        let combinators = complexes.iter().map(Combinators::of).collect();
        let mut tree = OpenElements::new();
        // Per-type counting is the only potential per-element allocation.
        tree.tracks_type = complexes.iter().any(complex_uses_nth_of_type);
        Self {
            selectors: complexes,
            combinators,
            owner,
            tree,
            states: vec![SelectorState::ROOT; n],
            states_per_frame: n,
            scratch: Vec::with_capacity(n),
            matched: Vec::new(),
            head_row: Vec::new(),
            decoded: Vec::new(),
        }
    }

    /// Matches the element of a start tag planned by [`Self::prepare_start`],
    /// invoking `on_match` once for each registered selector index that
    /// matches it, and opens it when it stays open.
    fn push_element(
        &mut self,
        tag: &StartTag<'_>,
        plan: StartPlan,
        mut on_match: impl FnMut(usize),
    ) -> Pushed {
        let (parent, (nth_child, nth_of_type), report) = match plan.placement {
            Placement::Dropped => return Pushed::Nothing,
            Placement::Merged { frame, claim } => {
                let element = self.tree.at(frame);
                (frame - 1, (element.position, element.type_position), claim)
            }
            Placement::Leaf(slot) | Placement::Open(slot, _) => {
                (slot.parent, self.tree.place(slot, plan.name), true)
            }
        };
        let candidate = Candidate {
            tag,
            nth_child: nth_child as usize,
            nth_of_type: nth_of_type as usize,
            quirks: self.tree.quirks(),
        };
        let Self {
            selectors,
            combinators,
            owner,
            states,
            states_per_frame,
            scratch,
            matched,
            decoded,
            ..
        } = self;
        scratch.clear();
        matched.clear();
        let parent_row = parent * *states_per_frame;
        let mut state_index = 0;
        for ((complex, &masks), &owner) in
            selectors.iter().zip(combinators.iter()).zip(owner.iter())
        {
            let hit = if let [part] = complex.parts.as_slice() {
                compound_matches(&part.compound, &candidate, decoded)
            } else {
                let parent_state = states[parent_row + state_index];
                state_index += 1;
                let (state, hit) = eval_selector(complex, masks, parent_state, &candidate, decoded);
                scratch.push(state);
                hit
            };
            if report && hit && !matched.contains(&owner) {
                matched.push(owner);
            }
        }
        for &index in matched.iter() {
            on_match(index);
        }

        match plan.placement {
            Placement::Open(_, element) => {
                self.tree.push(plan.name, element, (nth_child, nth_of_type));
                self.states.extend_from_slice(&self.scratch);
                Pushed::Open(self.tree.depth() - 1)
            }
            Placement::Merged { frame, claim } => {
                // Its attributes reach the ancestry of later descendants.
                let row = frame * self.states_per_frame;
                if let Some(states) = self.states.get_mut(row..row + self.states_per_frame) {
                    for (state, merged) in states.iter_mut().zip(&self.scratch) {
                        state.completed |= merged.completed;
                        state.desc_ready |= merged.desc_ready;
                    }
                }
                Pushed::Merged { frame, claim }
            }
            Placement::Leaf(_) => Pushed::Leaf,
            Placement::Dropped => Pushed::Nothing,
        }
    }

    /// Recounts the stack caches; every frame carries its state row.
    #[cfg(any(test, fuzzing))]
    fn assert_consistent(&self) {
        self.tree.assert_consistent();
        assert_eq!(
            self.states.len(),
            self.tree.depth() * self.states_per_frame,
            "one selector state row per frame"
        );
    }

    fn prepare_start(&mut self, tag: &StartTag<'_>) -> StartPlan {
        self.tree.start_tag(tag)
    }

    fn pop_element(&mut self, tag: &EndTag<'_>) -> EndOutcome {
        self.tree.end_tag(tag)
    }

    /// Applies a text run; see [`OpenElements::text`].
    fn text(&mut self, text: &[u8]) -> usize {
        self.tree.text(text)
    }

    fn finish(&mut self) {
        self.tree.finish();
    }

    /// Brings the per-frame selector state in line with the stack after a
    /// tree change, returning the lowest stack length the change reached:
    /// frames from there up closed, or are new elements browsers created
    /// without a tag.
    #[inline]
    fn sync(&mut self) -> usize {
        if !self.tree.changed() {
            return self.tree.depth();
        }
        let low = self.tree.take_low();
        let n = self.states_per_frame;
        if let Some(head) = self.tree.take_closed_head()
            && let Some(row) = self.states.get(head * n..(head + 1) * n)
        {
            self.head_row.clear();
            self.head_row.extend_from_slice(row);
        }
        self.states.truncate(low * n);
        if n != 0 && low < self.tree.depth() {
            self.sync_new_frames(low);
        }
        low
    }

    /// Computes the state rows of the frames from `low` up: elements browsers
    /// created without a tag, or the reopened head.
    fn sync_new_frames(&mut self, low: usize) {
        let n = self.states_per_frame;
        for index in low..self.tree.depth() {
            let frame = self.tree.at(index);
            if frame.origin == Origin::Reopened && self.head_row.len() == n {
                self.states.extend_from_slice(&self.head_row);
                continue;
            }
            let tag = StartTag::synthetic(frame.tag.name());
            let candidate = Candidate {
                tag: &tag,
                nth_child: frame.position as usize,
                nth_of_type: frame.type_position as usize,
                quirks: false,
            };
            let parent_row = (index - 1) * n;
            let mut state_index = 0;
            for (complex, &masks) in self.selectors.iter().zip(self.combinators.iter()) {
                if complex.parts.len() == 1 {
                    continue;
                }
                let parent_state = self.states[parent_row + state_index];
                state_index += 1;
                let (state, _) =
                    eval_selector(complex, masks, parent_state, &candidate, &mut self.decoded);
                self.states.push(state);
            }
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
#[inline]
fn eval_selector(
    complex: &ComplexSelector,
    masks: Combinators,
    parent: SelectorState,
    candidate: &Candidate<'_, '_>,
    decoded: &mut Vec<u8>,
) -> (SelectorState, bool) {
    if masks.full == 0 {
        return (SelectorState::ROOT, false);
    }
    // Which compounds can be matched at this element (bit 0 always): those
    // whose prefix completed at the parent (child) or an ancestor
    // (descendant).
    let ready = 1 | (parent.completed & masks.child) | (parent.desc_ready & masks.descendant);

    // Which prefixes complete at this element (bit 0 = empty prefix).
    let mut completed = 1u64;
    let mut pending = ready;
    while pending != 0 {
        let i = pending.trailing_zeros() as usize;
        pending &= pending - 1;
        if complex
            .parts
            .get(i)
            .is_some_and(|part| compound_matches(&part.compound, candidate, decoded))
        {
            completed |= 2 << i;
        }
    }

    // What flows down to descendants (descendant combinators only).
    let desc_ready = 1 | ((completed | parent.desc_ready) & masks.descendant);
    (
        SelectorState {
            completed,
            desc_ready,
        },
        completed & masks.full != 0,
    )
}

/// Whether a single compound selector matches the candidate element.
/// Combinators are handled by the caller.
fn compound_matches(
    compound: &Compound,
    candidate: &Candidate<'_, '_>,
    decoded: &mut Vec<u8>,
) -> bool {
    let tag = candidate.tag;
    if let Some(name) = &compound.name
        && !name.matches_tag(tag.name_hash(), tag.name())
    {
        return false;
    }
    if let Some(id) = &compound.id
        && !attribute_matches(tag, b"id", decoded, |value| {
            text_eq(value, id.as_bytes(), candidate.quirks)
        })
    {
        return false;
    }
    for class in &compound.classes {
        let class = class.as_bytes();
        let present = attribute_matches(tag, b"class", decoded, |value| {
            value
                .split(u8::is_ascii_whitespace)
                .any(|c| text_eq(c, class, candidate.quirks))
        });
        if !present {
            return false;
        }
    }
    for attr in &compound.attributes {
        if !attribute_matches(tag, attr.name.as_bytes(), decoded, |value| {
            attr.matches_value(value)
        }) {
            return false;
        }
    }
    for nth in &compound.nth {
        let index = match nth.ty {
            NthType::Child => candidate.nth_child,
            NthType::OfType => candidate.nth_of_type,
        };
        if !nth.matches_index(index) {
            return false;
        }
    }
    !compound
        .negations
        .iter()
        .any(|neg| compound_matches(neg, candidate, decoded))
}

/// Class and id equality; quirks-mode documents compare ASCII
/// case-insensitively.
fn text_eq(value: &[u8], expected: &[u8], quirks: bool) -> bool {
    if quirks {
        value.eq_ignore_ascii_case(expected)
    } else {
        value == expected
    }
}

/// Tests the value browsers see (character references decoded) of the
/// first attribute named `name` (ASCII case-insensitive); `false` when the
/// element has no such attribute.
fn attribute_matches(
    tag: &StartTag<'_>,
    name: &[u8],
    decoded: &mut Vec<u8>,
    test: impl FnOnce(&[u8]) -> bool,
) -> bool {
    let Some(attr) = tag
        .attributes()
        .find(|attr| attr.name().eq_ignore_ascii_case(name))
    else {
        return false;
    };
    let raw = attr.value();
    if memchr(b'&', raw).is_none() {
        return test(raw);
    }
    decoded.clear();
    decode_attribute_value_into(raw, decoded);
    test(decoded)
}
