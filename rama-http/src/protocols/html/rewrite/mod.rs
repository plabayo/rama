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

// Optional-end-tag / implied-close elements. These cover the common HTML
// tree-builder cases that affect streaming selector ancestry.
const ADDRESS: LocalNameHash = LocalNameHash::from_static(b"address");
const ARTICLE: LocalNameHash = LocalNameHash::from_static(b"article");
const ASIDE: LocalNameHash = LocalNameHash::from_static(b"aside");
const BLOCKQUOTE: LocalNameHash = LocalNameHash::from_static(b"blockquote");
const DD: LocalNameHash = LocalNameHash::from_static(b"dd");
const DETAILS: LocalNameHash = LocalNameHash::from_static(b"details");
const DIV: LocalNameHash = LocalNameHash::from_static(b"div");
const DL: LocalNameHash = LocalNameHash::from_static(b"dl");
const DT: LocalNameHash = LocalNameHash::from_static(b"dt");
const FIELDSET: LocalNameHash = LocalNameHash::from_static(b"fieldset");
const FIGCAPTION: LocalNameHash = LocalNameHash::from_static(b"figcaption");
const FIGURE: LocalNameHash = LocalNameHash::from_static(b"figure");
const FOOTER: LocalNameHash = LocalNameHash::from_static(b"footer");
const FORM: LocalNameHash = LocalNameHash::from_static(b"form");
const H1: LocalNameHash = LocalNameHash::from_static(b"h1");
const H2: LocalNameHash = LocalNameHash::from_static(b"h2");
const H3: LocalNameHash = LocalNameHash::from_static(b"h3");
const H4: LocalNameHash = LocalNameHash::from_static(b"h4");
const H5: LocalNameHash = LocalNameHash::from_static(b"h5");
const H6: LocalNameHash = LocalNameHash::from_static(b"h6");
const HEADER: LocalNameHash = LocalNameHash::from_static(b"header");
const HGROUP: LocalNameHash = LocalNameHash::from_static(b"hgroup");
const LI: LocalNameHash = LocalNameHash::from_static(b"li");
const MAIN: LocalNameHash = LocalNameHash::from_static(b"main");
const MENU: LocalNameHash = LocalNameHash::from_static(b"menu");
const NAV: LocalNameHash = LocalNameHash::from_static(b"nav");
const OL: LocalNameHash = LocalNameHash::from_static(b"ol");
const OPTGROUP: LocalNameHash = LocalNameHash::from_static(b"optgroup");
const OPTION: LocalNameHash = LocalNameHash::from_static(b"option");
const P: LocalNameHash = LocalNameHash::from_static(b"p");
const PRE: LocalNameHash = LocalNameHash::from_static(b"pre");
const RB: LocalNameHash = LocalNameHash::from_static(b"rb");
const RP: LocalNameHash = LocalNameHash::from_static(b"rp");
const RT: LocalNameHash = LocalNameHash::from_static(b"rt");
const RTC: LocalNameHash = LocalNameHash::from_static(b"rtc");
const SEARCH: LocalNameHash = LocalNameHash::from_static(b"search");
const SECTION: LocalNameHash = LocalNameHash::from_static(b"section");
const TABLE: LocalNameHash = LocalNameHash::from_static(b"table");
const TBODY: LocalNameHash = LocalNameHash::from_static(b"tbody");
const TD: LocalNameHash = LocalNameHash::from_static(b"td");
const TFOOT: LocalNameHash = LocalNameHash::from_static(b"tfoot");
const TH: LocalNameHash = LocalNameHash::from_static(b"th");
const THEAD: LocalNameHash = LocalNameHash::from_static(b"thead");
const TR: LocalNameHash = LocalNameHash::from_static(b"tr");
const UL: LocalNameHash = LocalNameHash::from_static(b"ul");

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

    /// Applies start-tag implied end tags before a new element is matched.
    ///
    /// This mirrors the common optional-end-tag cases (`<li><li>`,
    /// `<p><p>`, table cells/rows, options, ruby annotations). It keeps
    /// selector ancestry and deferred rewriter actions aligned with the HTML
    /// tree-builder shape for in-the-wild markup that legally omits end tags.
    pub(crate) fn pop_implied_for_start(&mut self, name: LocalNameHash) -> usize {
        let mut popped = 0;
        match name {
            LI => popped += self.pop_nearest(&[LI]),
            DD | DT => popped += self.pop_nearest(&[DD, DT]),
            OPTION => popped += self.pop_nearest(&[OPTION]),
            OPTGROUP => {
                popped += self.pop_nearest(&[OPTION]);
                popped += self.pop_nearest(&[OPTGROUP]);
            }
            RB | RT | RTC | RP => popped += self.pop_nearest(&[RB, RT, RTC, RP]),
            TR => {
                popped += self.pop_nearest(&[TD, TH]);
                popped += self.pop_nearest(&[TR]);
            }
            TD | TH => popped += self.pop_nearest(&[TD, TH]),
            THEAD | TBODY | TFOOT => {
                popped += self.pop_nearest(&[TD, TH]);
                popped += self.pop_nearest(&[TR]);
                popped += self.pop_nearest(&[THEAD, TBODY, TFOOT]);
            }
            _ if closes_p(name) => popped += self.pop_nearest(&[P]),
            _ => {}
        }
        popped
    }

    /// Processes an end tag, closing the matching open element.
    ///
    /// Mirrors HTML's "generate implied end tags": it closes the *topmost*
    /// open element with this `name` **and every still-open descendant above
    /// it** (so crossed/unclosed tags like `<a><b></a>` close `b` too).
    /// Returns the number of frames closed — `0` for a stray end tag that
    /// matches nothing. The rewriter relies on this count to keep its
    /// deferred-action stack and suppression depth in lockstep with the
    /// open-element stack (otherwise a never-popped suppressing frame would
    /// swallow the rest of the document).
    pub(crate) fn pop_element(&mut self, name: LocalNameHash) -> usize {
        // Index 0 is the root sentinel and is never closed.
        let Some(pos) = self.stack.iter().rposition(|f| f.name == name) else {
            return 0;
        };
        if pos == 0 {
            return 0;
        }
        let popped = self.stack.len() - pos;
        self.stack.truncate(pos);
        self.states.truncate(pos * self.selectors.len());
        popped
    }

    /// Closes every still-open element at EOF.
    pub(crate) fn finish(&mut self) -> usize {
        let popped = self.stack.len().saturating_sub(1);
        self.stack.truncate(1);
        self.states.truncate(self.selectors.len());
        popped
    }

    fn pop_nearest(&mut self, names: &[LocalNameHash]) -> usize {
        let Some(pos) = self
            .stack
            .iter()
            .rposition(|frame| names.contains(&frame.name))
        else {
            return 0;
        };
        if pos == 0 {
            return 0;
        }
        let popped = self.stack.len() - pos;
        self.stack.truncate(pos);
        self.states.truncate(pos * self.selectors.len());
        popped
    }
}

fn closes_p(name: LocalNameHash) -> bool {
    matches!(
        name,
        ADDRESS
            | ARTICLE
            | ASIDE
            | BLOCKQUOTE
            | DD
            | DETAILS
            | DIV
            | DL
            | DT
            | FIELDSET
            | FIGCAPTION
            | FIGURE
            | FOOTER
            | FORM
            | H1
            | H2
            | H3
            | H4
            | H5
            | H6
            | HEADER
            | HGROUP
            | VOID_HR
            | MAIN
            | MENU
            | NAV
            | OL
            | P
            | PRE
            | SEARCH
            | SECTION
            | TABLE
            | UL
    )
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
