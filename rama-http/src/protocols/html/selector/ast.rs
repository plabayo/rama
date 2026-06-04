//! Abstract syntax tree for the supported CSS selector subset.
//!
//! The subset mirrors what a streaming matcher can evaluate (the same
//! constraint lol-html's selector engine works under), but the parser is
//! hand-rolled from scratch so rama pulls in no extra dependencies — no
//! `cssparser`, no Servo `selectors`. See `parser.rs` for the grammar.

/// A parsed CSS selector string.
///
/// A selector string may contain a comma-separated list of complex
/// selectors (e.g. `"a, .b > c"`); the [`Selector`] matches an element if
/// *any* of those complex selectors matches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selector {
    pub(crate) selectors: Vec<ComplexSelector>,
}

/// A single complex selector: a sequence of compound selectors joined by
/// combinators (e.g. `div.menu > a`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ComplexSelector {
    /// Compound selectors in source (left-to-right) order. The combinator
    /// stored with each part is the one that *precedes* it; the first
    /// part's combinator is always `None`.
    pub(crate) parts: Vec<SelectorPart>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SelectorPart {
    pub(crate) combinator: Option<Combinator>,
    pub(crate) compound: Compound,
}

/// A combinator between two compound selectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Combinator {
    /// Descendant combinator (whitespace), e.g. `a b`.
    Descendant,
    /// Child combinator `>`, e.g. `a > b`.
    Child,
}

/// A compound selector: an optional type/universal selector plus zero or
/// more subclass selectors, all of which must match the same element.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Compound {
    /// Element type. `None` matches any element.
    pub(crate) name: Option<LocalName>,
    /// Whether a universal `*` was explicitly written. Only affects
    /// serialization; matching treats `None` and `Universal` identically.
    pub(crate) explicit_universal: bool,
    pub(crate) id: Option<Box<str>>,
    pub(crate) classes: Vec<Box<str>>,
    pub(crate) attributes: Vec<AttributeSelector>,
    pub(crate) nth: Vec<Nth>,
    /// Arguments of `:not(...)`. The element matches the compound only if
    /// it matches *none* of these (so `:not(a, b)` is stored as two
    /// entries, matching neither).
    pub(crate) negations: Vec<Self>,
}

/// An attribute selector such as `[href]` or `[class~="menu" i]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttributeSelector {
    /// ASCII-lowercased attribute name.
    pub(crate) name: Box<str>,
    /// Match operator. `None` means presence-only (`[name]`).
    pub(crate) operator: Option<AttributeOperator>,
    /// Match value; empty when `operator` is `None`.
    pub(crate) value: Box<str>,
    pub(crate) case: CaseSensitivity,
}

/// Attribute value match operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttributeOperator {
    /// `[a=v]` — exactly equal.
    Equals,
    /// `[a~=v]` — whitespace-separated list contains `v`.
    Includes,
    /// `[a|=v]` — equal to `v` or starts with `v-`.
    DashMatch,
    /// `[a^=v]` — begins with `v`.
    Prefix,
    /// `[a$=v]` — ends with `v`.
    Suffix,
    /// `[a*=v]` — contains `v`.
    Substring,
}

/// Whether an attribute value is matched case-sensitively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaseSensitivity {
    /// Default for HTML attribute values.
    CaseSensitive,
    /// Requested via the `i` flag (ASCII case-insensitive).
    AsciiCaseInsensitive,
}

/// A structural `:nth-*` selector reduced to its `An+B` form.
///
/// `:first-child` is stored as `Child` with `a = 0, b = 1`, and
/// `:first-of-type` as `OfType` with `a = 0, b = 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Nth {
    pub(crate) ty: NthType,
    pub(crate) a: i32,
    pub(crate) b: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NthType {
    /// `:nth-child` / `:first-child` — counts all element siblings.
    Child,
    /// `:nth-of-type` / `:first-of-type` — counts same-type siblings.
    OfType,
}

impl Nth {
    /// Returns whether a 1-based sibling `index` satisfies this `An+B`.
    pub(crate) fn matches_index(self, index: usize) -> bool {
        // Work in `i64` (selectors are `i32`), converting/subtracting with
        // checked ops so a pathologically large `index` or `b` can never
        // overflow — it simply fails to match.
        let Ok(i) = i64::try_from(index) else {
            return false;
        };
        let a = i64::from(self.a);
        let b = i64::from(self.b);
        let Some(diff) = i.checked_sub(b) else {
            return false;
        };
        if a == 0 {
            return diff == 0;
        }
        diff % a == 0 && diff / a >= 0
    }
}

/// An ASCII-lowercased element (tag) name with a precomputed packed key
/// for allocation-free comparison against raw element names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalName {
    /// ASCII-lowercased name.
    name: Box<str>,
    /// `Some(_)` when `name` fits in 8 ASCII bytes, enabling an integer
    /// fast path in [`LocalName::matches`].
    packed: Option<u64>,
}

impl LocalName {
    pub(crate) fn new(name: &str) -> Self {
        let lower = name.to_ascii_lowercase();
        let packed = pack_name(lower.as_bytes());
        Self {
            name: lower.into_boxed_str(),
            packed,
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.name
    }

    /// ASCII-case-insensitive comparison against a raw element name,
    /// without allocating.
    pub(crate) fn matches(&self, raw: &str) -> bool {
        if let Some(packed) = self.packed
            && let Some(other) = pack_name(raw.as_bytes())
        {
            return packed == other;
        }
        raw.eq_ignore_ascii_case(&self.name)
    }
}

/// Packs an element name into a `u64` when it is at most 8 ASCII bytes,
/// ASCII-lowercasing each byte. Returns `None` otherwise, signalling the
/// caller to fall back to a byte comparison.
fn pack_name(bytes: &[u8]) -> Option<u64> {
    if bytes.len() > 8 {
        return None;
    }
    let mut packed = 0u64;
    for &b in bytes {
        if !b.is_ascii() {
            return None;
        }
        packed = (packed << 8) | u64::from(b.to_ascii_lowercase());
    }
    Some(packed)
}
