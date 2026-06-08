//! Infallible builders for [`Selector`] and [`Compound`].
//!
//! Unlike [`parse`](str::parse), these construct the AST directly from
//! component values, so they can't fail — there is no grammar to violate.
//! Inputs are taken *literally* (a *component value*, not a selector
//! fragment): tag/attribute names are ASCII-lowercased per HTML, class/id
//! and attribute values are kept verbatim. A value that can't occur in real
//! markup (whitespace in a tag name, …) simply never matches; in debug
//! builds such an almost-certainly-mistaken input trips a `debug_assert`.

use super::ast::{
    AttributeOperator, AttributeSelector, CaseSensitivity, Combinator, ComplexSelector, Compound,
    LocalName, Nth, NthType, Selector, SelectorPart,
};

/// Debug-only guard for an ident-position input (tag / class / id / attribute
/// name). These can't hold whitespace in real markup and are never empty, so
/// such input is almost always a fragment that should have gone through
/// `parse` instead. Released builds accept it (it just never matches).
#[inline]
fn debug_assert_ident(kind: &str, value: &str) {
    debug_assert!(
        !value.is_empty() && !value.bytes().any(|b| b.is_ascii_whitespace()),
        "{kind} must be a non-empty literal without whitespace, got {value:?} \
         (use `parse` for a selector fragment)"
    );
}

impl Selector {
    /// A type (tag) selector, e.g. `div`. Shorthand for
    /// `Selector::of(Compound::tag(name))`.
    #[must_use]
    pub fn tag(name: impl AsRef<str>) -> Self {
        Self::of(Compound::tag(name))
    }

    /// A class selector, e.g. `.menu`.
    #[must_use]
    pub fn class(name: impl AsRef<str>) -> Self {
        Self::of(Compound::class(name))
    }

    /// An id selector, e.g. `#main`.
    #[must_use]
    pub fn id(name: impl AsRef<str>) -> Self {
        Self::of(Compound::id(name))
    }

    /// The universal selector `*`.
    #[must_use]
    pub fn any() -> Self {
        Self::of(Compound::any())
    }

    /// A selector from a single [`Compound`].
    #[must_use]
    pub fn of(compound: Compound) -> Self {
        Self {
            selectors: vec![ComplexSelector {
                parts: vec![SelectorPart {
                    combinator: None,
                    compound,
                }],
            }],
        }
    }

    /// Extends the current complex selector with a child combinator:
    /// `self > compound`.
    #[must_use]
    pub fn child(self, compound: Compound) -> Self {
        self.combine(Combinator::Child, compound)
    }

    /// Extends the current complex selector with a descendant combinator:
    /// `self compound`.
    #[must_use]
    pub fn descendant(self, compound: Compound) -> Self {
        self.combine(Combinator::Descendant, compound)
    }

    /// Adds `other`'s complex selectors as further alternatives (the comma
    /// list): `self, other`.
    #[must_use]
    pub fn or(mut self, other: Self) -> Self {
        self.selectors.extend(other.selectors);
        self
    }

    fn combine(mut self, combinator: Combinator, compound: Compound) -> Self {
        // `of`/`tag`/… always seed exactly one complex, and `or` only appends
        // whole complexes, so there is always a last complex to extend.
        if let Some(complex) = self.selectors.last_mut() {
            complex.parts.push(SelectorPart {
                combinator: Some(combinator),
                compound,
            });
        }
        self
    }
}

impl Compound {
    /// A type (tag) selector, e.g. `div` (ASCII-lowercased).
    #[must_use]
    pub fn tag(name: impl AsRef<str>) -> Self {
        let name = name.as_ref();
        debug_assert_ident("tag name", name);
        Self {
            name: Some(LocalName::new(name)),
            ..Self::default()
        }
    }

    /// The universal selector `*`.
    #[must_use]
    pub fn any() -> Self {
        Self {
            explicit_universal: true,
            ..Self::default()
        }
    }

    /// A class selector, e.g. `.menu`.
    #[must_use]
    pub fn class(name: impl AsRef<str>) -> Self {
        Self::default().with_class(name)
    }

    /// An id selector, e.g. `#main`.
    #[must_use]
    pub fn id(name: impl AsRef<str>) -> Self {
        Self::default().with_id(name)
    }

    /// Sets (replacing) the id, e.g. `#main`.
    #[must_use]
    pub fn with_id(mut self, id: impl AsRef<str>) -> Self {
        let id = id.as_ref();
        debug_assert_ident("id", id);
        self.id = Some(id.into());
        self
    }

    /// Adds a class, e.g. `.menu`.
    #[must_use]
    pub fn with_class(mut self, class: impl AsRef<str>) -> Self {
        let class = class.as_ref();
        debug_assert_ident("class", class);
        self.classes.push(class.into());
        self
    }

    /// Adds an attribute-presence selector, e.g. `[disabled]`.
    #[must_use]
    pub fn with_attr(self, name: impl AsRef<str>) -> Self {
        self.push_attr(name, None, "", CaseSensitivity::CaseSensitive)
    }

    /// Adds `[name="value"]` (exact match).
    #[must_use]
    pub fn with_attr_eq(self, name: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        self.push_attr(
            name,
            Some(AttributeOperator::Equals),
            value.as_ref(),
            CaseSensitivity::CaseSensitive,
        )
    }

    /// Adds `[name="value" i]` (exact, ASCII case-insensitive).
    #[must_use]
    pub fn with_attr_eq_ignore_case(self, name: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        self.push_attr(
            name,
            Some(AttributeOperator::Equals),
            value.as_ref(),
            CaseSensitivity::AsciiCaseInsensitive,
        )
    }

    /// Adds `[name~="value"]` (whitespace-separated list contains `value`).
    #[must_use]
    pub fn with_attr_includes(self, name: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        self.push_attr(
            name,
            Some(AttributeOperator::Includes),
            value.as_ref(),
            CaseSensitivity::CaseSensitive,
        )
    }

    /// Adds `[name|="value"]` (equals `value` or starts with `value-`).
    #[must_use]
    pub fn with_attr_dash_match(self, name: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        self.push_attr(
            name,
            Some(AttributeOperator::DashMatch),
            value.as_ref(),
            CaseSensitivity::CaseSensitive,
        )
    }

    /// Adds `[name^="value"]` (begins with `value`).
    #[must_use]
    pub fn with_attr_prefix(self, name: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        self.push_attr(
            name,
            Some(AttributeOperator::Prefix),
            value.as_ref(),
            CaseSensitivity::CaseSensitive,
        )
    }

    /// Adds `[name$="value"]` (ends with `value`).
    #[must_use]
    pub fn with_attr_suffix(self, name: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        self.push_attr(
            name,
            Some(AttributeOperator::Suffix),
            value.as_ref(),
            CaseSensitivity::CaseSensitive,
        )
    }

    /// Adds `[name*="value"]` (contains `value`).
    #[must_use]
    pub fn with_attr_substring(self, name: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        self.push_attr(
            name,
            Some(AttributeOperator::Substring),
            value.as_ref(),
            CaseSensitivity::CaseSensitive,
        )
    }

    /// Adds `:nth-child(an + b)`.
    #[must_use]
    pub fn with_nth_child(mut self, a: i32, b: i32) -> Self {
        self.nth.push(Nth {
            ty: NthType::Child,
            a,
            b,
        });
        self
    }

    /// Adds `:nth-of-type(an + b)`.
    #[must_use]
    pub fn with_nth_of_type(mut self, a: i32, b: i32) -> Self {
        self.nth.push(Nth {
            ty: NthType::OfType,
            a,
            b,
        });
        self
    }

    /// Adds `:first-child`.
    #[must_use]
    pub fn with_first_child(self) -> Self {
        self.with_nth_child(0, 1)
    }

    /// Adds `:first-of-type`.
    #[must_use]
    pub fn with_first_of_type(self) -> Self {
        self.with_nth_of_type(0, 1)
    }

    /// Adds `:not(compound)`.
    #[must_use]
    pub fn without(mut self, compound: Self) -> Self {
        self.negations.push(compound);
        self
    }

    fn push_attr(
        mut self,
        name: impl AsRef<str>,
        operator: Option<AttributeOperator>,
        value: &str,
        case: CaseSensitivity,
    ) -> Self {
        let name = name.as_ref();
        debug_assert_ident("attribute name", name);
        self.attributes.push(AttributeSelector {
            name: name.to_ascii_lowercase().into(),
            operator,
            value: value.into(),
            case,
        });
        self
    }
}
