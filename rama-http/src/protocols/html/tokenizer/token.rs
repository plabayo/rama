//! Borrowed token views handed to a [`TokenSink`](super::TokenSink).
//!
//! Each view borrows the input buffer for the duration of the sink call and
//! exposes byte slices into it — no per-token allocation. Every view also
//! exposes its full `raw()` span (the exact input bytes it covers); the raw
//! spans of all tokens partition the input contiguously, which is what makes
//! verbatim re-serialization (the identity property) possible.

use std::borrow::Cow;

use super::super::decode_entities;
use super::name::LocalNameHash;

/// UTF-8-lossy decode `bytes` and resolve HTML entities, borrowing the input
/// when both are no-ops.
fn decode_lossy(bytes: &[u8]) -> Cow<'_, str> {
    match String::from_utf8_lossy(bytes) {
        Cow::Borrowed(s) => decode_entities(s),
        Cow::Owned(s) => Cow::Owned(decode_entities(&s).into_owned()),
    }
}

/// Half-open `[start, end)` byte span into the input buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Span {
    pub(crate) start: usize,
    pub(crate) end: usize,
}

impl Span {
    pub(crate) const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub(crate) const fn empty(at: usize) -> Self {
        Self { start: at, end: at }
    }

    fn slice(self, input: &[u8]) -> &[u8] {
        input.get(self.start..self.end).unwrap_or(&[])
    }
}

/// A single attribute's name and value spans (relative to the input).
#[derive(Debug, Clone, Copy)]
pub(crate) struct AttrRange {
    pub(crate) name: Span,
    pub(crate) value: Span,
    pub(crate) has_value: bool,
}

/// A start tag, e.g. `<a href="/x">` or `<br/>`.
#[derive(Debug)]
pub struct StartTag<'i> {
    pub(crate) input: &'i [u8],
    pub(crate) raw: Span,
    pub(crate) name: Span,
    pub(crate) name_hash: LocalNameHash,
    pub(crate) attributes: &'i [AttrRange],
    pub(crate) self_closing: bool,
}

impl<'i> StartTag<'i> {
    /// The tag name bytes (original case).
    #[must_use]
    pub fn name(&self) -> &'i [u8] {
        self.name.slice(self.input)
    }

    /// The hash of the (ASCII-lowercased) tag name.
    #[must_use]
    pub fn name_hash(&self) -> LocalNameHash {
        self.name_hash
    }

    /// Whether the tag was written self-closing (`<br/>`).
    #[must_use]
    pub fn is_self_closing(&self) -> bool {
        self.self_closing
    }

    /// Iterator over the tag's attributes, in source order.
    #[must_use]
    pub fn attributes(&self) -> Attributes<'i> {
        Attributes {
            input: self.input,
            ranges: self.attributes.iter(),
        }
    }

    /// The full source bytes of the tag, including `<` and `>`.
    #[must_use]
    pub fn raw(&self) -> &'i [u8] {
        self.raw.slice(self.input)
    }
}

/// Iterator over a [`StartTag`]'s attributes.
#[derive(Debug, Clone)]
pub struct Attributes<'i> {
    input: &'i [u8],
    ranges: std::slice::Iter<'i, AttrRange>,
}

impl<'i> Iterator for Attributes<'i> {
    type Item = Attribute<'i>;

    fn next(&mut self) -> Option<Self::Item> {
        let range = self.ranges.next()?;
        Some(Attribute {
            name: range.name.slice(self.input),
            value: range.value.slice(self.input),
            has_value: range.has_value,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.ranges.size_hint()
    }
}

impl ExactSizeIterator for Attributes<'_> {}

/// A single attribute view.
#[derive(Debug, Clone, Copy)]
pub struct Attribute<'i> {
    name: &'i [u8],
    value: &'i [u8],
    has_value: bool,
}

impl<'i> Attribute<'i> {
    /// The attribute name bytes (original case).
    #[must_use]
    pub fn name(&self) -> &'i [u8] {
        self.name
    }

    /// The attribute value bytes (raw, not entity-decoded). Empty for a
    /// valueless attribute or an empty value; use [`Attribute::has_value`]
    /// to distinguish them.
    #[must_use]
    pub fn value(&self) -> &'i [u8] {
        self.value
    }

    /// The attribute value as display text: UTF-8-lossy decoded with HTML
    /// entities resolved. Borrows [`value`](Self::value) when it is already
    /// valid UTF-8 with nothing to decode.
    #[must_use]
    pub fn value_decoded(&self) -> Cow<'i, str> {
        decode_lossy(self.value)
    }

    /// Whether the attribute had an explicit `=value`.
    #[must_use]
    pub fn has_value(&self) -> bool {
        self.has_value
    }
}

/// An end tag, e.g. `</a>`.
#[derive(Debug)]
pub struct EndTag<'i> {
    pub(crate) input: &'i [u8],
    pub(crate) raw: Span,
    pub(crate) name: Span,
    pub(crate) name_hash: LocalNameHash,
}

impl<'i> EndTag<'i> {
    /// The tag name bytes (original case).
    #[must_use]
    pub fn name(&self) -> &'i [u8] {
        self.name.slice(self.input)
    }

    /// The hash of the (ASCII-lowercased) tag name.
    #[must_use]
    pub fn name_hash(&self) -> LocalNameHash {
        self.name_hash
    }

    /// The full source bytes of the tag, including `</` and `>`.
    #[must_use]
    pub fn raw(&self) -> &'i [u8] {
        self.raw.slice(self.input)
    }
}

/// A run of character data (text). Raw bytes, not entity-decoded.
#[derive(Debug)]
pub struct Text<'i> {
    pub(crate) input: &'i [u8],
    pub(crate) raw: Span,
}

impl<'i> Text<'i> {
    /// The text bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &'i [u8] {
        self.raw.slice(self.input)
    }

    /// The text as display text: UTF-8-lossy decoded with HTML entities
    /// resolved. Borrows [`as_bytes`](Self::as_bytes) when it is already valid
    /// UTF-8 with nothing to decode.
    #[must_use]
    pub fn decoded(&self) -> Cow<'i, str> {
        decode_lossy(self.raw.slice(self.input))
    }

    /// The full source bytes of the text (same as [`Text::as_bytes`]).
    #[must_use]
    pub fn raw(&self) -> &'i [u8] {
        self.raw.slice(self.input)
    }
}

/// A comment, e.g. `<!-- hi -->`.
#[derive(Debug)]
pub struct Comment<'i> {
    pub(crate) input: &'i [u8],
    pub(crate) raw: Span,
    pub(crate) data: Span,
}

impl<'i> Comment<'i> {
    /// The comment's inner data bytes (without `<!--` / `-->`).
    #[must_use]
    pub fn data(&self) -> &'i [u8] {
        self.data.slice(self.input)
    }

    /// The full source bytes of the comment.
    #[must_use]
    pub fn raw(&self) -> &'i [u8] {
        self.raw.slice(self.input)
    }
}

/// A CDATA section, e.g. `<![CDATA[ x ]]>` (only emitted inside foreign
/// content — SVG/MathML; elsewhere `<![CDATA[` is a bogus comment).
#[derive(Debug)]
pub struct Cdata<'i> {
    pub(crate) input: &'i [u8],
    pub(crate) raw: Span,
    pub(crate) data: Span,
}

impl<'i> Cdata<'i> {
    /// The section's inner data bytes (without `<![CDATA[` / `]]>`).
    #[must_use]
    pub fn data(&self) -> &'i [u8] {
        self.data.slice(self.input)
    }

    /// The full source bytes of the CDATA section.
    #[must_use]
    pub fn raw(&self) -> &'i [u8] {
        self.raw.slice(self.input)
    }
}

/// A document type declaration, e.g. `<!DOCTYPE html>`.
#[derive(Debug)]
pub struct Doctype<'i> {
    pub(crate) input: &'i [u8],
    pub(crate) raw: Span,
    pub(crate) name: Option<Span>,
}

impl<'i> Doctype<'i> {
    /// The doctype name bytes (original case), if present.
    #[must_use]
    pub fn name(&self) -> Option<&'i [u8]> {
        self.name.map(|span| span.slice(self.input))
    }

    /// The full source bytes of the doctype declaration.
    #[must_use]
    pub fn raw(&self) -> &'i [u8] {
        self.raw.slice(self.input)
    }
}
