//! The [`Element`] handle passed to rewrite handlers, plus the
//! [`ElementContentHandler`] trait.

use std::borrow::Cow;

use rama_core::error::BoxError;

use super::super::tokenizer::StartTag;
use super::super::{IntoHtml, escape_attr_value_into};

/// The result of an element content handler. An error aborts the rewrite.
pub type HandlerResult = Result<(), BoxError>;

/// Handles matched elements during a rewrite.
///
/// Implement this on your own type — that type holds any state the handler
/// accumulates, mutated through `&mut self`. `selector` is the index (in
/// registration order) of the selector that matched `element`.
///
/// For one-off rewrites, the closure-based
/// [`ElementContentHandlers`](super::ElementContentHandlers) builder
/// implements this trait for you.
pub trait ElementContentHandler {
    /// Handles a matched element.
    ///
    /// # Errors
    ///
    /// Returning an error aborts the rewrite and surfaces the error from
    /// [`HtmlRewriter::write`](super::HtmlRewriter::write) /
    /// [`end`](super::HtmlRewriter::end).
    fn handle_element(&mut self, selector: usize, element: &mut Element<'_>) -> HandlerResult;
}

/// One attribute in an [`Element`]'s edited attribute list. Unchanged
/// attributes borrow the source tag; only set/added ones own their bytes.
#[derive(Debug)]
struct EditedAttribute<'t> {
    name: Cow<'t, [u8]>,
    /// `None` for a valueless attribute (e.g. `disabled`).
    value: Option<Cow<'t, [u8]>>,
}

/// What happens to the element's start tag, children and end tag as a whole.
///
/// These are mutually exclusive dispositions (last call wins); `before` /
/// `after` / attribute edits apply on top of any of them.
#[derive(Debug, Default)]
enum ElementMode {
    /// Emit the element unchanged (modulo attribute / `prepend` / `append`
    /// edits).
    #[default]
    Normal,
    /// Replace the element's children with this (pre-escaped) content; keep
    /// the start and end tags.
    Inner(String),
    /// Replace the whole element (start tag … end tag) with this content.
    Replace(String),
    /// Remove the whole element, children included.
    Remove,
    /// Remove only the start and end tags, keeping the children.
    RemoveKeepContent,
}

/// A matched element, for inspection and mutation by a handler.
///
/// Start-anchored edits ([`before`], [`prepend`], attribute changes) take
/// effect at the start tag; end-anchored edits ([`append`], [`after`],
/// [`set_inner_content`], [`replace`], [`remove`],
/// [`remove_and_keep_content`]) are deferred to the matching end tag by the
/// rewriter.
///
/// [`before`]: Element::before
/// [`prepend`]: Element::prepend
/// [`append`]: Element::append
/// [`after`]: Element::after
/// [`set_inner_content`]: Element::set_inner_content
/// [`replace`]: Element::replace
/// [`remove`]: Element::remove
/// [`remove_and_keep_content`]: Element::remove_and_keep_content
pub struct Element<'t> {
    tag: &'t StartTag<'t>,
    before: String,
    prepend: String,
    append: String,
    after: String,
    /// `None` until an attribute is edited; then it is the full attribute
    /// list to re-serialize.
    attributes: Option<Vec<EditedAttribute<'t>>>,
    mode: ElementMode,
}

impl<'t> Element<'t> {
    pub(crate) fn new(tag: &'t StartTag<'t>) -> Self {
        Self {
            tag,
            before: String::new(),
            prepend: String::new(),
            append: String::new(),
            after: String::new(),
            attributes: None,
            mode: ElementMode::Normal,
        }
    }

    /// The element's tag name bytes (original case).
    #[must_use]
    pub fn name(&self) -> &[u8] {
        self.tag.name()
    }

    /// The value of the attribute with the given (ASCII case-insensitive)
    /// name, or `None` if absent. A valueless attribute reports `Some(b"")`.
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<&[u8]> {
        let name = name.as_bytes();
        match &self.attributes {
            Some(edited) => edited
                .iter()
                .find(|a| a.name.eq_ignore_ascii_case(name))
                .map(|a| a.value.as_deref().unwrap_or(b"")),
            None => self
                .tag
                .attributes()
                .find(|a| a.name().eq_ignore_ascii_case(name))
                .map(|a| if a.has_value() { a.value() } else { b"" }),
        }
    }

    /// Whether the element has the given attribute.
    #[must_use]
    pub fn has_attribute(&self, name: &str) -> bool {
        self.attribute(name).is_some()
    }

    /// Sets (or adds) an attribute with the given value.
    pub fn set_attribute(&mut self, name: &str, value: &str) {
        self.ensure_attributes();
        let Some(attributes) = self.attributes.as_mut() else {
            return;
        };
        let name = name.as_bytes();
        if let Some(existing) = attributes
            .iter_mut()
            .find(|a| a.name.eq_ignore_ascii_case(name))
        {
            existing.value = Some(Cow::Owned(value.as_bytes().to_vec()));
        } else {
            attributes.push(EditedAttribute {
                name: Cow::Owned(name.to_vec()),
                value: Some(Cow::Owned(value.as_bytes().to_vec())),
            });
        }
    }

    /// Removes the attribute with the given (ASCII case-insensitive) name.
    pub fn remove_attribute(&mut self, name: &str) {
        self.ensure_attributes();
        let Some(attributes) = self.attributes.as_mut() else {
            return;
        };
        let name = name.as_bytes();
        attributes.retain(|a| !a.name.eq_ignore_ascii_case(name));
    }

    /// Inserts content immediately before the element's start tag.
    ///
    /// Accepts any [`IntoHtml`] value: plain strings are escaped; wrap
    /// trusted HTML in [`PreEscaped`](super::super::PreEscaped) to emit it
    /// verbatim.
    pub fn before(&mut self, content: impl IntoHtml) {
        reserve_html(&mut self.before, &content);
        content.escape_and_write(&mut self.before);
    }

    /// Inserts content as the element's first children (immediately after the
    /// start tag). Escaping follows [`before`](Self::before).
    pub fn prepend(&mut self, content: impl IntoHtml) {
        reserve_html(&mut self.prepend, &content);
        content.escape_and_write(&mut self.prepend);
    }

    /// Inserts content as the element's last children (immediately before the
    /// end tag). Escaping follows [`before`](Self::before).
    pub fn append(&mut self, content: impl IntoHtml) {
        reserve_html(&mut self.append, &content);
        content.escape_and_write(&mut self.append);
    }

    /// Inserts content immediately after the element's end tag. Escaping
    /// follows [`before`](Self::before).
    pub fn after(&mut self, content: impl IntoHtml) {
        reserve_html(&mut self.after, &content);
        content.escape_and_write(&mut self.after);
    }

    /// Replaces the element's children, keeping the start and end tags (and
    /// any attribute edits). Escaping follows [`before`](Self::before).
    pub fn set_inner_content(&mut self, content: impl IntoHtml) {
        let mut inner = String::with_capacity(html_capacity(&content));
        content.escape_and_write(&mut inner);
        self.mode = ElementMode::Inner(inner);
    }

    /// Replaces the whole element (start tag through end tag). Escaping
    /// follows [`before`](Self::before).
    pub fn replace(&mut self, content: impl IntoHtml) {
        let mut replacement = String::with_capacity(html_capacity(&content));
        content.escape_and_write(&mut replacement);
        self.mode = ElementMode::Replace(replacement);
    }

    /// Removes the whole element, children included.
    pub fn remove(&mut self) {
        self.mode = ElementMode::Remove;
    }

    /// Removes only the element's start and end tags, leaving its children in
    /// place.
    pub fn remove_and_keep_content(&mut self) {
        self.mode = ElementMode::RemoveKeepContent;
    }

    /// Whether a [`remove`](Self::remove) /
    /// [`remove_and_keep_content`](Self::remove_and_keep_content) /
    /// [`replace`](Self::replace) disposition is in effect.
    #[must_use]
    pub fn is_removed(&self) -> bool {
        matches!(
            self.mode,
            ElementMode::Remove | ElementMode::RemoveKeepContent | ElementMode::Replace(_)
        )
    }

    fn ensure_attributes(&mut self) {
        if self.attributes.is_none() {
            let attributes = self
                .tag
                .attributes()
                .map(|a| EditedAttribute {
                    name: Cow::Borrowed(a.name()),
                    value: a.has_value().then(|| Cow::Borrowed(a.value())),
                })
                .collect();
            self.attributes = Some(attributes);
        }
    }

    /// Emits the element's start-side output into `out` (only when `visible`
    /// — i.e. not swallowed by an enclosing removed/replaced ancestor) and
    /// returns the [`EndActions`] to apply at the matching end tag. Consumes
    /// `self` so the owned edit buffers move out without copying.
    pub(crate) fn serialize(self, out: &mut Vec<u8>, visible: bool) -> EndActions {
        let Self {
            tag,
            before,
            prepend,
            append,
            after,
            attributes,
            mode,
        } = self;

        match mode {
            ElementMode::Normal => {
                if visible {
                    out.extend_from_slice(before.as_bytes());
                    emit_start_tag(out, tag, attributes.as_deref());
                    out.extend_from_slice(prepend.as_bytes());
                }
                EndActions {
                    append,
                    after,
                    suppress_content: false,
                    suppress_end_tag: false,
                }
            }
            ElementMode::Inner(inner) => {
                if visible {
                    out.extend_from_slice(before.as_bytes());
                    emit_start_tag(out, tag, attributes.as_deref());
                    out.extend_from_slice(prepend.as_bytes());
                    out.extend_from_slice(inner.as_bytes());
                }
                EndActions {
                    append,
                    after,
                    suppress_content: true,
                    suppress_end_tag: false,
                }
            }
            ElementMode::Replace(replacement) => {
                if visible {
                    out.extend_from_slice(before.as_bytes());
                    out.extend_from_slice(replacement.as_bytes());
                }
                // The element (and its children/end tag) is gone; only
                // `after` still applies, at the end-tag position.
                EndActions {
                    append: String::new(),
                    after,
                    suppress_content: true,
                    suppress_end_tag: true,
                }
            }
            ElementMode::Remove => {
                if visible {
                    out.extend_from_slice(before.as_bytes());
                }
                EndActions {
                    append: String::new(),
                    after,
                    suppress_content: true,
                    suppress_end_tag: true,
                }
            }
            ElementMode::RemoveKeepContent => {
                if visible {
                    out.extend_from_slice(before.as_bytes());
                    // Start tag dropped; `prepend` sits where it was.
                    out.extend_from_slice(prepend.as_bytes());
                }
                EndActions {
                    append,
                    after,
                    suppress_content: false,
                    suppress_end_tag: true,
                }
            }
        }
    }
}

/// Output to emit at an element's matching end tag, returned by
/// [`Element::serialize`].
pub(crate) struct EndActions {
    /// Emitted just before the end tag (the element's last children).
    pub(crate) append: String,
    /// Emitted just after the end tag.
    pub(crate) after: String,
    /// Whether the element's children must be suppressed from the output.
    pub(crate) suppress_content: bool,
    /// Whether the end tag itself must be suppressed.
    pub(crate) suppress_end_tag: bool,
}

impl EndActions {
    /// The no-op actions for an opened element that needs no end-side edits
    /// (an unmatched element, or one with only start-anchored edits).
    pub(crate) fn passthrough() -> Self {
        Self {
            append: String::new(),
            after: String::new(),
            suppress_content: false,
            suppress_end_tag: false,
        }
    }
}

/// Emits an element's start tag, re-serializing when attributes were edited
/// (`edited` is `Some`) or passing the original bytes through verbatim.
fn emit_start_tag(out: &mut Vec<u8>, tag: &StartTag<'_>, edited: Option<&[EditedAttribute<'_>]>) {
    match edited {
        None => out.extend_from_slice(tag.raw()),
        Some(attributes) => {
            out.push(b'<');
            out.extend_from_slice(tag.name());
            for attr in attributes {
                out.push(b' ');
                out.extend_from_slice(&attr.name);
                if let Some(value) = &attr.value {
                    out.extend_from_slice(b"=\"");
                    escape_attr_value_into(out, value);
                    out.push(b'"');
                }
            }
            if tag.is_self_closing() {
                out.extend_from_slice(b" />");
            } else {
                out.push(b'>');
            }
        }
    }
}

fn reserve_html(buf: &mut String, content: &impl IntoHtml) {
    buf.reserve(html_capacity(content));
}

fn html_capacity(content: &impl IntoHtml) -> usize {
    let hint = content.size_hint();
    hint + (hint / 10)
}
