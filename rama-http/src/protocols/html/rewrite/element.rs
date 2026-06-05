//! The [`Element`] handle passed to rewrite handlers, plus the
//! [`ElementContentHandler`] trait.

use std::borrow::Cow;

use rama_core::error::BoxError;

use super::super::tokenizer::StartTag;
use super::super::{IntoHtml, escape_into};

/// The result of an element content handler. An error aborts the rewrite.
pub type HandlerResult = Result<(), BoxError>;

/// Handles matched elements during a rewrite.
///
/// Implement this on your own type — *that type is your shared state*: a
/// handler mutates `&mut self` directly, with no `Rc<RefCell>` /
/// `Arc<Mutex>` ceremony. `selector` is the index (in registration order)
/// of the selector that matched `element`.
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

/// A matched element, for inspection and mutation by a handler.
///
/// This handles start-tag-anchored edits: attribute changes, [`before`]
/// (insert before the element) and [`prepend`] (insert as the first
/// children). End-anchored edits (`after` / `append` / `set_inner` /
/// `replace` / `remove`) land in a later slice.
///
/// [`before`]: Element::before
/// [`prepend`]: Element::prepend
pub struct Element<'t> {
    tag: &'t StartTag<'t>,
    before: String,
    prepend: String,
    /// `None` until an attribute is edited; then it is the full attribute
    /// list to re-serialize.
    attributes: Option<Vec<EditedAttribute<'t>>>,
}

impl<'t> Element<'t> {
    pub(crate) fn new(tag: &'t StartTag<'t>) -> Self {
        Self {
            tag,
            before: String::new(),
            prepend: String::new(),
            attributes: None,
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

    /// Inserts HTML content immediately before the element's start tag.
    ///
    /// Accepts any [`IntoHtml`] value — e.g. content built with rama's
    /// `html!` / element macros — which is written pre-escaped.
    pub fn before(&mut self, content: impl IntoHtml) {
        content.escape_and_write(&mut self.before);
    }

    /// Inserts escaped text immediately before the element's start tag.
    pub fn before_text(&mut self, text: impl AsRef<str>) {
        escape_into(&mut self.before, text.as_ref());
    }

    /// Inserts HTML content as the element's first children (immediately
    /// after the start tag). Accepts any [`IntoHtml`] value.
    pub fn prepend(&mut self, content: impl IntoHtml) {
        content.escape_and_write(&mut self.prepend);
    }

    /// Inserts escaped text as the element's first children.
    pub fn prepend_text(&mut self, text: impl AsRef<str>) {
        escape_into(&mut self.prepend, text.as_ref());
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

    /// Serializes the element's start tag (with any edits) plus its `before`
    /// and `prepend` content, into `out`.
    pub(crate) fn serialize_start(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.before.as_bytes());
        match &self.attributes {
            None => out.extend_from_slice(self.tag.raw()),
            Some(attributes) => {
                out.push(b'<');
                out.extend_from_slice(self.tag.name());
                for attr in attributes {
                    out.push(b' ');
                    out.extend_from_slice(&attr.name);
                    if let Some(value) = &attr.value {
                        out.extend_from_slice(b"=\"");
                        push_attr_escaped(out, value);
                        out.push(b'"');
                    }
                }
                if self.tag.is_self_closing() {
                    out.extend_from_slice(b" />");
                } else {
                    out.push(b'>');
                }
            }
        }
        out.extend_from_slice(self.prepend.as_bytes());
    }
}

/// Escapes a double-quoted HTML attribute value (`&` and `"`).
fn push_attr_escaped(out: &mut Vec<u8>, value: &[u8]) {
    for &byte in value {
        match byte {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            _ => out.push(byte),
        }
    }
}
