//! The selector-driven HTML rewriter.

use rama_core::error::BoxError;

use super::super::selector::Selector;
use super::super::tokenizer::{
    Cdata, Comment, Doctype, EndTag, StartTag, Text, TokenSink, Tokenizer,
};
use super::SelectorMatcher;
use super::element::{Element, ElementContentHandler, HandlerResult};

/// The [`TokenSink`] that drives matching + mutation + serialization.
struct RewriteSink<H> {
    matcher: SelectorMatcher,
    handler: H,
    output: Vec<u8>,
    /// Reused scratch for the selectors matching the current element.
    matched: Vec<usize>,
    /// First handler error, if any (aborts the rewrite).
    error: Option<BoxError>,
}

impl<H: ElementContentHandler> TokenSink for RewriteSink<H> {
    fn start_tag(&mut self, tag: &StartTag<'_>) {
        if self.error.is_some() {
            self.output.extend_from_slice(tag.raw());
            return;
        }
        let Self {
            matcher,
            handler,
            output,
            matched,
            error,
        } = self;

        matched.clear();
        matcher.push_element(tag, |index| matched.push(index));
        if matched.is_empty() {
            output.extend_from_slice(tag.raw());
            return;
        }

        let mut element = Element::new(tag);
        for &index in matched.iter() {
            if let Err(err) = handler.handle_element(index, &mut element) {
                *error = Some(err);
                break;
            }
        }
        element.serialize_start(output);
    }

    fn end_tag(&mut self, tag: &EndTag<'_>) {
        self.matcher.pop_element(tag.name_hash());
        self.output.extend_from_slice(tag.raw());
    }

    fn text(&mut self, text: &Text<'_>) {
        self.output.extend_from_slice(text.raw());
    }

    fn comment(&mut self, comment: &Comment<'_>) {
        self.output.extend_from_slice(comment.raw());
    }

    fn cdata(&mut self, cdata: &Cdata<'_>) {
        self.output.extend_from_slice(cdata.raw());
    }

    fn doctype(&mut self, doctype: &Doctype<'_>) {
        self.output.extend_from_slice(doctype.raw());
    }
}

/// A streaming, selector-driven HTML rewriter.
///
/// Feed input with [`write`](Self::write) and finish with
/// [`end`](Self::end); the rewritten bytes accumulate in an internal buffer,
/// drained with [`take_output`](Self::take_output). Unmatched content passes
/// through byte-for-byte. For one-shot use, prefer [`rewrite_str`].
pub struct HtmlRewriter<H> {
    tokenizer: Tokenizer,
    sink: RewriteSink<H>,
}

impl<H: ElementContentHandler> HtmlRewriter<H> {
    /// Creates a rewriter that runs `handler` for elements matching
    /// `selectors` (the `selector` argument to the handler is the index into
    /// this slice).
    #[must_use]
    pub fn new(selectors: &[Selector], handler: H) -> Self {
        Self {
            tokenizer: Tokenizer::new(),
            sink: RewriteSink {
                matcher: SelectorMatcher::new(selectors),
                handler,
                output: Vec::new(),
                matched: Vec::new(),
                error: None,
            },
        }
    }

    /// Feeds a chunk of input, appending rewritten bytes to the output.
    ///
    /// # Errors
    ///
    /// Surfaces a handler error, or a [`ParsingAmbiguityError`] if the input
    /// is ambiguous for streaming parsing.
    ///
    /// [`ParsingAmbiguityError`]: crate::protocols::html::tokenizer::ParsingAmbiguityError
    pub fn write(&mut self, chunk: &[u8]) -> Result<(), BoxError> {
        self.tokenizer.write(chunk, &mut self.sink)?;
        self.sink.take_error()
    }

    /// Finalizes the stream, flushing any remaining input.
    ///
    /// # Errors
    ///
    /// See [`write`](Self::write).
    pub fn end(&mut self) -> Result<(), BoxError> {
        self.tokenizer.end(&mut self.sink)?;
        self.sink.take_error()
    }

    /// Removes and returns the rewritten output accumulated so far.
    #[must_use]
    pub fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.sink.output)
    }

    /// Consumes the rewriter, returning the handler (e.g. to read state
    /// accumulated during the rewrite).
    #[must_use]
    pub fn into_handler(self) -> H {
        self.sink.handler
    }
}

impl<H> RewriteSink<H> {
    fn take_error(&mut self) -> Result<(), BoxError> {
        match self.error.take() {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

type BoxedHandler<'h> = Box<dyn FnMut(&mut Element<'_>) -> HandlerResult + 'h>;

/// A builder bundling `(selector, closure)` pairs — the closure-based escape
/// hatch over the [`ElementContentHandler`] trait, for one-off rewrites that
/// don't need a dedicated state struct.
#[derive(Default)]
pub struct ElementContentHandlers<'h> {
    selectors: Vec<Selector>,
    handlers: Vec<BoxedHandler<'h>>,
}

impl<'h> ElementContentHandlers<'h> {
    /// Creates an empty set of handlers.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `handler` for elements matching `selector`.
    #[must_use]
    pub fn on(
        mut self,
        selector: Selector,
        handler: impl FnMut(&mut Element<'_>) -> HandlerResult + 'h,
    ) -> Self {
        self.selectors.push(selector);
        self.handlers.push(Box::new(handler));
        self
    }
}

impl ElementContentHandler for ElementContentHandlers<'_> {
    fn handle_element(&mut self, selector: usize, element: &mut Element<'_>) -> HandlerResult {
        match self.handlers.get_mut(selector) {
            Some(handler) => handler(element),
            None => Ok(()),
        }
    }
}

impl<'h> HtmlRewriter<ElementContentHandlers<'h>> {
    /// Creates a rewriter from a closure-based [`ElementContentHandlers`].
    #[must_use]
    pub fn from_handlers(handlers: ElementContentHandlers<'h>) -> Self {
        let selectors = handlers.selectors.clone();
        Self::new(&selectors, handlers)
    }
}

/// One-shot rewrite of a complete HTML string.
///
/// # Errors
///
/// Surfaces a handler error, a parsing-ambiguity error, or invalid UTF-8 in
/// the rewritten output.
pub fn rewrite_str(html: &str, handlers: ElementContentHandlers<'_>) -> Result<String, BoxError> {
    let mut rewriter = HtmlRewriter::from_handlers(handlers);
    rewriter.write(html.as_bytes())?;
    rewriter.end()?;
    String::from_utf8(rewriter.take_output()).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::{ElementContentHandlers, HtmlRewriter, rewrite_str};
    use crate::protocols::html::rewrite::{Element, ElementContentHandler, HandlerResult};
    use crate::protocols::html::selector::Selector;

    fn sel(s: &str) -> Selector {
        s.parse()
            .unwrap_or_else(|e| panic!("`{s}` should parse: {e}"))
    }

    fn rewrite(html: &str, handlers: ElementContentHandlers<'_>) -> String {
        rewrite_str(html, handlers).expect("rewrite succeeds")
    }

    #[test]
    fn unmatched_passes_through_verbatim() {
        let out = rewrite("<p>hi <b>x</b></p>", ElementContentHandlers::new());
        assert_eq!(out, "<p>hi <b>x</b></p>");
    }

    #[test]
    fn set_and_remove_attributes() {
        let out = rewrite(
            r#"<a href="/old" data-x="1">link</a>"#,
            ElementContentHandlers::new().on(sel("a"), |el| {
                el.set_attribute("href", "/new");
                el.remove_attribute("data-x");
                el.set_attribute("rel", "nofollow");
                Ok(())
            }),
        );
        assert_eq!(out, r#"<a href="/new" rel="nofollow">link</a>"#);
    }

    #[test]
    fn attribute_values_are_escaped() {
        let out = rewrite(
            "<a>x</a>",
            ElementContentHandlers::new().on(sel("a"), |el| {
                el.set_attribute("title", r#"a "b" & c"#);
                Ok(())
            }),
        );
        assert_eq!(out, r#"<a title="a &quot;b&quot; &amp; c">x</a>"#);
    }

    #[test]
    fn before_and_prepend() {
        let out = rewrite(
            "<body>content</body>",
            ElementContentHandlers::new().on(sel("body"), |el| {
                el.before_text("X");
                el.prepend_text("Y<&");
                Ok(())
            }),
        );
        // `before` precedes the start tag; `prepend` follows it; text escaped.
        assert_eq!(out, "X<body>Y&lt;&amp;content</body>");
    }

    #[test]
    fn reading_attributes() {
        let out = rewrite(
            r#"<a href="/x" disabled>k</a>"#,
            ElementContentHandlers::new().on(sel("a"), |el| {
                assert_eq!(el.attribute("href"), Some(&b"/x"[..]));
                assert!(el.has_attribute("disabled"));
                assert_eq!(el.attribute("disabled"), Some(&b""[..]));
                assert_eq!(el.attribute("missing"), None);
                Ok(())
            }),
        );
        assert_eq!(out, r#"<a href="/x" disabled>k</a>"#);
    }

    #[test]
    fn only_matching_elements_are_touched() {
        let out = rewrite(
            "<div><span>a</span><span>b</span></div>",
            ElementContentHandlers::new().on(sel("div > span"), |el| {
                el.set_attribute("data-hit", "1");
                Ok(())
            }),
        );
        assert_eq!(
            out,
            r#"<div><span data-hit="1">a</span><span data-hit="1">b</span></div>"#
        );
    }

    #[test]
    fn handler_error_aborts() {
        rewrite_str(
            "<a></a>",
            ElementContentHandlers::new().on(sel("a"), |_el| Err("boom".into())),
        )
        .expect_err("handler error should abort the rewrite");
    }

    /// A visitor struct *is* the shared state — no `Rc<RefCell>`.
    #[derive(Default)]
    struct LinkCounter {
        count: usize,
    }

    impl ElementContentHandler for LinkCounter {
        fn handle_element(&mut self, _selector: usize, element: &mut Element<'_>) -> HandlerResult {
            self.count += 1;
            element.set_attribute("data-n", &self.count.to_string());
            Ok(())
        }
    }

    #[test]
    fn visitor_trait_shares_state() {
        let selectors = [sel("a")];
        let mut rewriter = HtmlRewriter::new(&selectors, LinkCounter::default());
        rewriter.write(b"<a>1</a><a>2</a>").expect("write succeeds");
        rewriter.end().expect("end succeeds");
        let out = String::from_utf8(rewriter.take_output()).expect("utf8");
        assert_eq!(out, r#"<a data-n="1">1</a><a data-n="2">2</a>"#);
        assert_eq!(rewriter.into_handler().count, 2);
    }
}
