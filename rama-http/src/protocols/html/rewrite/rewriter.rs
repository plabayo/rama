//! The selector-driven HTML rewriter.

use rama_core::error::BoxError;

use super::super::selector::Selector;
use super::super::tokenizer::{
    Cdata, Comment, Doctype, EndTag, StartTag, Text, TokenSink, Tokenizer,
};
use super::SelectorMatcher;
use super::element::{Element, ElementContentHandler, EndActions, HandlerResult};

/// The [`TokenSink`] that drives matching + mutation + serialization.
struct RewriteSink<H> {
    matcher: SelectorMatcher,
    handler: H,
    output: Vec<u8>,
    /// Reused scratch for the selectors matching the current element.
    matched: Vec<usize>,
    /// Deferred end-tag actions, one entry per open scope — kept in lockstep
    /// with the matcher's open-element stack (see [`SelectorMatcher`]).
    pending: Vec<EndActions>,
    /// Number of open ancestors currently suppressing their content (from a
    /// `remove` / `replace` / `set_inner_content`). While non-zero, token
    /// output is swallowed.
    suppress_depth: usize,
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
            pending,
            suppress_depth,
            error,
        } = self;

        let implied = matcher.pop_implied_for_start(tag.name_hash());
        close_pending(output, pending, suppress_depth, implied, None);

        // Visible iff no enclosing element is suppressing its content after
        // any optional-end-tag frames closed by this start tag.
        let visible = *suppress_depth == 0;
        matched.clear();
        let opened = matcher.push_element(tag, |index| matched.push(index));

        if matched.is_empty() {
            if visible {
                output.extend_from_slice(tag.raw());
            }
            if opened {
                pending.push(EndActions::passthrough());
            }
            return;
        }

        let mut element = Element::new(tag);
        for &index in matched.iter() {
            if let Err(err) = handler.handle_element(index, &mut element) {
                *error = Some(err);
                break;
            }
        }
        let actions = element.serialize(output, visible);

        if opened {
            if actions.suppress_content {
                *suppress_depth += 1;
            }
            pending.push(actions);
        } else if visible {
            // Void / self-closing: no children and no end tag, so the
            // end-anchored content (if any) lands right here.
            output.extend_from_slice(actions.append.as_bytes());
            output.extend_from_slice(actions.after.as_bytes());
        }
    }

    fn end_tag(&mut self, tag: &EndTag<'_>) {
        if self.error.is_some() {
            self.output.extend_from_slice(tag.raw());
            return;
        }
        let popped = self.matcher.pop_element(tag.name_hash());
        if popped == 0 {
            // Stray end tag: emit verbatim unless inside suppressed content.
            if self.suppress_depth == 0 {
                self.output.extend_from_slice(tag.raw());
            }
            return;
        }
        // The end tag closes `popped` frames: the named element plus any
        // still-open descendants it implicitly closes. Every closed frame gets
        // its deferred end actions at this point; only the named frame owns
        // the source end tag bytes.
        close_pending(
            &mut self.output,
            &mut self.pending,
            &mut self.suppress_depth,
            popped,
            Some(tag.raw()),
        );
    }

    fn text(&mut self, text: &Text<'_>) {
        self.passthrough(text.raw());
    }

    fn comment(&mut self, comment: &Comment<'_>) {
        self.passthrough(comment.raw());
    }

    fn cdata(&mut self, cdata: &Cdata<'_>) {
        self.passthrough(cdata.raw());
    }

    fn doctype(&mut self, doctype: &Doctype<'_>) {
        self.passthrough(doctype.raw());
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
                pending: Vec::new(),
                suppress_depth: 0,
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
        self.sink.finish();
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
    /// Emits a leaf token's raw bytes, unless it is inside suppressed content.
    /// (On error the rewrite is doomed and its output discarded, so bytes are
    /// passed through to keep the buffer well-formed for inspection.)
    fn passthrough(&mut self, raw: &[u8]) {
        if self.error.is_some() || self.suppress_depth == 0 {
            self.output.extend_from_slice(raw);
        }
    }

    fn take_error(&mut self) -> Result<(), BoxError> {
        match self.error.take() {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    fn finish(&mut self) {
        let popped = self.matcher.finish();
        close_pending(
            &mut self.output,
            &mut self.pending,
            &mut self.suppress_depth,
            popped,
            None,
        );
    }
}

fn close_pending(
    output: &mut Vec<u8>,
    pending: &mut Vec<EndActions>,
    suppress_depth: &mut usize,
    popped: usize,
    named_end_tag: Option<&[u8]>,
) {
    for i in 0..popped {
        let Some(actions) = pending.pop() else {
            break;
        };
        if actions.suppress_content {
            *suppress_depth = (*suppress_depth).saturating_sub(1);
        }
        if *suppress_depth == 0 {
            output.extend_from_slice(actions.append.as_bytes());
            if i + 1 == popped
                && let Some(raw) = named_end_tag
                && !actions.suppress_end_tag
            {
                output.extend_from_slice(raw);
            }
            output.extend_from_slice(actions.after.as_bytes());
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
    use crate::protocols::html::PreEscaped;
    use crate::protocols::html::rewrite::{
        AttributeName, Element, ElementContentHandler, HandlerResult,
    };
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
                el.set_attribute(AttributeName::from_static("href"), "/new");
                el.remove_attribute("data-x");
                el.set_attribute(AttributeName::from_static("rel"), "nofollow");
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
                el.set_attribute(AttributeName::from_static("title"), r#"a "b" & c"#);
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
                el.before("X");
                el.prepend("Y<&");
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
                el.set_attribute(AttributeName::from_static("data-hit"), "1");
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

    /// A handler struct carrying its own accumulated state.
    #[derive(Default)]
    struct LinkCounter {
        count: usize,
    }

    impl ElementContentHandler for LinkCounter {
        fn handle_element(&mut self, _selector: usize, element: &mut Element<'_>) -> HandlerResult {
            self.count += 1;
            element.set_attribute(
                AttributeName::from_static("data-n"),
                &self.count.to_string(),
            );
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

    // --- slice B: end-anchored edits ------------------------------------

    #[test]
    fn append_inserts_before_end_tag() {
        let out = rewrite(
            "<div>x</div>",
            ElementContentHandlers::new().on(sel("div"), |el| {
                el.append("!");
                Ok(())
            }),
        );
        assert_eq!(out, "<div>x!</div>");
    }

    #[test]
    fn after_inserts_after_end_tag() {
        let out = rewrite(
            "<div>x</div>",
            ElementContentHandlers::new().on(sel("div"), |el| {
                el.after("Y");
                Ok(())
            }),
        );
        assert_eq!(out, "<div>x</div>Y");
    }

    #[test]
    fn set_inner_content_replaces_children() {
        let out = rewrite(
            "<div>old<b>stuff</b></div>",
            ElementContentHandlers::new().on(sel("div"), |el| {
                el.set_inner_content("new");
                Ok(())
            }),
        );
        assert_eq!(out, "<div>new</div>");
    }

    #[test]
    fn set_inner_content_keeps_attribute_edits() {
        let out = rewrite(
            r#"<div class="a">old</div>"#,
            ElementContentHandlers::new().on(sel("div"), |el| {
                el.set_attribute(AttributeName::from_static("data-x"), "1");
                el.set_inner_content("new");
                Ok(())
            }),
        );
        assert_eq!(out, r#"<div class="a" data-x="1">new</div>"#);
    }

    #[test]
    fn replace_swaps_whole_element() {
        let out = rewrite(
            "a<p>hi</p>b",
            ElementContentHandlers::new().on(sel("p"), |el| {
                el.replace("X");
                Ok(())
            }),
        );
        assert_eq!(out, "aXb");
    }

    #[test]
    fn replace_then_after() {
        let out = rewrite(
            "<p>hi</p>",
            ElementContentHandlers::new().on(sel("p"), |el| {
                el.replace("R");
                el.after("A");
                Ok(())
            }),
        );
        assert_eq!(out, "RA");
    }

    #[test]
    fn remove_drops_element_and_children() {
        let out = rewrite(
            "a<p>h<b>i</b></p>b",
            ElementContentHandlers::new().on(sel("p"), |el| {
                el.remove();
                Ok(())
            }),
        );
        assert_eq!(out, "ab");
    }

    #[test]
    fn remove_keeps_before_and_after() {
        let out = rewrite(
            "x<p>hi</p>y",
            ElementContentHandlers::new().on(sel("p"), |el| {
                el.before("B");
                el.remove();
                el.after("A");
                Ok(())
            }),
        );
        // `before` then (element gone) then `after`.
        assert_eq!(out, "xBAy");
    }

    #[test]
    fn remove_and_keep_content_drops_only_tags() {
        let out = rewrite(
            "a<p>hi</p>b",
            ElementContentHandlers::new().on(sel("p"), |el| {
                el.remove_and_keep_content();
                Ok(())
            }),
        );
        assert_eq!(out, "ahib");
    }

    #[test]
    fn match_inside_removed_ancestor_is_swallowed() {
        // The inner handler still runs, but its output is suppressed by the
        // removed ancestor.
        let out = rewrite(
            "<div><a>x</a></div>",
            ElementContentHandlers::new()
                .on(sel("div"), |el| {
                    el.remove();
                    Ok(())
                })
                .on(sel("a"), |el| {
                    el.set_attribute(AttributeName::from_static("data-hit"), "1");
                    Ok(())
                }),
        );
        assert_eq!(out, "");
    }

    #[test]
    fn after_on_void_element() {
        let out = rewrite(
            "<img src=x>tail",
            ElementContentHandlers::new().on(sel("img"), |el| {
                el.after("Y");
                Ok(())
            }),
        );
        // No end tag for a void element: `after` lands right after it.
        assert_eq!(out, "<img src=x>Ytail");
    }

    #[test]
    fn append_accepts_into_html() {
        let out = rewrite(
            "<div>x</div>",
            ElementContentHandlers::new().on(sel("div"), |el| {
                el.append(PreEscaped("<i>!</i>"));
                Ok(())
            }),
        );
        // `PreEscaped` content is written verbatim (the `IntoHtml` path).
        assert_eq!(out, "<div>x<i>!</i></div>");
    }

    #[test]
    fn remove_survives_chunk_boundaries() {
        // Suppression state must persist across `write` calls.
        let mut rewriter =
            HtmlRewriter::from_handlers(ElementContentHandlers::new().on(sel("div"), |el| {
                el.remove();
                Ok(())
            }));
        for chunk in [&b"a<div>con"[..], b"tent</di", b"v>b"] {
            rewriter.write(chunk).expect("write succeeds");
        }
        rewriter.end().expect("end succeeds");
        let out = String::from_utf8(rewriter.take_output()).expect("utf8");
        assert_eq!(out, "ab");
    }

    // --- robustness on malformed / crossed nesting --------------------------

    #[test]
    fn remove_survives_crossed_nesting() {
        // `</d>` implicitly closes the still-open `<e>`; suppression must clear
        // so the trailing text is not swallowed.
        let out = rewrite(
            "<d><e></d>VISIBLE",
            ElementContentHandlers::new().on(sel("d"), |el| {
                el.remove();
                Ok(())
            }),
        );
        assert_eq!(out, "VISIBLE");
    }

    #[test]
    fn remove_with_unclosed_child_keeps_the_rest() {
        // Only the `<a>…</a>` span is removed; the misnested remainder passes
        // through byte-for-byte (no runaway suppression).
        let out = rewrite(
            "keep<a>1<b>2</a>3</b>4",
            ElementContentHandlers::new().on(sel("a"), |el| {
                el.remove();
                Ok(())
            }),
        );
        assert_eq!(out, "keep3</b>4");
    }

    #[test]
    fn set_inner_content_survives_crossed_nesting() {
        let out = rewrite(
            "<a>1<b>2</a>3",
            ElementContentHandlers::new().on(sel("a"), |el| {
                el.set_inner_content("X");
                Ok(())
            }),
        );
        assert_eq!(out, "<a>X</a>3");
    }

    #[test]
    fn nested_match_inside_removed_ancestor_is_swallowed() {
        // The inner `<a>`'s handler still runs, but its end-anchored output is
        // suppressed along with the rest of the removed subtree.
        let out = rewrite(
            "<div><a>x</a></div>z",
            ElementContentHandlers::new()
                .on(sel("div"), |el| {
                    el.remove();
                    Ok(())
                })
                .on(sel("a"), |el| {
                    el.after("!");
                    el.append("?");
                    Ok(())
                }),
        );
        assert_eq!(out, "z");
    }

    #[test]
    fn replace_on_self_closing_element() {
        // A self-closing (non-void) element has no end tag: the replacement is
        // emitted inline and suppression is never engaged.
        let out = rewrite(
            "<x/>tail",
            ElementContentHandlers::new().on(sel("x"), |el| {
                el.replace("R");
                Ok(())
            }),
        );
        assert_eq!(out, "Rtail");
    }

    #[test]
    fn append_applies_to_optional_li_end_tags() {
        let out = rewrite(
            "<ul><li>one<li>two</ul>",
            ElementContentHandlers::new().on(sel("li"), |el| {
                el.append("!");
                Ok(())
            }),
        );
        assert_eq!(out, "<ul><li>one!<li>two!</ul>");
    }

    #[test]
    fn start_implied_p_close_restores_suppression() {
        #[derive(Default)]
        struct RemoveFirst {
            seen: usize,
        }

        impl ElementContentHandler for RemoveFirst {
            fn handle_element(
                &mut self,
                _selector: usize,
                element: &mut Element<'_>,
            ) -> HandlerResult {
                if self.seen == 0 {
                    element.remove();
                } else {
                    element.append("!");
                }
                self.seen += 1;
                Ok(())
            }
        }

        let selectors = [sel("p")];
        let mut rewriter = HtmlRewriter::new(&selectors, RemoveFirst::default());
        rewriter
            .write(b"<p>drop<p>keep</p>")
            .expect("write succeeds");
        rewriter.end().expect("end succeeds");
        let out = String::from_utf8(rewriter.take_output()).expect("utf8");
        assert_eq!(out, "<p>keep!</p>");
    }

    #[test]
    fn eof_flushes_end_anchored_actions() {
        let out = rewrite(
            "<div>tail",
            ElementContentHandlers::new().on(sel("div"), |el| {
                el.append("!");
                el.after("A");
                Ok(())
            }),
        );
        assert_eq!(out, "<div>tail!A");
    }
}
