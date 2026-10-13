//! The selector-driven HTML rewriter.

use std::mem;

use rama_core::error::BoxError;
use rama_utils::macros::generate_set_and_with;

use super::element::{Element, ElementContentHandler, EndActions, HandlerResult};
use super::tree::Origin;
use super::{Pushed, ScopeMode, SelectorMatcher};
use crate::protocols::html::selector::Selector;
use crate::protocols::html::tokenizer::{
    Cdata, Comment, ContextTracker, Doctype, EndTag, HtmlTag, LocalNameHash, ParseSink,
    ParsingAmbiguityError, Span, StartTag, Text, TextMode, Tokenizer,
};

/// The UTF-8 byte order mark: browsers strip it while decoding, before any
/// parsing decision.
const BOM: &[u8; 3] = b"\xEF\xBB\xBF";

/// The [`ParseSink`] that drives matching + mutation + serialization.
struct RewriteSink<H> {
    matcher: SelectorMatcher,
    /// Text-mode and CDATA decisions in [`ScopeMode::NearestMatch`], which
    /// does not track namespaces in its tree.
    context: ContextTracker,
    handler: H,
    output: Vec<u8>,
    /// Bytes of the current input that pass through unchanged but are not
    /// copied yet: such tokens are contiguous, so a run of them is one copy.
    pass: Span,
    /// Reused scratch for the selectors matching the current element.
    matched: Vec<usize>,
    /// Deferred end-anchored actions of open elements, ordered by frame
    /// index (one entry per frame at most).
    pending: Vec<Pending>,
    /// Number of open elements currently suppressing their content (from a
    /// `remove` / `replace` / `set_inner_content`). While non-zero, token
    /// output is swallowed.
    suppress_depth: usize,
    /// How the head's own edits treat its content, kept after it closes for
    /// tags browsers still insert into it.
    closed_head: Option<HeadSuppression>,
    /// First handler error, if any (aborts the rewrite).
    error: Option<BoxError>,
}

struct Pending {
    depth: usize,
    actions: EndActions,
    /// The element is the head (see [`RewriteSink::closed_head`]).
    head: bool,
}

#[derive(Clone, Copy)]
struct HeadSuppression {
    suppress_content: bool,
    suppress_end_tag: bool,
}

impl<H> RewriteSink<H> {
    fn browser(&self) -> bool {
        self.matcher.tree.mode == ScopeMode::Browser
    }
}

impl<H: ElementContentHandler> ParseSink for RewriteSink<H> {
    fn cdata_allowed(&self) -> bool {
        if self.browser() {
            self.matcher.tree.cdata_allowed()
        } else {
            self.context.cdata_allowed()
        }
    }

    fn text_mode(&mut self, hash: LocalNameHash, name: &[u8]) -> Option<TextMode> {
        if self.browser() {
            self.matcher.tree.text_mode(hash, name)
        } else {
            self.context.peek_text_mode(hash, name)
        }
    }

    fn start_tag(&mut self, tag: &StartTag<'_>) -> Result<(), ParsingAmbiguityError> {
        if !self.browser() {
            self.context.on_start_tag(tag)?;
        }
        self.handle_start_tag(tag);
        Ok(())
    }

    fn end_tag(&mut self, tag: &EndTag<'_>, closes_text: bool) {
        if !self.browser() && !closes_text {
            self.context.on_end_tag(tag);
        }
        self.handle_end_tag(tag);
    }

    fn text(&mut self, text: &Text<'_>) {
        let (input, raw) = (text.input, text.raw);
        if self.error.is_some() {
            self.pass(input, raw);
            return;
        }
        // Leading whitespace stays in a head or column group; the stack
        // changes at the first other byte.
        let at = raw.start + self.matcher.text(text.raw());
        if !self.matcher.tree.changed() {
            self.passthrough(input, raw);
            return;
        }
        self.passthrough(input, Span::new(raw.start, at));
        self.apply_tree_change(input, None);
        self.passthrough(input, Span::new(at, raw.end));
    }

    fn comment(&mut self, comment: &Comment<'_>) {
        self.passthrough(comment.input, comment.raw);
    }

    fn cdata(&mut self, cdata: &Cdata<'_>) {
        self.passthrough(cdata.input, cdata.raw);
    }

    fn doctype(&mut self, doctype: &Doctype<'_>) {
        self.matcher.tree.doctype(doctype.raw());
        self.passthrough(doctype.input, doctype.raw);
    }

    fn flush(&mut self, input: &[u8]) {
        self.flush_pass(input);
    }
}

impl<H: ElementContentHandler> RewriteSink<H> {
    fn handle_start_tag(&mut self, tag: &StartTag<'_>) {
        if self.error.is_some() {
            self.pass(tag.input, tag.raw);
            return;
        }
        let plan = self.matcher.prepare_start(tag);
        if self.matcher.tree.changed() {
            self.apply_tree_change(tag.input, None);
        }

        // Visible iff no enclosing element is suppressing its content after
        // any frames closed by this start tag.
        let visible = self.suppress_depth == 0;
        let Self {
            matcher, matched, ..
        } = self;
        matched.clear();
        let pushed = matcher.push_element(tag, plan, |index| matched.push(index));
        if let Pushed::Open(index) = pushed {
            matcher.tree.at_mut(index).visible = visible;
        }

        if self.matched.is_empty() {
            if visible {
                self.pass(tag.input, tag.raw);
            }
            return;
        }

        self.flush_pass(tag.input);
        let Self {
            handler,
            output,
            matched,
            pending,
            suppress_depth,
            error,
            ..
        } = self;
        let mut element = Element::new(tag);
        for &index in matched.iter() {
            if let Err(err) = handler.handle_element(index, &mut element) {
                *error = Some(err);
                break;
            }
        }
        let is_head = element.tag() == HtmlTag::Head;
        let actions = element.serialize(output, visible);
        if !visible || actions.is_empty() {
            return;
        }
        match pushed {
            Pushed::Open(depth) | Pushed::Merged { frame: depth, .. } => {
                if actions.suppress_content {
                    *suppress_depth += 1;
                }
                // Merged elements sit below newer entries; each frame has at
                // most one entry, and only the first tag naming it claims it.
                let at = pending.partition_point(|entry| entry.depth < depth);
                pending.insert(
                    at,
                    Pending {
                        depth,
                        actions,
                        head: is_head,
                    },
                );
            }
            Pushed::Leaf | Pushed::Nothing => {
                // Void / self-closing: no children and no end tag, so the
                // end-anchored content (if any) lands right here.
                output.extend_from_slice(actions.append.as_bytes());
                output.extend_from_slice(actions.after.as_bytes());
            }
        }
    }

    fn handle_end_tag(&mut self, tag: &EndTag<'_>) {
        if self.error.is_some() {
            self.pass(tag.input, tag.raw);
            return;
        }
        let outcome = self.matcher.pop_element(tag);
        self.apply_tree_change(tag.input, outcome.closes_named.then_some(tag.raw));
        if outcome.closes_named {
            return;
        }
        let anchors = outcome.anchors.into_iter().filter(|&index| index > 0);
        let mut own_suppression = 0;
        let mut tag_hidden = true;
        let mut anchored = false;
        for index in anchors.clone() {
            anchored = true;
            let entry = self.entry(index);
            if entry.is_some_and(|actions| actions.suppress_content) {
                own_suppression += 1;
            }
            // Only the outermost anchor owns the source end tag.
            tag_hidden = entry.map_or(!self.matcher.tree.at(index).visible, |actions| {
                actions.suppress_end_tag
            });
        }
        if !anchored {
            if self.suppress_depth == 0 {
                self.pass(tag.input, tag.raw);
            }
            return;
        }
        self.flush_pass(tag.input);
        // Inside removed content the end tag is swallowed like the rest.
        let show_tag = !tag_hidden && self.suppress_depth == own_suppression;
        let mut anchors = anchors.peekable();
        while let Some(index) = anchors.next() {
            let outer = anchors.peek().is_none();
            let Some(slot) = self.slot(index) else {
                if outer && show_tag {
                    self.output.extend_from_slice(tag.raw());
                }
                continue;
            };
            // Inner anchors end implicitly: finish each inner edit first.
            let actions = &mut self.pending[slot].actions;
            self.output
                .extend_from_slice(mem::take(&mut actions.append).as_bytes());
            if outer && show_tag {
                self.output.extend_from_slice(tag.raw());
            }
            let actions = &mut self.pending[slot].actions;
            self.output
                .extend_from_slice(mem::take(&mut actions.after).as_bytes());
        }
    }

    /// The pending entry of the open frame at `index`.
    fn slot(&self, index: usize) -> Option<usize> {
        self.pending
            .binary_search_by_key(&index, |entry| entry.depth)
            .ok()
    }

    fn entry(&self, index: usize) -> Option<&EndActions> {
        self.slot(index).map(|slot| &self.pending[slot].actions)
    }

    /// Follows a tree change: emits the end-anchored edits of closed
    /// elements (with the `named_end_tag` of `input` standing for the deepest
    /// one's end), and marks the elements browsers created without a tag.
    #[inline]
    fn apply_tree_change(&mut self, input: &[u8], named_end_tag: Option<Span>) {
        if !self.matcher.tree.changed() {
            return;
        }
        let low = self.matcher.sync();
        if self.pending.last().is_some_and(|entry| entry.depth >= low) {
            self.flush_pass(input);
            close_pending(
                &mut self.output,
                &mut self.pending,
                &mut self.suppress_depth,
                &mut self.closed_head,
                low,
                named_end_tag.and_then(|raw| input.get(raw.start..raw.end)),
            );
        } else if let Some(raw) = named_end_tag
            && self.suppress_depth == 0
        {
            self.pass(input, raw);
        }
        #[cfg(fuzzing)]
        self.assert_consistent();
        for index in low..self.matcher.tree.depth() {
            let visible = self.suppress_depth == 0;
            let frame = self.matcher.tree.at_mut(index);
            match frame.origin {
                Origin::Reopened => {
                    // Content browsers put back into a removed head stays removed.
                    if let Some(head) = self.closed_head
                        && head.suppress_content
                        && frame.visible
                    {
                        self.suppress_depth += 1;
                        self.pending.push(Pending {
                            depth: index,
                            actions: EndActions::suppressing(head.suppress_end_tag),
                            head: true,
                        });
                    }
                }
                _ => frame.visible = visible,
            }
        }
    }
}

/// A streaming, selector-driven HTML rewriter.
///
/// Feed input with [`write`](Self::write) and finish with
/// [`end`](Self::end); the rewritten bytes accumulate in an internal buffer,
/// drained with [`take_output`](Self::take_output). Unmatched content passes
/// through byte-for-byte. For one-shot use, prefer [`rewrite_str`].
///
/// By default ([`ScopeMode::Browser`]) the input is parsed as a full
/// document, the way browsers parse a page they navigate to.
pub struct HtmlRewriter<H> {
    tokenizer: Tokenizer,
    sink: RewriteSink<H>,
    /// Leading UTF-8 BOM bytes seen so far (`None` once decided).
    bom: Option<u8>,
    /// Whether input has been written (the scope mode is then fixed).
    started: bool,
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
                context: ContextTracker::new(false),
                handler,
                output: Vec::new(),
                pass: Span::empty(0),
                matched: Vec::new(),
                pending: Vec::new(),
                suppress_depth: 0,
                closed_head: None,
                error: None,
            },
            bom: Some(0),
            started: false,
        }
    }

    generate_set_and_with! {
        /// Sets how omitted and misnested end tags affect element scopes.
        /// Defaults to [`ScopeMode::Browser`].
        ///
        /// The mode is fixed once input has been written: later calls have no
        /// effect, as the document's structure so far was built under the
        /// mode it started with.
        pub fn scope_mode(mut self, mode: ScopeMode) -> Self {
            if !self.started {
                self.sink.matcher.tree.mode = mode;
            }
            self
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
        self.started = true;
        let Some(chunk) = self.skip_bom(chunk)? else {
            return Ok(());
        };
        self.tokenizer.write_parse(chunk, &mut self.sink)?;
        self.sink.take_error()
    }

    /// Finalizes the stream, flushing any remaining input.
    ///
    /// # Errors
    ///
    /// See [`write`](Self::write).
    pub fn end(&mut self) -> Result<(), BoxError> {
        self.started = true;
        if let Some(seen) = self.bom.take()
            && let Some(prefix) = BOM.get(..usize::from(seen))
            && !prefix.is_empty()
        {
            // A truncated BOM is plain text.
            self.tokenizer.write_parse(prefix, &mut self.sink)?;
        }
        self.tokenizer.end_parse(&mut self.sink)?;
        self.sink.finish();
        self.sink.take_error()
    }

    /// Passes a leading UTF-8 BOM (possibly split across writes) straight
    /// to the output, returning the rest of `chunk` to parse (`None` while a
    /// BOM prefix is still undecided).
    fn skip_bom<'c>(&mut self, chunk: &'c [u8]) -> Result<Option<&'c [u8]>, BoxError> {
        let Some(seen) = self.bom else {
            return Ok(Some(chunk));
        };
        let seen = usize::from(seen);
        let needed = BOM.get(seen..).unwrap_or_default();
        let take = needed.len().min(chunk.len());
        if chunk.get(..take) == needed.get(..take) {
            if take < needed.len() {
                self.bom = u8::try_from(seen + take).ok();
                return Ok(None);
            }
            self.bom = None;
            self.sink.output.extend_from_slice(BOM);
            return Ok(chunk.get(take..));
        }
        self.bom = None;
        if let Some(prefix) = BOM.get(..seen)
            && !prefix.is_empty()
        {
            self.tokenizer.write_parse(prefix, &mut self.sink)?;
        }
        Ok(Some(chunk))
    }

    /// Removes and returns the rewritten output accumulated so far.
    #[must_use]
    pub fn take_output(&mut self) -> Vec<u8> {
        mem::take(&mut self.sink.output)
    }

    /// Consumes the rewriter, returning the handler (e.g. to read state
    /// accumulated during the rewrite).
    #[must_use]
    pub fn into_handler(self) -> H {
        self.sink.handler
    }
}

impl<H> RewriteSink<H> {
    /// Recounts the stack caches and checks the edit bookkeeping against them.
    #[cfg(fuzzing)]
    fn assert_consistent(&self) {
        self.matcher.assert_consistent();
        let depth = self.matcher.tree.depth();
        assert!(
            self.pending.windows(2).all(|w| w[0].depth < w[1].depth),
            "pending edits are ordered by frame, one per frame"
        );
        assert!(
            self.pending.last().is_none_or(|entry| entry.depth < depth),
            "pending edits belong to open frames"
        );
        let suppressing = self
            .pending
            .iter()
            .filter(|entry| entry.actions.suppress_content)
            .count();
        assert_eq!(suppressing, self.suppress_depth, "suppression depth");
    }

    /// Emits a leaf token's raw bytes (the `raw` span of `input`), unless it
    /// is inside suppressed content. (On error the rewrite is doomed and its
    /// output discarded, so bytes are passed through to keep the buffer
    /// well-formed for inspection.)
    #[inline]
    fn passthrough(&mut self, input: &[u8], raw: Span) {
        if self.error.is_some() || self.suppress_depth == 0 {
            self.pass(input, raw);
        }
    }

    /// Passes the `raw` span of `input` to the output unchanged.
    #[inline]
    fn pass(&mut self, input: &[u8], raw: Span) {
        if self.pass.end != raw.start {
            self.flush_pass(input);
            self.pass.start = raw.start;
        }
        self.pass.end = raw.end;
    }

    /// Copies the pending passthrough bytes of `input` to the output; done
    /// before anything else is written.
    #[inline]
    fn flush_pass(&mut self, input: &[u8]) {
        if self.pass.start < self.pass.end {
            self.output.extend_from_slice(
                input
                    .get(self.pass.start..self.pass.end)
                    .unwrap_or_default(),
            );
        }
        self.pass.start = self.pass.end;
    }

    fn take_error(&mut self) -> Result<(), BoxError> {
        match self.error.take() {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    fn finish(&mut self) {
        self.matcher.finish();
        let low = self.matcher.sync();
        close_pending(
            &mut self.output,
            &mut self.pending,
            &mut self.suppress_depth,
            &mut self.closed_head,
            low,
            None,
        );
    }
}

/// Emits the end-anchored edits of the elements at stack index `keep_depth`
/// and above (all closed), innermost first; `named_end_tag` is the source end
/// tag standing for the end of the element at `keep_depth`.
fn close_pending(
    output: &mut Vec<u8>,
    pending: &mut Vec<Pending>,
    suppress_depth: &mut usize,
    closed_head: &mut Option<HeadSuppression>,
    keep_depth: usize,
    named_end_tag: Option<&[u8]>,
) {
    let mut named = false;
    while pending
        .last()
        .is_some_and(|entry| entry.depth >= keep_depth)
    {
        let Some(Pending {
            depth,
            actions,
            head,
        }) = pending.pop()
        else {
            break;
        };
        if actions.suppress_content {
            *suppress_depth = (*suppress_depth).saturating_sub(1);
        }
        if head {
            *closed_head = Some(HeadSuppression {
                suppress_content: actions.suppress_content,
                suppress_end_tag: actions.suppress_end_tag,
            });
        }
        if depth == keep_depth {
            named = true;
        }
        if *suppress_depth == 0 {
            output.extend_from_slice(actions.append.as_bytes());
            if depth == keep_depth
                && !actions.suppress_end_tag
                && let Some(raw) = named_end_tag
            {
                output.extend_from_slice(raw);
            }
            output.extend_from_slice(actions.after.as_bytes());
        }
    }
    if !named
        && *suppress_depth == 0
        && let Some(raw) = named_end_tag
    {
        output.extend_from_slice(raw);
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
    fn html_self_closing_flag_does_not_end_suppression() {
        // HTML ignores the self-closing flag on non-void elements.
        let out = rewrite(
            "<x/>tail",
            ElementContentHandlers::new().on(sel("x"), |el| {
                el.replace("R");
                Ok(())
            }),
        );
        assert_eq!(out, "R");
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

    // --- foreign-content integration points ---------------------------------

    fn mark_hit(selector: &str) -> ElementContentHandlers<'static> {
        ElementContentHandlers::new().on(sel(selector), |el| {
            el.set_attribute(AttributeName::from_static("hit"), "");
            Ok(())
        })
    }

    #[test]
    fn consecutive_svg_integration_points_all_match() {
        let html = "<svg><desc>d</desc><title>t</title><foreignObject></foreignObject></svg>";
        let expected = r#"<svg><desc hit="">d</desc><title hit="">t</title><foreignObject hit=""></foreignObject></svg>"#;
        assert_eq!(
            rewrite(html, mark_hit("desc, title, foreignobject")),
            expected
        );

        // Same result however the input is split across writes.
        let mut rewriter = HtmlRewriter::from_handlers(mark_hit("desc, title, foreignobject"));
        for chunk in html.as_bytes().chunks(1) {
            rewriter.write(chunk).expect("write succeeds");
        }
        rewriter.end().expect("end succeeds");
        let out = String::from_utf8(rewriter.take_output()).expect("utf8");
        assert_eq!(out, expected);
    }

    #[test]
    fn consecutive_math_ml_integration_points_all_match() {
        assert_eq!(
            rewrite(
                "<math><mi>x</mi><mo>+</mo><mn>1</mn><annotation-xml></annotation-xml></math>",
                mark_hit("mi, mo, mn, annotation-xml"),
            ),
            r#"<math><mi hit="">x</mi><mo hit="">+</mo><mn hit="">1</mn><annotation-xml hit=""></annotation-xml></math>"#
        );
    }
}
