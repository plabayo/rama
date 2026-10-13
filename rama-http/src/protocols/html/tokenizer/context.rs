//! Tree-builder *simulation*: just enough open-element context to tokenize
//! correctly without building a DOM.
//!
//! Two things depend on context that a flat tokenizer otherwise can't know:
//!
//!   * **Text mode** — `<script>`, `<style>`, `<textarea>`, … switch their
//!     body to a raw-text parsing mode, but only in the HTML namespace.
//!   * **CDATA** — `<![CDATA[ … ]]>` is real character data inside foreign
//!     content (SVG/MathML) and a bogus comment everywhere else.
//!
//! HTML is context-sensitive, so this is modelled with a small namespace
//! stack plus the integration-point / breakout rules. A few non-conforming
//! constructs (text-mode tags inside `<select>` / after `<frameset>`) make
//! the context genuinely ambiguous for a streaming parser; following
//! lol-html, those bail out with a [`ParsingAmbiguityError`] in strict mode
//! rather than risk mis-tokenizing (an XSS-gadget hazard).
//!
//! Adapted from lol-html's `tree_builder_simulator` (BSD-3-Clause).

use std::error::Error;
use std::fmt;

use super::charref::attribute_value_is;
use super::name::{KnownName, KnownNames, LocalNameHash};
use super::token::{EndTag, StartTag};

// --- known tag names -------------------------------------------------------

const SVG: KnownName = KnownName::new(b"svg");
const MATH: KnownName = KnownName::new(b"math");
const FONT: KnownName = KnownName::new(b"font");
const P: KnownName = KnownName::new(b"p");
const BR: KnownName = KnownName::new(b"br");
const ANNOTATION_XML: KnownName = KnownName::new(b"annotation-xml");

const SCRIPT: KnownName = KnownName::new(b"script");
const NOFRAMES: KnownName = KnownName::new(b"noframes");

// SVG HTML-integration points.
const SVG_HTML_INTEGRATION_POINTS: KnownNames<3> =
    KnownNames::new([b"foreignobject", b"desc", b"title"]);

// MathML text-integration points.
const MATHML_TEXT_INTEGRATION_POINTS: KnownNames<5> =
    KnownNames::new([b"mi", b"mo", b"mn", b"ms", b"mtext"]);

// Ambiguity-guard insertion-mode markers.
const SELECT: KnownName = KnownName::new(b"select");
const FRAMESET: KnownName = KnownName::new(b"frameset");
const TEMPLATE: KnownName = KnownName::new(b"template");

/// HTML elements that force an exit from foreign content (per the HTML
/// "any other start tag" foreign-content breakout list).
const BREAKOUT_TAGS: KnownNames<44> = KnownNames::new([
    b"b",
    b"big",
    b"blockquote",
    b"body",
    b"br",
    b"center",
    b"code",
    b"dd",
    b"div",
    b"dl",
    b"dt",
    b"em",
    b"embed",
    b"h1",
    b"h2",
    b"h3",
    b"h4",
    b"h5",
    b"h6",
    b"head",
    b"hr",
    b"i",
    b"img",
    b"li",
    b"listing",
    b"menu",
    b"meta",
    b"nobr",
    b"ol",
    b"p",
    b"pre",
    b"ruby",
    b"s",
    b"small",
    b"span",
    b"strong",
    b"strike",
    b"sub",
    b"sup",
    b"table",
    b"tt",
    b"u",
    b"ul",
    b"var",
]);

/// Start tags that end the "in select" insertion mode early.
const SELECT_EXITS: KnownNames<4> = KnownNames::new([b"select", b"textarea", b"input", b"keygen"]);

/// How an element's body is tokenized once its start tag is seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TextMode {
    /// `<style>`, `<xmp>`, `<iframe>`, `<noembed>`, `<noframes>`,
    /// `<noscript>` — raw text until the matching end tag.
    RawText,
    /// `<textarea>`, `<title>` — like raw text (bytes are kept raw, so the
    /// only practical difference from `RawText` is the element name).
    RcData,
    /// `<script>` — raw text with the HTML script-data escape rules.
    ScriptData,
    /// `<plaintext>` — everything to end of input is text.
    PlainText,
}

/// HTML element (in the HTML namespace) whose body is a special text mode.
fn html_text_mode(hash: LocalNameHash, name: &[u8]) -> Option<TextMode> {
    const fn h(name: &'static [u8]) -> u64 {
        LocalNameHash::from_static(name).as_u64()
    }
    const SCRIPT: u64 = h(b"script");
    const TEXTAREA: u64 = h(b"textarea");
    const TITLE: u64 = h(b"title");
    const PLAINTEXT: u64 = h(b"plaintext");
    const STYLE: u64 = h(b"style");
    const XMP: u64 = h(b"xmp");
    const IFRAME: u64 = h(b"iframe");
    const NOEMBED: u64 = h(b"noembed");
    const NOFRAMES: u64 = h(b"noframes");
    const NOSCRIPT: u64 = h(b"noscript");
    let (known, mode): (&[u8], _) = match hash.as_u64() {
        SCRIPT => (b"script", TextMode::ScriptData),
        TEXTAREA => (b"textarea", TextMode::RcData),
        TITLE => (b"title", TextMode::RcData),
        PLAINTEXT => (b"plaintext", TextMode::PlainText),
        STYLE => (b"style", TextMode::RawText),
        XMP => (b"xmp", TextMode::RawText),
        IFRAME => (b"iframe", TextMode::RawText),
        NOEMBED => (b"noembed", TextMode::RawText),
        NOFRAMES => (b"noframes", TextMode::RawText),
        NOSCRIPT => (b"noscript", TextMode::RawText),
        _ => return None,
    };
    // A crafted long name can share the hash.
    (hash.is_exact() || name.eq_ignore_ascii_case(known)).then_some(mode)
}

/// The namespace an element's content is parsed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Namespace {
    Html,
    Svg,
    MathMl,
}

/// Raised when text-mode context can't be determined in strict mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsingAmbiguityError {
    tag_name: Box<str>,
}

impl fmt::Display for ParsingAmbiguityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ambiguous parsing context at `<{}>`: cannot tell whether following \
             content is raw text or markup (usually caused by non-conforming HTML)",
            self.tag_name
        )
    }
}

impl Error for ParsingAmbiguityError {}

/// Tracks the open-element context needed for correct tokenization.
#[derive(Debug)]
pub(crate) struct ContextTracker {
    ns_stack: Vec<Namespace>,
    current_ns: Namespace,
    ambiguity: AmbiguityGuard,
    strict: bool,
}

impl ContextTracker {
    pub(crate) fn new(strict: bool) -> Self {
        Self {
            ns_stack: vec![Namespace::Html],
            current_ns: Namespace::Html,
            ambiguity: AmbiguityGuard::default(),
            strict,
        }
    }

    /// Whether `<![CDATA[ … ]]>` is currently real character data.
    pub(crate) fn cdata_allowed(&self) -> bool {
        self.current_ns != Namespace::Html
    }

    /// Non-mutating peek at the text mode a start tag enters in the current
    /// context (the streaming tokenizer uses it to decide whether a raw-text
    /// body is fully buffered before committing to it).
    pub(crate) fn peek_text_mode(&self, hash: LocalNameHash, name: &[u8]) -> Option<TextMode> {
        if self.current_ns != Namespace::Html || SVG.is(hash, name) || MATH.is(hash, name) {
            None
        } else {
            html_text_mode(hash, name)
        }
    }

    /// Updates context for a start tag.
    pub(crate) fn on_start_tag(&mut self, tag: &StartTag<'_>) -> Result<(), ParsingAmbiguityError> {
        let (hash, name) = (tag.name_hash(), tag.name());
        if self.strict {
            self.ambiguity.track_start_tag(hash, name)?;
        }

        // A self-closing foreign root never opens: browsers pop it at once.
        if SVG.is(hash, name) {
            if !tag.is_self_closing() {
                self.enter_ns(Namespace::Svg);
            }
        } else if MATH.is(hash, name) {
            if !tag.is_self_closing() {
                self.enter_ns(Namespace::MathMl);
            }
        } else if self.current_ns != Namespace::Html {
            self.foreign_start_tag(tag);
        }
        Ok(())
    }

    /// Updates context for an end tag.
    pub(crate) fn on_end_tag(&mut self, tag: &EndTag<'_>) {
        let (hash, name) = (tag.name_hash(), tag.name());
        if self.strict {
            self.ambiguity.track_end_tag(hash, name);
        }
        if self.current_ns == Namespace::Html {
            self.check_integration_point_exit(hash, name);
        } else if self.should_leave_ns(hash, name) {
            self.leave_ns();
        }
    }

    fn enter_ns(&mut self, ns: Namespace) {
        self.ns_stack.push(ns);
        self.current_ns = ns;
    }

    fn leave_ns(&mut self) {
        self.ns_stack.pop();
        self.current_ns = self.ns_stack.last().copied().unwrap_or(Namespace::Html);
    }

    fn should_leave_ns(&self, hash: LocalNameHash, name: &[u8]) -> bool {
        match self.current_ns {
            Namespace::Svg => SVG.is(hash, name) || P.is(hash, name) || BR.is(hash, name),
            Namespace::MathMl => MATH.is(hash, name) || P.is(hash, name) || BR.is(hash, name),
            Namespace::Html => false,
        }
    }

    fn foreign_start_tag(&mut self, tag: &StartTag<'_>) {
        let (hash, name) = (tag.name_hash(), tag.name());
        if BREAKOUT_TAGS.contains(hash, name) {
            self.leave_ns();
        } else if self.is_integration_point_enter(hash, name) {
            if !tag.is_self_closing() {
                self.enter_ns(Namespace::Html);
            }
        } else if FONT.is(hash, name) {
            if tag.attributes().any(|attr| {
                let name = attr.name();
                [&b"color"[..], b"size", b"face"]
                    .iter()
                    .any(|n| name.eq_ignore_ascii_case(n))
            }) {
                self.leave_ns();
            }
        } else if self.current_ns == Namespace::MathMl
            && !tag.is_self_closing()
            && ANNOTATION_XML.is(hash, name)
            && annotation_xml_is_html(tag)
        {
            self.enter_ns(Namespace::Html);
        }
    }

    fn is_integration_point_enter(&self, hash: LocalNameHash, name: &[u8]) -> bool {
        match self.current_ns {
            Namespace::Svg => SVG_HTML_INTEGRATION_POINTS.contains(hash, name),
            Namespace::MathMl => MATHML_TEXT_INTEGRATION_POINTS.contains(hash, name),
            Namespace::Html => false,
        }
    }

    fn check_integration_point_exit(&mut self, hash: LocalNameHash, name: &[u8]) {
        if self.ns_stack.len() < 2 {
            return;
        }
        let Some(&prev_ns) = self.ns_stack.get(self.ns_stack.len() - 2) else {
            return;
        };
        let exits = match prev_ns {
            Namespace::Svg => SVG_HTML_INTEGRATION_POINTS.contains(hash, name),
            Namespace::MathMl => {
                MATHML_TEXT_INTEGRATION_POINTS.contains(hash, name) || ANNOTATION_XML.is(hash, name)
            }
            Namespace::Html => false,
        };
        if exits {
            self.leave_ns();
        }
    }
}

/// Whether `<annotation-xml>` carries `encoding=text/html` (or the XHTML
/// equivalent), which makes its content an HTML integration point. Browsers
/// read the first `encoding` attribute, character references decoded.
pub(crate) fn annotation_xml_is_html(tag: &StartTag<'_>) -> bool {
    tag.attributes()
        .find(|attr| attr.name().eq_ignore_ascii_case(b"encoding"))
        .is_some_and(|attr| {
            attribute_value_is(attr.value(), &[b"text/html", b"application/xhtml+xml"])
        })
}

/// Guards against tokenizing a text-mode element in an insertion mode where
/// the tree builder would ignore it (`<select>`, in/after `<frameset>`).
#[derive(Debug, Clone, Copy)]
enum AmbiguityState {
    Default,
    InSelect,
    InTemplateInSelect(u32),
    InOrAfterFrameset,
}

#[derive(Debug)]
struct AmbiguityGuard {
    state: AmbiguityState,
}

impl Default for AmbiguityGuard {
    fn default() -> Self {
        Self {
            state: AmbiguityState::Default,
        }
    }
}

impl AmbiguityGuard {
    fn track_start_tag(
        &mut self,
        hash: LocalNameHash,
        name: &[u8],
    ) -> Result<(), ParsingAmbiguityError> {
        match self.state {
            AmbiguityState::Default => {
                if SELECT.is(hash, name) {
                    self.state = AmbiguityState::InSelect;
                } else if FRAMESET.is(hash, name) {
                    self.state = AmbiguityState::InOrAfterFrameset;
                }
            }
            AmbiguityState::InSelect => {
                // These prematurely exit the "in select" insertion mode.
                if SELECT_EXITS.contains(hash, name) {
                    self.state = AmbiguityState::Default;
                } else if TEMPLATE.is(hash, name) {
                    self.state = AmbiguityState::InTemplateInSelect(1);
                } else if !SCRIPT.is(hash, name) {
                    // `<script>` is allowed in "in select".
                    assert_not_ambiguous(hash, name)?;
                }
            }
            AmbiguityState::InTemplateInSelect(depth) => {
                if TEMPLATE.is(hash, name) {
                    self.state = AmbiguityState::InTemplateInSelect(depth + 1);
                } else {
                    assert_not_ambiguous(hash, name)?;
                }
            }
            AmbiguityState::InOrAfterFrameset => {
                // `<noframes>` is allowed in and after `<frameset>`.
                if !NOFRAMES.is(hash, name) {
                    assert_not_ambiguous(hash, name)?;
                }
            }
        }
        Ok(())
    }

    fn track_end_tag(&mut self, hash: LocalNameHash, name: &[u8]) {
        match self.state {
            AmbiguityState::InSelect if SELECT.is(hash, name) => {
                self.state = AmbiguityState::Default;
            }
            AmbiguityState::InTemplateInSelect(depth) if TEMPLATE.is(hash, name) => {
                self.state = if depth == 1 {
                    AmbiguityState::InSelect
                } else {
                    AmbiguityState::InTemplateInSelect(depth - 1)
                };
            }
            _ => {}
        }
    }
}

fn assert_not_ambiguous(hash: LocalNameHash, name: &[u8]) -> Result<(), ParsingAmbiguityError> {
    if html_text_mode(hash, name).is_some() {
        Err(ParsingAmbiguityError {
            tag_name: String::from_utf8_lossy(name)
                .to_ascii_lowercase()
                .into_boxed_str(),
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::protocols::html::tokenizer::{Cdata, Comment, TokenSink, tokenize};

    #[derive(Default)]
    struct ContentKind {
        cdata: usize,
        comments: usize,
    }

    impl TokenSink for ContentKind {
        fn cdata(&mut self, _: &Cdata<'_>) {
            self.cdata += 1;
        }

        fn comment(&mut self, _: &Comment<'_>) {
            self.comments += 1;
        }
    }

    #[test]
    fn annotation_encoding_uses_first_attribute_and_decodes_entities() {
        for (attrs, html) in [
            ("encoding='text&#47;html'", true),
            ("encoding='application/xhtml&#x2b;xml'", true),
            ("encoding='x' encoding='text/html'", false),
            ("encoding='text/html' encoding='x'", true),
        ] {
            let input =
                format!("<math><annotation-xml {attrs}><![CDATA[x]]></annotation-xml></math>");
            let mut sink = ContentKind::default();
            tokenize(input.as_bytes(), &mut sink).unwrap();
            assert_eq!(
                (sink.comments, sink.cdata),
                if html { (1, 0) } else { (0, 1) },
                "{attrs}"
            );
        }
    }
}
