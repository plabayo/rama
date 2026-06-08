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

use std::fmt;

use super::name::LocalNameHash;
use super::token::AttrRange;

// --- known tag-name hashes -------------------------------------------------

const SVG: LocalNameHash = LocalNameHash::from_static(b"svg");
const MATH: LocalNameHash = LocalNameHash::from_static(b"math");
const FONT: LocalNameHash = LocalNameHash::from_static(b"font");
const P: LocalNameHash = LocalNameHash::from_static(b"p");
const BR: LocalNameHash = LocalNameHash::from_static(b"br");

const SCRIPT: LocalNameHash = LocalNameHash::from_static(b"script");
const STYLE: LocalNameHash = LocalNameHash::from_static(b"style");
const TEXTAREA: LocalNameHash = LocalNameHash::from_static(b"textarea");
const TITLE: LocalNameHash = LocalNameHash::from_static(b"title");
const PLAINTEXT: LocalNameHash = LocalNameHash::from_static(b"plaintext");
const XMP: LocalNameHash = LocalNameHash::from_static(b"xmp");
const IFRAME: LocalNameHash = LocalNameHash::from_static(b"iframe");
const NOEMBED: LocalNameHash = LocalNameHash::from_static(b"noembed");
const NOFRAMES: LocalNameHash = LocalNameHash::from_static(b"noframes");
const NOSCRIPT: LocalNameHash = LocalNameHash::from_static(b"noscript");

// SVG HTML-integration points.
const DESC: LocalNameHash = LocalNameHash::from_static(b"desc");
const FOREIGN_OBJECT: LocalNameHash = LocalNameHash::from_static(b"foreignobject");

// MathML text-integration points.
const MI: LocalNameHash = LocalNameHash::from_static(b"mi");
const MO: LocalNameHash = LocalNameHash::from_static(b"mo");
const MN: LocalNameHash = LocalNameHash::from_static(b"mn");
const MS: LocalNameHash = LocalNameHash::from_static(b"ms");
const MTEXT: LocalNameHash = LocalNameHash::from_static(b"mtext");

// Ambiguity-guard insertion-mode markers.
const SELECT: LocalNameHash = LocalNameHash::from_static(b"select");
const FRAMESET: LocalNameHash = LocalNameHash::from_static(b"frameset");
const TEMPLATE: LocalNameHash = LocalNameHash::from_static(b"template");
const INPUT: LocalNameHash = LocalNameHash::from_static(b"input");
const KEYGEN: LocalNameHash = LocalNameHash::from_static(b"keygen");

/// Text-parsing-mode switching tags — the ones whose context-sensitivity is
/// dangerous to misjudge.
const TEXT_SWITCH_TAGS: &[LocalNameHash] = &[
    TEXTAREA, TITLE, PLAINTEXT, SCRIPT, STYLE, IFRAME, XMP, NOEMBED, NOFRAMES, NOSCRIPT,
];

/// HTML elements that force an exit from foreign content (per the HTML
/// "any other start tag" foreign-content breakout list).
const BREAKOUT_TAGS: &[LocalNameHash] = &[
    LocalNameHash::from_static(b"b"),
    LocalNameHash::from_static(b"big"),
    LocalNameHash::from_static(b"blockquote"),
    LocalNameHash::from_static(b"body"),
    LocalNameHash::from_static(b"br"),
    LocalNameHash::from_static(b"center"),
    LocalNameHash::from_static(b"code"),
    LocalNameHash::from_static(b"dd"),
    LocalNameHash::from_static(b"div"),
    LocalNameHash::from_static(b"dl"),
    LocalNameHash::from_static(b"dt"),
    LocalNameHash::from_static(b"em"),
    LocalNameHash::from_static(b"embed"),
    LocalNameHash::from_static(b"h1"),
    LocalNameHash::from_static(b"h2"),
    LocalNameHash::from_static(b"h3"),
    LocalNameHash::from_static(b"h4"),
    LocalNameHash::from_static(b"h5"),
    LocalNameHash::from_static(b"h6"),
    LocalNameHash::from_static(b"head"),
    LocalNameHash::from_static(b"hr"),
    LocalNameHash::from_static(b"i"),
    LocalNameHash::from_static(b"img"),
    LocalNameHash::from_static(b"li"),
    LocalNameHash::from_static(b"listing"),
    LocalNameHash::from_static(b"menu"),
    LocalNameHash::from_static(b"meta"),
    LocalNameHash::from_static(b"nobr"),
    LocalNameHash::from_static(b"ol"),
    LocalNameHash::from_static(b"p"),
    LocalNameHash::from_static(b"pre"),
    LocalNameHash::from_static(b"ruby"),
    LocalNameHash::from_static(b"s"),
    LocalNameHash::from_static(b"small"),
    LocalNameHash::from_static(b"span"),
    LocalNameHash::from_static(b"strong"),
    LocalNameHash::from_static(b"strike"),
    LocalNameHash::from_static(b"sub"),
    LocalNameHash::from_static(b"sup"),
    LocalNameHash::from_static(b"table"),
    LocalNameHash::from_static(b"tt"),
    LocalNameHash::from_static(b"u"),
    LocalNameHash::from_static(b"ul"),
    LocalNameHash::from_static(b"var"),
];

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
fn html_text_mode(name: LocalNameHash) -> Option<TextMode> {
    if name == SCRIPT {
        Some(TextMode::ScriptData)
    } else if name == TEXTAREA || name == TITLE {
        Some(TextMode::RcData)
    } else if name == PLAINTEXT {
        Some(TextMode::PlainText)
    } else if name == STYLE
        || name == XMP
        || name == IFRAME
        || name == NOEMBED
        || name == NOFRAMES
        || name == NOSCRIPT
    {
        Some(TextMode::RawText)
    } else {
        None
    }
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

impl std::error::Error for ParsingAmbiguityError {}

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

    /// Non-mutating peek at the text mode a start tag would enter in the
    /// current context (used by the streaming tokenizer to decide whether a
    /// raw-text body is fully buffered before committing to it). Mirrors the
    /// text-mode outcome of [`Self::on_start_tag`].
    pub(crate) fn peek_text_mode(&self, name: LocalNameHash) -> Option<TextMode> {
        if self.current_ns != Namespace::Html || name == SVG || name == MATH {
            None
        } else {
            html_text_mode(name)
        }
    }

    /// Updates context for a start tag, returning the body's text mode (only
    /// possible in the HTML namespace).
    pub(crate) fn on_start_tag(
        &mut self,
        name_hash: LocalNameHash,
        name: &[u8],
        attributes: &[AttrRange],
        input: &[u8],
        self_closing: bool,
    ) -> Result<Option<TextMode>, ParsingAmbiguityError> {
        if self.strict {
            self.ambiguity.track_start_tag(name_hash, name)?;
        }

        if name_hash == SVG {
            self.enter_ns(Namespace::Svg);
            Ok(None)
        } else if name_hash == MATH {
            self.enter_ns(Namespace::MathMl);
            Ok(None)
        } else if self.current_ns == Namespace::Html {
            Ok(html_text_mode(name_hash))
        } else {
            self.foreign_start_tag(name_hash, name, attributes, input, self_closing);
            Ok(None)
        }
    }

    /// Updates context for an end tag.
    pub(crate) fn on_end_tag(&mut self, name_hash: LocalNameHash, name: &[u8]) {
        if self.strict {
            self.ambiguity.track_end_tag(name_hash);
        }
        if self.current_ns == Namespace::Html {
            self.check_integration_point_exit(name_hash, name);
        } else if self.should_leave_ns(name_hash) {
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

    fn should_leave_ns(&self, name: LocalNameHash) -> bool {
        match self.current_ns {
            Namespace::Svg => name == SVG || name == P || name == BR,
            Namespace::MathMl => name == MATH || name == P || name == BR,
            Namespace::Html => false,
        }
    }

    fn foreign_start_tag(
        &mut self,
        name_hash: LocalNameHash,
        name: &[u8],
        attributes: &[AttrRange],
        input: &[u8],
        self_closing: bool,
    ) {
        if BREAKOUT_TAGS.contains(&name_hash) {
            self.leave_ns();
        } else if self.is_integration_point_enter(name_hash) {
            if !self_closing {
                self.enter_ns(Namespace::Html);
            }
        } else if name_hash == FONT {
            if attr_named_any(attributes, input, &[b"color", b"size", b"face"]) {
                self.leave_ns();
            }
        } else if self.current_ns == Namespace::MathMl
            && !self_closing
            && name.eq_ignore_ascii_case(b"annotation-xml")
            && annotation_xml_is_html(attributes, input)
        {
            self.enter_ns(Namespace::Html);
        }
    }

    fn is_integration_point_enter(&self, name: LocalNameHash) -> bool {
        match self.current_ns {
            Namespace::Svg => is_svg_html_integration_point(name),
            Namespace::MathMl => is_mathml_text_integration_point(name),
            Namespace::Html => false,
        }
    }

    fn check_integration_point_exit(&mut self, name_hash: LocalNameHash, name: &[u8]) {
        if self.ns_stack.len() < 2 {
            return;
        }
        let Some(&prev_ns) = self.ns_stack.get(self.ns_stack.len() - 2) else {
            return;
        };
        let exits = match prev_ns {
            Namespace::Svg => is_svg_html_integration_point(name_hash),
            Namespace::MathMl => {
                is_mathml_text_integration_point(name_hash)
                    || name.eq_ignore_ascii_case(b"annotation-xml")
            }
            Namespace::Html => false,
        };
        if exits {
            self.leave_ns();
        }
    }
}

fn is_svg_html_integration_point(name: LocalNameHash) -> bool {
    name == FOREIGN_OBJECT || name == DESC || name == TITLE
}

fn is_mathml_text_integration_point(name: LocalNameHash) -> bool {
    name == MI || name == MO || name == MN || name == MS || name == MTEXT
}

/// Whether any attribute's name (ASCII case-insensitive) is in `names`.
fn attr_named_any(attributes: &[AttrRange], input: &[u8], names: &[&[u8]]) -> bool {
    attributes.iter().any(|attr| {
        let attr_name = input.get(attr.name.start..attr.name.end).unwrap_or(&[]);
        names.iter().any(|n| attr_name.eq_ignore_ascii_case(n))
    })
}

/// Whether `<annotation-xml>` carries `encoding=text/html` (or the XHTML
/// equivalent), which makes its content an HTML integration point.
fn annotation_xml_is_html(attributes: &[AttrRange], input: &[u8]) -> bool {
    attributes.iter().any(|attr| {
        let attr_name = input.get(attr.name.start..attr.name.end).unwrap_or(&[]);
        if !attr_name.eq_ignore_ascii_case(b"encoding") {
            return false;
        }
        let value = input.get(attr.value.start..attr.value.end).unwrap_or(&[]);
        value.eq_ignore_ascii_case(b"text/html")
            || value.eq_ignore_ascii_case(b"application/xhtml+xml")
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
        name_hash: LocalNameHash,
        name: &[u8],
    ) -> Result<(), ParsingAmbiguityError> {
        match self.state {
            AmbiguityState::Default => {
                if name_hash == SELECT {
                    self.state = AmbiguityState::InSelect;
                } else if name_hash == FRAMESET {
                    self.state = AmbiguityState::InOrAfterFrameset;
                }
            }
            AmbiguityState::InSelect => {
                // These prematurely exit the "in select" insertion mode.
                if name_hash == SELECT
                    || name_hash == TEXTAREA
                    || name_hash == INPUT
                    || name_hash == KEYGEN
                {
                    self.state = AmbiguityState::Default;
                } else if name_hash == TEMPLATE {
                    self.state = AmbiguityState::InTemplateInSelect(1);
                } else if name_hash != SCRIPT {
                    // `<script>` is allowed in "in select".
                    assert_not_ambiguous(name_hash, name)?;
                }
            }
            AmbiguityState::InTemplateInSelect(depth) => {
                if name_hash == TEMPLATE {
                    self.state = AmbiguityState::InTemplateInSelect(depth + 1);
                } else {
                    assert_not_ambiguous(name_hash, name)?;
                }
            }
            AmbiguityState::InOrAfterFrameset => {
                // `<noframes>` is allowed in and after `<frameset>`.
                if name_hash != NOFRAMES {
                    assert_not_ambiguous(name_hash, name)?;
                }
            }
        }
        Ok(())
    }

    fn track_end_tag(&mut self, name_hash: LocalNameHash) {
        match self.state {
            AmbiguityState::InSelect if name_hash == SELECT => {
                self.state = AmbiguityState::Default;
            }
            AmbiguityState::InTemplateInSelect(depth) if name_hash == TEMPLATE => {
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

fn assert_not_ambiguous(
    name_hash: LocalNameHash,
    name: &[u8],
) -> Result<(), ParsingAmbiguityError> {
    if TEXT_SWITCH_TAGS.contains(&name_hash) {
        Err(ParsingAmbiguityError {
            tag_name: String::from_utf8_lossy(name)
                .to_ascii_lowercase()
                .into_boxed_str(),
        })
    } else {
        Ok(())
    }
}
