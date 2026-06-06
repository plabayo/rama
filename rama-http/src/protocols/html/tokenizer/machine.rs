//! The scan-based, resumable HTML tokenizer.
//!
//! The tokenizer owns a growable buffer and is driven by [`Tokenizer::write`]
//! (feed a chunk) and [`Tokenizer::end`] (finalize); [`Tokenizer::tokenize`]
//! is the one-shot convenience (`write` + `end`). Both paths share one
//! resumable core, so a document tokenizes identically no matter how the
//! input is split across `write` calls.
//!
//! It is built for verbatim re-serialization: the `raw` spans of the emitted
//! tokens partition the input contiguously, so concatenating them reproduces
//! the input exactly (the *identity* property). Bytes the HTML spec would
//! drop (e.g. a stray `<`) are preserved as text — this is the substrate for
//! a byte-faithful rewriter, not a DOM builder.
//!
//! Atomic constructs (tags, comments, CDATA, doctype, and raw-text/script
//! bodies) are retained whole until their terminator arrives; ordinary text
//! streams in chunk-sized pieces. A small context tracker (see
//! [`super::context`]) supplies the open-element context needed to pick the
//! right text mode and to recognize CDATA in foreign content.
//!
//! > Memory note: a single unterminated raw-text/script body (or
//! > `<plaintext>`) is buffered until its end tag or end of input; ordinary
//! > text is not.

use memchr::{memchr, memchr2};

use super::context::{ContextTracker, ParsingAmbiguityError, TextMode};
use super::name::LocalNameHash;
use super::sink::TokenSink;
use super::token::{AttrRange, Cdata, Comment, Doctype, EndTag, Span, StartTag, Text};

/// `<!` — the markup-declaration opener.
const MARKUP_DECL_PREFIX: &[u8] = b"<!";
/// `<!--` — the comment opener.
const COMMENT_PREFIX: &[u8] = b"<!--";
/// `-->` — the comment closer.
const COMMENT_SUFFIX: &[u8] = b"-->";
/// `<![CDATA[` — the CDATA-section opener.
const CDATA_PREFIX: &[u8] = b"<![CDATA[";
/// `]]>` — the CDATA-section closer.
const CDATA_SUFFIX: &[u8] = b"]]>";
/// The DOCTYPE keyword (matched ASCII case-insensitively).
const DOCTYPE_KEYWORD: &[u8] = b"doctype";
/// The `<script>` tag name (its body is scanned as script-data).
const SCRIPT_NAME: &[u8] = b"script";

/// A byte-faithful, low-allocation, resumable HTML tokenizer.
#[derive(Debug)]
pub struct Tokenizer {
    /// Bytes received but not yet fully tokenized.
    buffer: Vec<u8>,
    /// Reusable attribute-range scratch for the current tag.
    attributes: Vec<AttrRange>,
    context: ContextTracker,
    strict: bool,
}

impl Default for Tokenizer {
    fn default() -> Self {
        Self {
            buffer: Vec::new(),
            attributes: Vec::new(),
            context: ContextTracker::new(true),
            strict: true,
        }
    }
}

/// Tokenizes `input` in one pass, dispatching events to `sink`.
///
/// # Errors
///
/// Returns [`ParsingAmbiguityError`] if a text-mode element appears in a
/// context whose parsing is genuinely ambiguous for a streaming parser
/// (strict mode).
pub fn tokenize<S: TokenSink>(input: &[u8], sink: &mut S) -> Result<(), ParsingAmbiguityError> {
    Tokenizer::new().tokenize(input, sink)
}

impl Tokenizer {
    /// Creates a new tokenizer (strict mode: ambiguous text-mode contexts
    /// abort with an error rather than risk mis-tokenizing).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets strict mode. When disabled, ambiguous contexts are tokenized
        /// best-effort instead of erroring.
        pub fn strict(mut self, strict: bool) -> Self {
            self.strict = strict;
            self.context = ContextTracker::new(strict);
            self
        }
    }

    /// Feeds a chunk of input, emitting every token that is now complete.
    ///
    /// # Errors
    ///
    /// See [`tokenize`].
    pub fn write<S: TokenSink>(
        &mut self,
        chunk: &[u8],
        sink: &mut S,
    ) -> Result<(), ParsingAmbiguityError> {
        self.buffer.extend_from_slice(chunk);
        self.run(false, sink)
    }

    /// Finalizes the stream, emitting any remaining (possibly unterminated)
    /// tokens, then resets for reuse.
    ///
    /// # Errors
    ///
    /// See [`tokenize`].
    pub fn end<S: TokenSink>(&mut self, sink: &mut S) -> Result<(), ParsingAmbiguityError> {
        let result = self.run(true, sink);
        self.reset();
        result
    }

    /// Tokenizes a complete `input` in one shot (`write` then `end`).
    ///
    /// # Errors
    ///
    /// See [`tokenize`].
    pub fn tokenize<S: TokenSink>(
        &mut self,
        input: &[u8],
        sink: &mut S,
    ) -> Result<(), ParsingAmbiguityError> {
        if let Err(err) = self.write(input, sink) {
            self.reset();
            return Err(err);
        }
        self.end(sink)
    }

    fn reset(&mut self) {
        self.buffer.clear();
        self.context = ContextTracker::new(self.strict);
    }

    /// The resumable core. Emits all complete tokens from the buffer; if
    /// `is_final` is false, stops at the first incomplete construct and
    /// retains it (and the trailing text run) for the next call.
    fn run<S: TokenSink>(
        &mut self,
        is_final: bool,
        sink: &mut S,
    ) -> Result<(), ParsingAmbiguityError> {
        // Disjoint field borrows: the buffer is read while the attribute
        // scratch and context are mutated.
        let Self {
            buffer,
            attributes,
            context,
            ..
        } = self;

        let mut pos = 0;
        // Start of the pending (not-yet-emitted) text run.
        let mut text_start = 0;

        loop {
            let Some(rel) = memchr(b'<', buffer.get(pos..).unwrap_or(&[])) else {
                // No more markup: the rest is text.
                emit_text(buffer, text_start, buffer.len(), sink);
                text_start = buffer.len();
                break;
            };
            let lt = pos + rel;

            match classify(buffer, lt, context.cdata_allowed()) {
                Resolve::Text => pos = lt + 1, // a `<` that isn't markup is text
                Resolve::NeedMore => {
                    if is_final {
                        pos = lt + 1; // a trailing `<` at EOF is text
                    } else {
                        emit_text(buffer, text_start, lt, sink);
                        text_start = lt;
                        break;
                    }
                }
                Resolve::Construct(construct) => {
                    if !is_final && !terminator_available(construct, buffer, lt, context) {
                        emit_text(buffer, text_start, lt, sink);
                        text_start = lt;
                        break;
                    }
                    emit_text(buffer, text_start, lt, sink);
                    pos = process(construct, attributes, context, buffer, lt, sink)?;
                    text_start = pos;
                }
            }
        }

        buffer.drain(..text_start);
        Ok(())
    }
}

/// The classification of a `<` and whether more input is needed to make it.
enum Resolve {
    /// The `<` is literal text (e.g. `< ` or `<3`).
    Text,
    /// More input is required to classify (only returned in non-final runs).
    NeedMore,
    Construct(Construct),
}

#[derive(Debug, Clone, Copy)]
enum Construct {
    StartTag,
    EndTag,
    Comment,
    Cdata,
    Doctype,
    /// A bogus comment; the payload is the opener length to skip for `data`.
    BogusComment(usize),
}

/// A pending raw-text scan triggered by a text-mode start tag.
#[derive(Debug, Clone, Copy)]
struct RawScan {
    mode: TextMode,
    /// Span of the element name, used to find the matching end tag.
    name: Span,
}

/// Classifies the `<` at `lt`, signalling [`Resolve::NeedMore`] when the
/// available bytes are only a prefix of a longer opener (`<!--`, `<![CDATA[`,
/// `<!doctype`).
fn classify(input: &[u8], lt: usize, cdata_allowed: bool) -> Resolve {
    match input.get(lt + 1) {
        None => Resolve::NeedMore,
        Some(b) if b.is_ascii_alphabetic() => Resolve::Construct(Construct::StartTag),
        Some(b'/') => match input.get(lt + 2) {
            None => Resolve::NeedMore,
            Some(c) if c.is_ascii_alphabetic() => Resolve::Construct(Construct::EndTag),
            Some(_) => Resolve::Construct(Construct::BogusComment(2)),
        },
        Some(b'!') => classify_markup_declaration(input, lt, cdata_allowed),
        Some(b'?') => Resolve::Construct(Construct::BogusComment(1)),
        Some(_) => Resolve::Text,
    }
}

fn classify_markup_declaration(input: &[u8], lt: usize, cdata_allowed: bool) -> Resolve {
    // Bytes after the `<!`.
    let rest = input.get(lt + MARKUP_DECL_PREFIX.len()..).unwrap_or(&[]);

    if rest.starts_with(b"--") {
        return Resolve::Construct(Construct::Comment);
    }
    if is_strict_prefix(rest, b"--") {
        return Resolve::NeedMore;
    }
    if cdata_allowed {
        let cdata_inner = &CDATA_PREFIX[MARKUP_DECL_PREFIX.len()..]; // `[CDATA[`
        if rest.starts_with(cdata_inner) {
            return Resolve::Construct(Construct::Cdata);
        }
        if is_strict_prefix(rest, cdata_inner) {
            return Resolve::NeedMore;
        }
    }
    if starts_with_ci(rest, DOCTYPE_KEYWORD) {
        return Resolve::Construct(Construct::Doctype);
    }
    if is_strict_prefix_ci(rest, DOCTYPE_KEYWORD) {
        return Resolve::NeedMore;
    }
    Resolve::Construct(Construct::BogusComment(MARKUP_DECL_PREFIX.len()))
}

/// Whether the construct at `lt` has its terminator within the buffer (so it
/// can be emitted without more input). For a text-mode start tag this also
/// requires the body's end tag to be present.
fn terminator_available(
    construct: Construct,
    input: &[u8],
    lt: usize,
    context: &ContextTracker,
) -> bool {
    match construct {
        Construct::StartTag => {
            let name_end = scan_tag_name(input, lt + 1);
            let (close, _self_closing, complete) = scan_attributes(None, input, name_end);
            if !complete {
                return false;
            }
            let name = slice(input, lt + 1, name_end);
            match context.peek_text_mode(LocalNameHash::of(name)) {
                None => true,
                Some(mode) => find_body_end(mode, input, close, name).is_some(),
            }
        }
        Construct::EndTag => scan_attributes(None, input, scan_tag_name(input, lt + 2)).2,
        Construct::Comment => find_seq(input, lt + COMMENT_PREFIX.len(), COMMENT_SUFFIX).is_some(),
        Construct::Cdata => find_seq(input, lt + CDATA_PREFIX.len(), CDATA_SUFFIX).is_some(),
        Construct::Doctype => {
            let from = lt + MARKUP_DECL_PREFIX.len() + DOCTYPE_KEYWORD.len();
            memchr(b'>', input.get(from..).unwrap_or(&[])).is_some()
        }
        Construct::BogusComment(open) => {
            memchr(b'>', input.get(lt + open..).unwrap_or(&[])).is_some()
        }
    }
}

/// Emits the construct at `lt`, returning the position just past it.
fn process<S: TokenSink>(
    construct: Construct,
    attributes: &mut Vec<AttrRange>,
    context: &mut ContextTracker,
    input: &[u8],
    lt: usize,
    sink: &mut S,
) -> Result<usize, ParsingAmbiguityError> {
    Ok(match construct {
        Construct::StartTag => {
            let (close, name_hash, name, self_closing) =
                scan_start_tag(attributes, input, lt, sink);
            let text_mode = context.on_start_tag(
                name_hash,
                slice(input, name.start, name.end),
                attributes,
                input,
                self_closing,
            )?;
            if let Some(mode) = text_mode {
                scan_raw_text(attributes, input, close, RawScan { mode, name }, sink)
            } else {
                close
            }
        }
        Construct::EndTag => {
            let (close, name_hash, name) = scan_end_tag(attributes, input, lt, sink);
            context.on_end_tag(name_hash, slice(input, name.start, name.end));
            close
        }
        Construct::Comment => scan_comment(input, lt, sink),
        Construct::Cdata => scan_cdata(input, lt, sink),
        Construct::Doctype => scan_doctype(input, lt, sink),
        Construct::BogusComment(open) => scan_bogus_comment(input, lt, open, sink),
    })
}

fn scan_start_tag<S: TokenSink>(
    attributes: &mut Vec<AttrRange>,
    input: &[u8],
    lt: usize,
    sink: &mut S,
) -> (usize, LocalNameHash, Span, bool) {
    let name_start = lt + 1;
    let name_end = scan_tag_name(input, name_start);
    let name = Span::new(name_start, name_end);
    let name_hash = LocalNameHash::of(slice(input, name_start, name_end));

    attributes.clear();
    let (close, self_closing, _complete) = scan_attributes(Some(attributes), input, name_end);

    let tag = StartTag {
        input,
        raw: Span::new(lt, close),
        name,
        name_hash,
        attributes,
        self_closing,
    };
    sink.start_tag(&tag);
    (close, name_hash, name, self_closing)
}

fn scan_end_tag<S: TokenSink>(
    attributes: &mut Vec<AttrRange>,
    input: &[u8],
    lt: usize,
    sink: &mut S,
) -> (usize, LocalNameHash, Span) {
    let name_start = lt + 2;
    let name_end = scan_tag_name(input, name_start);
    let name = Span::new(name_start, name_end);
    let name_hash = LocalNameHash::of(slice(input, name_start, name_end));

    // End tags may carry (ignored) attributes; scan past them so that a `>`
    // inside a quoted value does not close the tag prematurely.
    attributes.clear();
    let (close, _self_closing, _complete) = scan_attributes(Some(attributes), input, name_end);

    let tag = EndTag {
        input,
        raw: Span::new(lt, close),
        name,
        name_hash,
    };
    sink.end_tag(&tag);
    (close, name_hash, name)
}

/// Scans an element body in a raw text mode, emitting a [`Text`] token for
/// the content and (if found) the matching end tag.
fn scan_raw_text<S: TokenSink>(
    attributes: &mut Vec<AttrRange>,
    input: &[u8],
    content_start: usize,
    scan: RawScan,
    sink: &mut S,
) -> usize {
    let name = slice(input, scan.name.start, scan.name.end);
    if let Some(lt) = find_body_end(scan.mode, input, content_start, name) {
        emit_text(input, content_start, lt, sink);
        let (close, _name_hash, _name) = scan_end_tag(attributes, input, lt, sink);
        close
    } else {
        emit_text(input, content_start, input.len(), sink);
        input.len()
    }
}

fn find_body_end(mode: TextMode, input: &[u8], content_start: usize, name: &[u8]) -> Option<usize> {
    match mode {
        TextMode::PlainText => None,
        TextMode::RawText | TextMode::RcData => {
            find_appropriate_end_tag(input, content_start, name)
        }
        TextMode::ScriptData => find_script_data_end(input, content_start),
    }
}

/// Parses a tag's attribute list starting at `from` (just after the tag
/// name), optionally recording attributes into `attributes`. Returns the
/// position just past the closing `>` (or end of input), whether the tag was
/// self-closing, and whether it actually closed (vs. running out of input).
///
/// Used for both emitting (with `Some` storage) and the streaming
/// completeness check (`None`), so the two can never disagree on where a tag
/// ends.
fn scan_attributes(
    mut attributes: Option<&mut Vec<AttrRange>>,
    input: &[u8],
    from: usize,
) -> (usize, bool, bool) {
    let mut i = from;
    loop {
        i = skip_space(input, i);
        match input.get(i) {
            None => return (input.len(), false, false),
            Some(b'>') => return (i + 1, false, true),
            Some(b'/') => {
                if input.get(i + 1) == Some(&b'>') {
                    return (i + 2, true, true);
                }
                i += 1; // stray solidus
            }
            Some(_) => i = scan_one_attribute(attributes.as_deref_mut(), input, i),
        }
    }
}

fn scan_one_attribute(attributes: Option<&mut Vec<AttrRange>>, input: &[u8], i: usize) -> usize {
    let name_start = i;
    let name_end = scan_attribute_name(input, i);

    let after_ws = skip_space(input, name_end);
    let (value, has_value, after) = if input.get(after_ws) == Some(&b'=') {
        let value_pos = skip_space(input, after_ws + 1);
        match input.get(value_pos) {
            Some(&q @ (b'"' | b'\'')) => {
                let (value, after) = scan_quoted_value(input, value_pos, q);
                (value, true, after)
            }
            None => (Span::empty(value_pos), true, value_pos),
            Some(_) => {
                let (value, after) = scan_unquoted_value(input, value_pos);
                (value, true, after)
            }
        }
    } else {
        (Span::empty(name_end), false, name_end)
    };

    if let Some(attributes) = attributes {
        attributes.push(AttrRange {
            name: Span::new(name_start, name_end),
            value,
            has_value,
        });
    }
    after
}

fn emit_text<S: TokenSink>(input: &[u8], start: usize, end: usize, sink: &mut S) {
    if end > start {
        sink.text(&Text {
            input,
            raw: Span::new(start, end),
        });
    }
}

fn scan_comment<S: TokenSink>(input: &[u8], lt: usize, sink: &mut S) -> usize {
    let data_start = lt + COMMENT_PREFIX.len();
    let (data_end, close) = match find_seq(input, data_start, COMMENT_SUFFIX) {
        Some(at) => (at, at + COMMENT_SUFFIX.len()),
        None => (input.len(), input.len()),
    };
    sink.comment(&Comment {
        input,
        raw: Span::new(lt, close),
        data: Span::new(data_start.min(data_end), data_end),
    });
    close
}

fn scan_cdata<S: TokenSink>(input: &[u8], lt: usize, sink: &mut S) -> usize {
    let data_start = lt + CDATA_PREFIX.len();
    let (data_end, close) = match find_seq(input, data_start, CDATA_SUFFIX) {
        Some(at) => (at, at + CDATA_SUFFIX.len()),
        None => (input.len(), input.len()),
    };
    sink.cdata(&Cdata {
        input,
        raw: Span::new(lt, close),
        data: Span::new(data_start.min(data_end), data_end),
    });
    close
}

fn scan_doctype<S: TokenSink>(input: &[u8], lt: usize, sink: &mut S) -> usize {
    let after_keyword = lt + MARKUP_DECL_PREFIX.len() + DOCTYPE_KEYWORD.len();
    let (content_end, close) = match memchr(b'>', input.get(after_keyword..).unwrap_or(&[])) {
        Some(rel) => (after_keyword + rel, after_keyword + rel + 1),
        None => (input.len(), input.len()),
    };
    let name = parse_doctype_name(input, after_keyword, content_end);
    sink.doctype(&Doctype {
        input,
        raw: Span::new(lt, close),
        name,
    });
    close
}

fn parse_doctype_name(input: &[u8], from: usize, end: usize) -> Option<Span> {
    let start = skip_space(input, from).min(end);
    let mut i = start;
    while i < end {
        match input.get(i) {
            Some(b) if is_html_space(*b) => break,
            Some(_) => i += 1,
            None => break,
        }
    }
    (i > start).then(|| Span::new(start, i))
}

fn scan_bogus_comment<S: TokenSink>(
    input: &[u8],
    lt: usize,
    open_len: usize,
    sink: &mut S,
) -> usize {
    let data_start = lt + open_len;
    let (data_end, close) = match memchr(b'>', input.get(data_start..).unwrap_or(&[])) {
        Some(rel) => (data_start + rel, data_start + rel + 1),
        None => (input.len(), input.len()),
    };
    sink.comment(&Comment {
        input,
        raw: Span::new(lt, close),
        data: Span::new(data_start.min(data_end), data_end),
    });
    close
}

fn scan_tag_name(input: &[u8], from: usize) -> usize {
    let mut i = from;
    while let Some(&b) = input.get(i) {
        if is_html_space(b) || b == b'/' || b == b'>' {
            break;
        }
        i += 1;
    }
    i
}

fn scan_attribute_name(input: &[u8], from: usize) -> usize {
    let mut i = from;
    while let Some(&b) = input.get(i) {
        if is_html_space(b) || b == b'=' || b == b'/' || b == b'>' {
            break;
        }
        i += 1;
    }
    i
}

fn scan_quoted_value(input: &[u8], quote_pos: usize, quote: u8) -> (Span, usize) {
    let start = quote_pos + 1;
    match memchr(quote, input.get(start..).unwrap_or(&[])) {
        Some(rel) => (Span::new(start, start + rel), start + rel + 1),
        None => (Span::new(start, input.len()), input.len()),
    }
}

fn scan_unquoted_value(input: &[u8], from: usize) -> (Span, usize) {
    let mut i = from;
    while let Some(&b) = input.get(i) {
        if is_html_space(b) || b == b'>' {
            break;
        }
        i += 1;
    }
    (Span::new(from, i), i)
}

fn skip_space(input: &[u8], from: usize) -> usize {
    let mut i = from;
    while let Some(&b) = input.get(i) {
        if is_html_space(b) {
            i += 1;
        } else {
            break;
        }
    }
    i
}

/// HTML whitespace (space, tab, LF, FF, CR) as a `[bool; 256]` table so the
/// hot-path check is a single branchless byte load.
const HTML_SPACE: [bool; 256] = rama_utils::byte_set::set_each([false; 256], b" \t\n\x0c\r");

#[inline]
const fn is_html_space(b: u8) -> bool {
    HTML_SPACE[b as usize]
}

fn starts_with_ci(haystack: &[u8], lower_needle: &[u8]) -> bool {
    haystack
        .get(..lower_needle.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(lower_needle))
}

/// Whether `bytes` is a strict (shorter) prefix of `whole`.
fn is_strict_prefix(bytes: &[u8], whole: &[u8]) -> bool {
    bytes.len() < whole.len() && whole.starts_with(bytes)
}

/// ASCII-case-insensitive [`is_strict_prefix`].
fn is_strict_prefix_ci(bytes: &[u8], whole: &[u8]) -> bool {
    bytes.len() < whole.len()
        && whole
            .get(..bytes.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(bytes))
}

/// Finds `needle` in `input[from..]`, returning the absolute start index.
fn find_seq(input: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    let Some((&first, rest)) = needle.split_first() else {
        return Some(from);
    };
    let mut i = from;
    while let Some(rel) = memchr(first, input.get(i..).unwrap_or(&[])) {
        let at = i + rel;
        if input.get(at + 1..at + 1 + rest.len()) == Some(rest) {
            return Some(at);
        }
        i = at + 1;
    }
    None
}

fn is_tag_terminator(b: u8) -> bool {
    is_html_space(b) || b == b'/' || b == b'>'
}

/// Whether `lt` begins an "appropriate end tag" — `</name` for `name`
/// (ASCII case-insensitive) followed by a tag terminator.
fn is_appropriate_end_tag(input: &[u8], lt: usize, name: &[u8]) -> bool {
    if input.get(lt + 1) != Some(&b'/') {
        return false;
    }
    let start = lt + 2;
    let end = start + name.len();
    if !input
        .get(start..end)
        .is_some_and(|s| s.eq_ignore_ascii_case(name))
    {
        return false;
    }
    matches!(input.get(end), Some(&b) if is_tag_terminator(b))
}

/// Finds the first appropriate end tag for raw-text / RCDATA content,
/// returning the position of its `<`.
fn find_appropriate_end_tag(input: &[u8], from: usize, name: &[u8]) -> Option<usize> {
    let mut i = from;
    while let Some(rel) = memchr(b'<', input.get(i..).unwrap_or(&[])) {
        let lt = i + rel;
        if is_appropriate_end_tag(input, lt, name) {
            return Some(lt);
        }
        i = lt + 1;
    }
    None
}

#[derive(Debug, Clone, Copy)]
enum ScriptState {
    Data,
    Escaped,
    DoubleEscaped,
}

/// Finds the `</script>` that terminates a script element per the HTML
/// script-data escape rules (handling `<!-- … -->` and nested `<script>`),
/// returning the position of its `<`.
fn find_script_data_end(input: &[u8], from: usize) -> Option<usize> {
    let mut state = ScriptState::Data;
    let mut i = from;
    loop {
        match state {
            ScriptState::Data => {
                let lt = i + memchr(b'<', input.get(i..).unwrap_or(&[]))?;
                if is_appropriate_end_tag(input, lt, SCRIPT_NAME) {
                    return Some(lt);
                }
                if input.get(lt + 1) == Some(&b'!')
                    && input.get(lt + 2..).is_some_and(|s| s.starts_with(b"--"))
                {
                    state = ScriptState::Escaped;
                    i = lt + 4;
                } else {
                    i = lt + 1;
                }
            }
            ScriptState::Escaped => {
                let at = i + memchr2(b'<', b'-', input.get(i..).unwrap_or(&[]))?;
                if input.get(at) == Some(&b'-') {
                    i = consume_comment_close(input, at, &mut state);
                } else if is_appropriate_end_tag(input, at, SCRIPT_NAME) {
                    // `</script>` ends the script even inside an escaped comment.
                    return Some(at);
                } else if let Some(after) = double_escape_start(input, at) {
                    state = ScriptState::DoubleEscaped;
                    i = after;
                } else {
                    i = at + 1;
                }
            }
            ScriptState::DoubleEscaped => {
                let at = i + memchr2(b'<', b'-', input.get(i..).unwrap_or(&[]))?;
                if input.get(at) == Some(&b'-') {
                    i = consume_comment_close(input, at, &mut state);
                } else if let Some(after) = double_escape_end(input, at) {
                    state = ScriptState::Escaped;
                    i = after;
                } else {
                    i = at + 1;
                }
            }
        }
    }
}

/// At a `-` in (double-)escaped script data: `-->` returns to script-data,
/// otherwise the dash is consumed. Returns the next scan position.
fn consume_comment_close(input: &[u8], at: usize, state: &mut ScriptState) -> usize {
    if input.get(at..).is_some_and(|s| s.starts_with(b"-->")) {
        *state = ScriptState::Data;
        at + 3
    } else {
        at + 1
    }
}

/// `<script` (no slash) + terminator in escaped script data, entering the
/// double-escaped state. Returns the position after the name.
fn double_escape_start(input: &[u8], lt: usize) -> Option<usize> {
    script_word_boundary(input, lt + 1)
}

/// `</script` + terminator in double-escaped script data, returning to the
/// escaped state. Returns the position after the name.
fn double_escape_end(input: &[u8], lt: usize) -> Option<usize> {
    if input.get(lt + 1) != Some(&b'/') {
        return None;
    }
    script_word_boundary(input, lt + 2)
}

/// If the ASCII-alpha run at `from` equals `script` (case-insensitive) and is
/// followed by a tag terminator, returns the run's end position.
fn script_word_boundary(input: &[u8], from: usize) -> Option<usize> {
    let end = scan_ascii_alpha(input, from);
    if end == from || !slice(input, from, end).eq_ignore_ascii_case(SCRIPT_NAME) {
        return None;
    }
    matches!(input.get(end), Some(&b) if is_tag_terminator(b)).then_some(end)
}

fn scan_ascii_alpha(input: &[u8], from: usize) -> usize {
    let mut i = from;
    while input.get(i).is_some_and(u8::is_ascii_alphabetic) {
        i += 1;
    }
    i
}

fn slice(input: &[u8], start: usize, end: usize) -> &[u8] {
    input.get(start..end).unwrap_or(&[])
}
