//! The scan-based, resumable HTML tokenizer.
//!
//! The tokenizer is driven by [`Tokenizer::write`] (feed a chunk) and
//! [`Tokenizer::end`] (finalize); [`Tokenizer::tokenize`] is the one-shot
//! convenience (`write` + `end`). Both paths share one resumable core, so a
//! document tokenizes identically no matter how the input is split across
//! `write` calls. A chunk is scanned in place; only an incomplete construct
//! at its end is copied into the tokenizer's buffer, to be completed by the
//! next chunk. The scan of that construct resumes where the last write left
//! it, so scanning work stays linear across small writes.
//!
//! It is built for verbatim re-serialization: the `raw` spans of the emitted
//! tokens partition the input contiguously, so concatenating them reproduces
//! the input exactly (the *identity* property). Bytes the HTML spec would
//! drop (e.g. a stray `<`) are preserved as text — this is the substrate for
//! a byte-faithful rewriter, not a DOM builder.
//!
//! Atomic constructs (tags, comments, CDATA, doctype, and raw-text/script
//! bodies) are retained whole until their terminator arrives; ordinary text
//! streams in chunk-sized pieces. The text mode of a start tag and whether
//! CDATA is real come from the consumer ([`ParseSink`]): a small context
//! tracker (see [`super::context`]) for a plain [`TokenSink`], the rewriter's
//! tree builder for the rewriter.
//!
//! > Memory note: a single unterminated raw-text/script body (or
//! > `<plaintext>`) is buffered until its end tag or end of input; ordinary
//! > text is not.

use memchr::{memchr, memchr2};
use rama_utils::byte_set::set_each;
use rama_utils::macros::generate_set_and_with;

use super::context::{ContextTracker, ParsingAmbiguityError, TextMode};
use super::name::LocalNameHash;
use super::sink::{ParseSink, Standalone, TokenSink};
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
    /// How far the scan of the incomplete construct at the start of `buffer` got.
    resume: Option<Resume>,
    context: ContextTracker,
    strict: bool,
}

impl Default for Tokenizer {
    fn default() -> Self {
        Self {
            buffer: Vec::new(),
            attributes: Vec::new(),
            resume: None,
            context: ContextTracker::new(false),
            strict: false,
        }
    }
}

/// Tokenizes `input` in one pass with the default (non-strict) tokenizer,
/// dispatching events to `sink`.
///
/// # Errors
///
/// The default tokenizer is non-strict, so this does not abort on ambiguous
/// contexts; build a strict [`Tokenizer`] (via
/// [`with_strict`](Tokenizer::with_strict)) to get a [`ParsingAmbiguityError`].
pub fn tokenize<S: TokenSink>(input: &[u8], sink: &mut S) -> Result<(), ParsingAmbiguityError> {
    Tokenizer::new().tokenize(input, sink)
}

impl Tokenizer {
    /// Creates a new tokenizer.
    ///
    /// Non-strict by default (rama's convention): ambiguous text-mode contexts
    /// are tokenized best-effort. Enable [`with_strict`](Self::with_strict) to
    /// abort on such ambiguity instead.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    generate_set_and_with! {
        /// Sets strict mode. When enabled, ambiguous text-mode contexts abort
        /// with a [`ParsingAmbiguityError`] instead of tokenizing best-effort.
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
        let Self {
            buffer,
            attributes,
            resume,
            context,
            ..
        } = self;
        feed(
            buffer,
            attributes,
            resume,
            chunk,
            &mut Standalone { sink, context },
            false,
        )
    }

    /// Finalizes the stream, emitting any remaining (possibly unterminated)
    /// tokens, then resets for reuse.
    ///
    /// # Errors
    ///
    /// See [`tokenize`].
    pub fn end<S: TokenSink>(&mut self, sink: &mut S) -> Result<(), ParsingAmbiguityError> {
        let Self {
            buffer,
            attributes,
            resume,
            context,
            ..
        } = self;
        let result = feed(
            buffer,
            attributes,
            resume,
            &[],
            &mut Standalone { sink, context },
            true,
        );
        self.reset();
        result
    }

    /// [`write`](Self::write) for a consumer that supplies its own
    /// tree-construction context.
    pub(crate) fn write_parse<P: ParseSink>(
        &mut self,
        chunk: &[u8],
        sink: &mut P,
    ) -> Result<(), ParsingAmbiguityError> {
        feed(
            &mut self.buffer,
            &mut self.attributes,
            &mut self.resume,
            chunk,
            sink,
            false,
        )
    }

    /// [`end`](Self::end) for a consumer that supplies its own
    /// tree-construction context.
    pub(crate) fn end_parse<P: ParseSink>(
        &mut self,
        sink: &mut P,
    ) -> Result<(), ParsingAmbiguityError> {
        let result = feed(
            &mut self.buffer,
            &mut self.attributes,
            &mut self.resume,
            &[],
            sink,
            true,
        );
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
        self.resume = None;
        self.context = ContextTracker::new(self.strict);
    }
}

/// Tokenizes `chunk` after the bytes retained from earlier calls. Without
/// retained bytes the chunk is scanned in place, and only its incomplete tail
/// is copied.
fn feed<P: ParseSink>(
    buffer: &mut Vec<u8>,
    attributes: &mut Vec<AttrRange>,
    resume: &mut Option<Resume>,
    chunk: &[u8],
    sink: &mut P,
    is_final: bool,
) -> Result<(), ParsingAmbiguityError> {
    if buffer.is_empty() {
        let result = run(chunk, attributes, resume, sink, is_final);
        sink.flush(chunk);
        let consumed = result.inspect_err(|_| buffer.extend_from_slice(chunk))?;
        buffer.extend_from_slice(chunk.get(consumed..).unwrap_or_default());
    } else {
        buffer.extend_from_slice(chunk);
        let result = run(buffer, attributes, resume, sink, is_final);
        sink.flush(buffer);
        buffer.drain(..result?);
    }
    Ok(())
}

/// The resumable core. Emits all complete tokens of `input`; if `is_final`
/// is false, stops at the first incomplete construct. Returns how many bytes
/// were consumed: the rest is retained for the next call.
///
/// `resume` carries the scan progress of the construct at the start of
/// `input` from the last call, and receives the progress of the incomplete
/// construct when that one starts at offset 0 (a construct further in is
/// moved to offset 0 by the caller and scanned afresh once).
fn run<P: ParseSink>(
    input: &[u8],
    attributes: &mut Vec<AttrRange>,
    resume: &mut Option<Resume>,
    sink: &mut P,
    is_final: bool,
) -> Result<usize, ParsingAmbiguityError> {
    let carried = resume.take();
    let mut pos = 0;
    // Start of the pending (not-yet-emitted) text run.
    let mut text_start = 0;

    loop {
        let Some(rel) = memchr(b'<', input.get(pos..).unwrap_or(&[])) else {
            // No more markup: the rest is text.
            emit_text(input, text_start, input.len(), sink);
            return Ok(input.len());
        };
        let lt = pos + rel;

        match classify(input, lt, sink) {
            Resolve::Text => pos = lt + 1, // a `<` that isn't markup is text
            Resolve::NeedMore => {
                if is_final {
                    pos = lt + 1; // a trailing `<` at EOF is text
                } else {
                    emit_text(input, text_start, lt, sink);
                    return Ok(lt);
                }
            }
            Resolve::Construct(construct) => {
                // The pending text goes first: it can change the context the
                // construct is judged in.
                emit_text(input, text_start, lt, sink);
                let from = if lt == 0 { carried.as_ref() } else { None };
                let Some(next) = process(
                    construct, attributes, from, resume, sink, input, lt, is_final,
                )?
                else {
                    // Positions are absolute, so they hold only at offset 0.
                    if lt != 0 {
                        *resume = None;
                    }
                    return Ok(lt);
                };
                pos = next;
                text_start = next;
            }
        }
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

/// Classifies the `<` at `lt`, signalling [`Resolve::NeedMore`] when the
/// available bytes are only a prefix of a longer opener (`<!--`, `<![CDATA[`,
/// `<!doctype`).
fn classify<P: ParseSink>(input: &[u8], lt: usize, sink: &P) -> Resolve {
    match input.get(lt + 1) {
        None => Resolve::NeedMore,
        Some(b) if b.is_ascii_alphabetic() => Resolve::Construct(Construct::StartTag),
        Some(b'/') => match input.get(lt + 2) {
            None => Resolve::NeedMore,
            Some(c) if c.is_ascii_alphabetic() => Resolve::Construct(Construct::EndTag),
            Some(_) => Resolve::Construct(Construct::BogusComment(2)),
        },
        Some(b'!') => classify_markup_declaration(input, lt, sink),
        Some(b'?') => Resolve::Construct(Construct::BogusComment(1)),
        Some(_) => Resolve::Text,
    }
}

fn classify_markup_declaration<P: ParseSink>(input: &[u8], lt: usize, sink: &P) -> Resolve {
    // Bytes after the `<!`.
    let rest = input.get(lt + MARKUP_DECL_PREFIX.len()..).unwrap_or(&[]);

    if rest.starts_with(b"--") {
        return Resolve::Construct(Construct::Comment);
    }
    if is_strict_prefix(rest, b"--") {
        return Resolve::NeedMore;
    }
    if sink.cdata_allowed() {
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

/// How far the scan of an incomplete construct got, so the next write
/// continues it. Positions are absolute in the input whose offset 0 is the
/// construct's `<`.
#[derive(Debug, Clone, Copy)]
enum Resume {
    /// A start tag that is not closed yet.
    StartTag(TagScan),
    /// A closed start tag whose text-mode body or end tag is not complete yet.
    Body {
        tag: ClosedTag,
        mode: TextMode,
        body: BodyScan,
    },
    /// An end tag that is not closed yet.
    EndTag(TagScan),
    /// A comment, CDATA section, doctype or bogus comment whose terminator
    /// does not start before `from`.
    Delimited { from: usize },
}

/// Emits the construct at `lt`, returning the position just past it, or
/// `None` (only when `is_final` is false) when it is not complete yet: then
/// nothing was emitted, and `left` holds the progress to resume from. A
/// construct an earlier write left incomplete continues from `from`.
#[expect(clippy::too_many_arguments, reason = "the scan state of one construct")]
fn process<P: ParseSink>(
    construct: Construct,
    attributes: &mut Vec<AttrRange>,
    from: Option<&Resume>,
    left: &mut Option<Resume>,
    sink: &mut P,
    input: &[u8],
    lt: usize,
    is_final: bool,
) -> Result<Option<usize>, ParsingAmbiguityError> {
    Ok(match construct {
        Construct::StartTag => {
            return scan_start_tag(attributes, from, left, input, lt, sink, is_final);
        }
        Construct::EndTag => scan_end_tag(from, left, input, lt, sink, is_final),
        Construct::Comment => {
            let data_start = lt + COMMENT_PREFIX.len();
            let end = find_terminator(from, left, input, data_start, COMMENT_SUFFIX);
            delimited(input, lt, data_start, end, COMMENT_SUFFIX.len(), is_final).map(
                |(raw, data)| {
                    sink.comment(&Comment { input, raw, data });
                    raw.end
                },
            )
        }
        Construct::Cdata => {
            let data_start = lt + CDATA_PREFIX.len();
            let end = find_terminator(from, left, input, data_start, CDATA_SUFFIX);
            delimited(input, lt, data_start, end, CDATA_SUFFIX.len(), is_final).map(
                |(raw, data)| {
                    sink.cdata(&Cdata { input, raw, data });
                    raw.end
                },
            )
        }
        Construct::Doctype => {
            let after_keyword = lt + MARKUP_DECL_PREFIX.len() + DOCTYPE_KEYWORD.len();
            let end = find_terminator(from, left, input, after_keyword, b">");
            delimited(input, lt, after_keyword, end, 1, is_final).map(|(raw, content)| {
                let name = parse_doctype_name(input, after_keyword, content.end);
                sink.doctype(&Doctype { input, raw, name });
                raw.end
            })
        }
        Construct::BogusComment(open) => {
            let data_start = lt + open;
            let end = find_terminator(from, left, input, data_start, b">");
            delimited(input, lt, data_start, end, 1, is_final).map(|(raw, data)| {
                sink.comment(&Comment { input, raw, data });
                raw.end
            })
        }
    })
}

/// Finds `needle` from `data_start`, continuing a search an earlier write
/// left in `from`, and leaving the progress in `left` when it is not found.
fn find_terminator(
    from: Option<&Resume>,
    left: &mut Option<Resume>,
    input: &[u8],
    data_start: usize,
    needle: &[u8],
) -> Option<usize> {
    let from = match from {
        Some(&Resume::Delimited { from }) => from.max(data_start),
        _ => data_start,
    };
    let end = find_seq(input, from, needle);
    if end.is_none() {
        *left = Some(Resume::Delimited {
            from: resume_at(input, from, needle.len()),
        });
    }
    end
}

/// Where a search for a match of up to `window` bytes resumes once the input
/// grows: a match can straddle the current end of the input.
fn resume_at(input: &[u8], from: usize, window: usize) -> usize {
    from.max(input.len().saturating_sub(window.saturating_sub(1)))
}

/// The raw and data spans of a construct opened at `lt` whose data starts at
/// `data_start` and is closed by a `close_len`-byte terminator at `end`; an
/// unterminated construct runs to the end of the final input.
fn delimited(
    input: &[u8],
    lt: usize,
    data_start: usize,
    end: Option<usize>,
    close_len: usize,
    is_final: bool,
) -> Option<(Span, Span)> {
    let (data_end, close) = match end {
        Some(at) => (at, at + close_len),
        None if is_final => (input.len(), input.len()),
        None => return None,
    };
    Some((
        Span::new(lt, close),
        Span::new(data_start.min(data_end), data_end),
    ))
}

/// Emits a start tag (and the text-mode body it opens, with its end tag),
/// returning the position past it. In a non-final run nothing is emitted
/// until the tag, and a text-mode body up to its end tag, are complete.
fn scan_start_tag<P: ParseSink>(
    attributes: &mut Vec<AttrRange>,
    from: Option<&Resume>,
    left: &mut Option<Resume>,
    input: &[u8],
    lt: usize,
    sink: &mut P,
    is_final: bool,
) -> Result<Option<usize>, ParsingAmbiguityError> {
    let name_start = lt + 1;
    // A carried body keeps the attributes recorded for its tag in place.
    let (tag, carried_body) = if let Some(&Resume::Body { tag, mode, body }) = from {
        (tag, Some((mode, body)))
    } else {
        let scan = match from {
            Some(&Resume::StartTag(scan)) => scan,
            _ => TagScan::new(name_start),
        };
        match scan_tag(Some(attributes), input, scan) {
            Ok(tag) => (tag, None),
            Err(cut) if is_final => (cut.unclosed(input), None),
            Err(cut) => {
                *left = Some(Resume::StartTag(cut));
                return Ok(None);
            }
        }
    };
    let name_bytes = slice(input, name_start, tag.name_end);
    let name_hash = LocalNameHash::of(name_bytes);
    // Decided before the tag is applied, so an incomplete body leaves no trace.
    let text_mode = sink.text_mode(name_hash, name_bytes);
    let end_tag = match text_mode {
        Some(mode) => {
            let mut body = carried_body
                .filter(|&(carried, _)| carried == mode)
                .map_or(BodyScan::start(tag.close), |(_, body)| body);
            find_body_end(mode, input, name_bytes, &mut body);
            // The end tag, too, must be whole: edits anchored at it land after it.
            let end_tag = match &mut body {
                BodyScan::EndTag { lt, scan } => match scan_tag(None, input, *scan) {
                    Ok(end_tag) => Some((*lt, end_tag)),
                    Err(cut) => {
                        *scan = cut;
                        is_final.then(|| (*lt, cut.unclosed(input)))
                    }
                },
                BodyScan::Search { .. } => None,
            };
            if end_tag.is_none() && !is_final {
                *left = Some(Resume::Body { tag, mode, body });
                return Ok(None);
            }
            end_tag
        }
        None => None,
    };

    sink.start_tag(&StartTag {
        input,
        raw: Span::new(lt, tag.close),
        name: Span::new(name_start, tag.name_end),
        name_hash,
        attributes,
        self_closing: tag.self_closing,
    })?;
    if text_mode.is_none() {
        return Ok(Some(tag.close));
    }
    let Some((end_lt, end_tag)) = end_tag else {
        // An unterminated text-mode body runs to the end of the final input.
        emit_text(input, tag.close, input.len(), sink);
        return Ok(Some(input.len()));
    };
    emit_text(input, tag.close, end_lt, sink);
    emit_end_tag(input, end_lt, end_tag, sink, true);
    Ok(Some(end_tag.close))
}

/// Emits an end tag, returning the position past it (`None` while it is
/// incomplete in a non-final run).
fn scan_end_tag<P: ParseSink>(
    from: Option<&Resume>,
    left: &mut Option<Resume>,
    input: &[u8],
    lt: usize,
    sink: &mut P,
    is_final: bool,
) -> Option<usize> {
    let scan = match from {
        Some(&Resume::EndTag(scan)) => scan,
        _ => TagScan::new(lt + 2),
    };
    // End tags may carry (ignored) attributes; scan past them so that a `>`
    // inside a quoted value does not close the tag prematurely.
    let tag = match scan_tag(None, input, scan) {
        Ok(tag) => tag,
        Err(cut) if is_final => cut.unclosed(input),
        Err(cut) => {
            *left = Some(Resume::EndTag(cut));
            return None;
        }
    };
    emit_end_tag(input, lt, tag, sink, false);
    Some(tag.close)
}

fn emit_end_tag<P: ParseSink>(
    input: &[u8],
    lt: usize,
    tag: ClosedTag,
    sink: &mut P,
    closes_text: bool,
) {
    let name = Span::new(lt + 2, tag.name_end);
    sink.end_tag(
        &EndTag {
            input,
            raw: Span::new(lt, tag.close),
            name,
            name_hash: LocalNameHash::of(slice(input, name.start, name.end)),
        },
        closes_text,
    );
}

/// Progress through a text-mode body and the end tag that closes it.
#[derive(Debug, Clone, Copy)]
enum BodyScan {
    /// No end tag starts before `from`, where script data is in `script`.
    Search { from: usize, script: ScriptState },
    /// The end tag starting at `lt`, scanned up to `scan`.
    EndTag { lt: usize, scan: TagScan },
}

impl BodyScan {
    const fn start(content_start: usize) -> Self {
        Self::Search {
            from: content_start,
            script: ScriptState::Data,
        }
    }
}

/// Looks for the end tag closing a text-mode body, continuing the search in
/// `body`.
fn find_body_end(mode: TextMode, input: &[u8], name: &[u8], body: &mut BodyScan) {
    let BodyScan::Search { from, script } = *body else {
        return;
    };
    let found = match mode {
        TextMode::PlainText => Err(BodyScan::Search { from, script }),
        TextMode::RawText | TextMode::RcData => {
            find_appropriate_end_tag(input, from, name).ok_or(BodyScan::Search {
                // `</`, the name and a terminator.
                from: resume_at(input, from, name.len() + 3),
                script,
            })
        }
        TextMode::ScriptData => find_script_data_end(input, from, script),
    };
    *body = found.map_or_else(
        |progress| progress,
        |lt| BodyScan::EndTag {
            lt,
            scan: TagScan::new(lt + 2),
        },
    );
}

/// Where a tag scan stands.
#[derive(Debug, Clone, Copy)]
enum TagState {
    /// In the tag name.
    Name,
    /// Between attributes.
    Between,
    /// Inside an attribute that ran into the end of the input.
    Attr(AttrState),
}

/// Where an attribute scan stands.
#[derive(Debug, Clone, Copy)]
enum AttrState {
    /// In the name starting at `start`.
    Name { start: usize },
    /// After the name, before a possible `=`.
    AfterName { name: Span },
    /// After `=`, before the value.
    BeforeValue { name: Span },
    /// In a value quoted by `quote`, starting at `start`.
    Quoted { name: Span, quote: u8, start: usize },
    /// In an unquoted value starting at `start`.
    Unquoted { name: Span, start: usize },
}

/// Resumable progress through a tag the input cut off. Every state change
/// is decided by bytes before `pos`, so appending input never changes it and
/// scanning continues at `pos`.
#[derive(Debug, Clone, Copy)]
struct TagScan {
    state: TagState,
    pos: usize,
    /// End of the tag name (final once `state` is past [`TagState::Name`]).
    name_end: usize,
    /// How many recorded attributes are complete (when recording).
    attrs: usize,
}

impl TagScan {
    const fn new(name_start: usize) -> Self {
        Self {
            state: TagState::Name,
            pos: name_start,
            name_end: name_start,
            attrs: 0,
        }
    }

    /// The tag as the final input leaves it: running to its end.
    const fn unclosed(self, input: &[u8]) -> ClosedTag {
        ClosedTag {
            name_end: self.name_end,
            close: input.len(),
            self_closing: false,
        }
    }
}

/// A scanned tag.
#[derive(Debug, Clone, Copy)]
struct ClosedTag {
    name_end: usize,
    /// The position just past the tag.
    close: usize,
    self_closing: bool,
}

/// Scans a tag's name and attribute list from where `scan` stands,
/// optionally recording attributes into `attributes`, up to the tag's close,
/// or to the end of the input (`Err` with the progress to resume from).
///
/// At the end of the input the attribute in progress is recorded as is (an
/// unterminated tag of the final input keeps it), but not counted as
/// complete, so a later write continues it.
///
/// Used for both emitting (with `Some` storage) and the streaming
/// completeness check (`None`), so the two can never disagree on where a tag
/// ends.
#[inline(always)]
fn scan_tag(
    mut attributes: Option<&mut Vec<AttrRange>>,
    input: &[u8],
    scan: TagScan,
) -> Result<ClosedTag, TagScan> {
    if let Some(attributes) = attributes.as_deref_mut() {
        attributes.truncate(scan.attrs);
    }
    let TagScan {
        state,
        pos,
        mut name_end,
        ..
    } = scan;
    let cut = |state, pos, name_end, attributes: Option<&Vec<AttrRange>>| {
        // The last recorded attribute is incomplete when the input cut it off.
        let partial = usize::from(matches!(state, TagState::Attr(_)));
        TagScan {
            state,
            pos,
            name_end,
            attrs: attributes.map_or(0, |attributes| attributes.len().saturating_sub(partial)),
        }
    };
    let from = match state {
        TagState::Name => {
            name_end = scan_tag_name(input, pos);
            if name_end == input.len() {
                return Err(cut(TagState::Name, name_end, name_end, None));
            }
            name_end
        }
        TagState::Between => pos,
        TagState::Attr(state) => {
            match resume_attribute(attributes.as_deref_mut(), input, state, pos) {
                Ok(after) => after,
                Err(state) => {
                    let state = TagState::Attr(state);
                    return Err(cut(state, input.len(), name_end, attributes.as_deref()));
                }
            }
        }
    };
    // Most tags close right after the name: that skips the out-of-line scan.
    let list = if input.get(from) == Some(&b'>') {
        Ok((from + 1, false))
    } else {
        scan_attribute_list(attributes.as_deref_mut(), input, from)
    };
    match list {
        Ok((close, self_closing)) => Ok(ClosedTag {
            name_end,
            close,
            self_closing,
        }),
        Err((state, pos)) => Err(cut(state, pos, name_end, attributes.as_deref())),
    }
}

/// Scans an attribute list from `from` up to and including the tag's
/// close, returning the position past it and whether the tag was
/// self-closing, or, when the input runs out, the state and position to
/// resume from.
///
/// Kept out of line: inlined into each tag scanner, its hot loop runs slower.
#[inline(never)]
fn scan_attribute_list(
    mut attributes: Option<&mut Vec<AttrRange>>,
    input: &[u8],
    from: usize,
) -> Result<(usize, bool), (TagState, usize)> {
    let mut i = from;
    loop {
        i = skip_space(input, i);
        match input.get(i) {
            None => return Err((TagState::Between, i)),
            Some(b'>') => return Ok((i + 1, false)),
            Some(b'/') => match input.get(i + 1) {
                Some(b'>') => return Ok((i + 2, true)),
                Some(_) => i += 1, // stray solidus
                None => return Err((TagState::Between, i)),
            },
            Some(_) => match attribute_name(attributes.as_deref_mut(), input, i, i) {
                Ok(after) => i = after,
                Err(state) => return Err((TagState::Attr(state), input.len())),
            },
        }
    }
}

/// Where an attribute scan records the attribute it ends with: complete, or
/// as far as the input goes.
type Attributes<'a> = Option<&'a mut Vec<AttrRange>>;

/// The position past a scanned attribute, or, when the input ends inside
/// it, the state to resume in.
type AttrScan = Result<usize, AttrState>;

fn record(attributes: Attributes<'_>, attr: AttrRange) {
    if let Some(attributes) = attributes {
        attributes.push(attr);
    }
}

fn resume_attribute(
    attributes: Attributes<'_>,
    input: &[u8],
    state: AttrState,
    i: usize,
) -> AttrScan {
    match state {
        AttrState::Name { start } => attribute_name(attributes, input, start, i),
        AttrState::AfterName { name } => after_attribute_name(attributes, input, name, i),
        AttrState::BeforeValue { name } => before_attribute_value(attributes, input, name, i),
        AttrState::Quoted { name, quote, start } => {
            quoted_value(attributes, input, name, quote, start, i)
        }
        AttrState::Unquoted { name, start } => unquoted_value(attributes, input, name, start, i),
    }
}

#[inline(always)]
fn attribute_name(attributes: Attributes<'_>, input: &[u8], start: usize, i: usize) -> AttrScan {
    let end = scan_attribute_name(input, i);
    let name = Span::new(start, end);
    if end == input.len() {
        record(attributes, valueless(name));
        return Err(AttrState::Name { start });
    }
    after_attribute_name(attributes, input, name, end)
}

#[inline(always)]
fn after_attribute_name(
    attributes: Attributes<'_>,
    input: &[u8],
    name: Span,
    i: usize,
) -> AttrScan {
    let i = skip_space(input, i);
    match input.get(i) {
        Some(b'=') => before_attribute_value(attributes, input, name, i + 1),
        next => {
            record(attributes, valueless(name));
            next.map_or(Err(AttrState::AfterName { name }), |_| Ok(i))
        }
    }
}

#[inline(always)]
fn before_attribute_value(
    attributes: Attributes<'_>,
    input: &[u8],
    name: Span,
    i: usize,
) -> AttrScan {
    let i = skip_space(input, i);
    match input.get(i) {
        None => {
            record(attributes, valued(name, Span::empty(i)));
            Err(AttrState::BeforeValue { name })
        }
        Some(&quote @ (b'"' | b'\'')) => quoted_value(attributes, input, name, quote, i + 1, i + 1),
        Some(_) => unquoted_value(attributes, input, name, i, i),
    }
}

#[inline(always)]
fn quoted_value(
    attributes: Attributes<'_>,
    input: &[u8],
    name: Span,
    quote: u8,
    start: usize,
    i: usize,
) -> AttrScan {
    let Some(rel) = memchr(quote, input.get(i..).unwrap_or(&[])) else {
        record(attributes, valued(name, Span::new(start, input.len())));
        return Err(AttrState::Quoted { name, quote, start });
    };
    record(attributes, valued(name, Span::new(start, i + rel)));
    Ok(i + rel + 1)
}

#[inline(always)]
fn unquoted_value(
    attributes: Attributes<'_>,
    input: &[u8],
    name: Span,
    start: usize,
    i: usize,
) -> AttrScan {
    let end = scan_unquoted_value(input, i);
    record(attributes, valued(name, Span::new(start, end)));
    if end == input.len() {
        Err(AttrState::Unquoted { name, start })
    } else {
        Ok(end)
    }
}

const fn valueless(name: Span) -> AttrRange {
    AttrRange {
        name,
        value: Span::empty(name.end),
        has_value: false,
    }
}

const fn valued(name: Span, value: Span) -> AttrRange {
    AttrRange {
        name,
        value,
        has_value: true,
    }
}

fn emit_text<P: ParseSink>(input: &[u8], start: usize, end: usize, sink: &mut P) {
    if end > start {
        sink.text(&Text {
            input,
            raw: Span::new(start, end),
        });
    }
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

fn scan_unquoted_value(input: &[u8], from: usize) -> usize {
    let mut i = from;
    while let Some(&b) = input.get(i) {
        if is_html_space(b) || b == b'>' {
            break;
        }
        i += 1;
    }
    i
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
const HTML_SPACE: [bool; 256] = set_each([false; 256], b" \t\n\x0c\r");

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScriptState {
    Data,
    Escaped,
    DoubleEscaped,
}

/// The longest match the script-data scan makes (`</script` and a
/// terminator).
const SCRIPT_MATCH_WINDOW: usize = b"</script>".len();

/// Finds the `</script>` that terminates a script element per the HTML
/// script-data escape rules (handling `<!-- … -->` and nested `<script>`),
/// scanning from `from` in `state` and returning the position of its `<`, or
/// the progress to resume from once more input arrives.
fn find_script_data_end(
    input: &[u8],
    from: usize,
    mut state: ScriptState,
) -> Result<usize, BodyScan> {
    let mut i = from;
    // Only a full match changes the state, so a scan from the last change
    // repeats this one; the bytes before the end window are settled.
    let mut changed_at = from;
    let progress = |state, changed_at| BodyScan::Search {
        from: resume_at(input, changed_at, SCRIPT_MATCH_WINDOW),
        script: state,
    };
    loop {
        let before = state;
        match state {
            ScriptState::Data => {
                let Some(rel) = memchr(b'<', input.get(i..).unwrap_or(&[])) else {
                    return Err(progress(state, changed_at));
                };
                let lt = i + rel;
                if is_appropriate_end_tag(input, lt, SCRIPT_NAME) {
                    return Ok(lt);
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
                let Some(rel) = memchr2(b'<', b'-', input.get(i..).unwrap_or(&[])) else {
                    return Err(progress(state, changed_at));
                };
                let at = i + rel;
                if input.get(at) == Some(&b'-') {
                    i = consume_comment_close(input, at, &mut state);
                } else if is_appropriate_end_tag(input, at, SCRIPT_NAME) {
                    // `</script>` ends the script even inside an escaped comment.
                    return Ok(at);
                } else if let Some(after) = double_escape_start(input, at) {
                    state = ScriptState::DoubleEscaped;
                    i = after;
                } else {
                    i = at + 1;
                }
            }
            ScriptState::DoubleEscaped => {
                let Some(rel) = memchr2(b'<', b'-', input.get(i..).unwrap_or(&[])) else {
                    return Err(progress(state, changed_at));
                };
                let at = i + rel;
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
        if state != before {
            changed_at = i;
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
