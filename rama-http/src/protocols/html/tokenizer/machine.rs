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
//! Atomic constructs (tags, comments, CDATA, doctype) are retained whole
//! until their terminator arrives; ordinary text, and the body of a
//! text-mode element (`<script>`, `<style>`, …), streams in chunk-sized
//! pieces. The text mode of a start tag and whether
//! CDATA is real come from the consumer ([`ParseSink`]): a small context
//! tracker (see [`super::context`]) for a plain [`TokenSink`], the rewriter's
//! tree builder for the rewriter.
//!
//! > Memory note: one construct may use at most
//! > [`max_buffered_bytes`](Tokenizer::with_max_buffered_bytes) of input and
//! > attribute bookkeeping, whether it arrives in one chunk or many.

use memchr::{memchr, memchr2};
use rama_utils::byte_set::set_each;
use rama_utils::macros::generate_set_and_with;
use rama_utils::octets::{kib, mib};

use super::context::{ContextTracker, ParsingAmbiguityError, TextMode};
use super::error::{MemoryLimitExceededError, TokenizerError};
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

/// The elements with a text-mode body (lowercase), as the tree builders know them.
const TEXT_ELEMENTS: [&[u8]; 10] = [
    b"script",
    b"style",
    b"title",
    b"textarea",
    b"xmp",
    b"iframe",
    b"noembed",
    b"noframes",
    b"noscript",
    b"plaintext",
];

/// The default [`Tokenizer::max_buffered_bytes`].
pub const DEFAULT_MAX_BUFFERED_BYTES: usize = mib(4);

/// The highest effective limit: it keeps tag offsets within an [`AttrRange`].
const MAX_LIMIT: usize = (u32::MAX - 1) as usize;

/// The lowest effective limit: room for a partial markup opener, which is not charged.
const MIN_LIMIT: usize = CDATA_PREFIX.len();

/// A buffer whose capacity grew past this is shrunk once its construct is gone.
const SHRINK_ABOVE: usize = kib(64);

/// The capacity a shrunk input buffer keeps.
const SHRUNK_CAPACITY: usize = kib(4);

/// A byte-faithful, low-allocation, resumable HTML tokenizer.
#[derive(Debug)]
pub struct Tokenizer {
    /// Bytes received but not yet fully tokenized.
    buffer: Vec<u8>,
    /// Reusable attribute-range scratch for the current tag.
    attributes: AttrBuf,
    /// How far the scan of the incomplete construct at the start of `buffer` got.
    resume: Option<Resume>,
    context: ContextTracker,
    strict: bool,
    max_buffered_bytes: usize,
}

impl Default for Tokenizer {
    fn default() -> Self {
        Self {
            buffer: Vec::new(),
            attributes: AttrBuf::default(),
            resume: None,
            context: ContextTracker::new(false),
            strict: false,
            max_buffered_bytes: DEFAULT_MAX_BUFFERED_BYTES,
        }
    }
}

/// The attribute ranges of the start tag being scanned.
#[derive(Debug, Default)]
struct AttrBuf {
    ranges: Vec<AttrRange>,
    /// Where the tag's `<` is in the input: the base of the ranges.
    base: usize,
    /// Ranges past this many are not recorded: the tag is over the limit.
    max: usize,
    /// Whether a range of the tag was not recorded.
    overflow: bool,
}

impl AttrBuf {
    /// The ranges the tag needs, recorded or not (then any count over `max`).
    fn needed(&self) -> usize {
        self.ranges.len() + usize::from(self.overflow)
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
/// A construct over [`DEFAULT_MAX_BUFFERED_BYTES`] fails with a
/// [`MemoryLimitExceededError`].
pub fn tokenize<S: TokenSink>(input: &[u8], sink: &mut S) -> Result<(), TokenizerError> {
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

    generate_set_and_with! {
        /// Sets the budget of one construct (a tag with its attributes, a
        /// comment, a doctype, …): its input bytes plus 16 bytes per
        /// attribute. A larger one fails with a [`MemoryLimitExceededError`].
        /// Defaults to [`DEFAULT_MAX_BUFFERED_BYTES`]; budgets below 9 bytes
        /// (the longest markup opener, `<![CDATA[`) act as 9.
        ///
        /// The tokenizer's input and attribute scratch buffers stay below
        /// about twice the budget (they are capped separately); this is not a
        /// ceiling for the whole heap (e.g. nesting context, a rewriter's
        /// output). Once a construct is gone, buffers above 64 KiB shrink
        /// back to 4 KiB, and ending or failing the stream shrinks them to
        /// 4 KiB.
        pub fn max_buffered_bytes(mut self, max_buffered_bytes: usize) -> Self {
            self.max_buffered_bytes = max_buffered_bytes;
            self
        }
    }

    /// The budget of one construct, see
    /// [`with_max_buffered_bytes`](Self::with_max_buffered_bytes).
    #[must_use]
    pub const fn max_buffered_bytes(&self) -> usize {
        self.max_buffered_bytes
    }

    /// Removes and returns the retained input not yet tokenized, and resets
    /// for reuse: after a [`MemoryLimitExceededError`] these are the bytes
    /// from the construct that hit the limit on, up to [`Stopped::chunk_from`].
    pub(crate) fn take_pending(&mut self) -> Vec<u8> {
        let pending = std::mem::take(&mut self.buffer);
        self.reset();
        pending
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
    ) -> Result<(), TokenizerError> {
        let Self {
            buffer,
            attributes,
            resume,
            context,
            max_buffered_bytes,
            ..
        } = self;
        let result = feed(
            buffer,
            attributes,
            resume,
            chunk,
            &mut Standalone { sink, context },
            *max_buffered_bytes,
            false,
        );
        result.map_err(|stopped| {
            self.reset();
            stopped.error
        })
    }

    /// Finalizes the stream, emitting any remaining (possibly unterminated)
    /// tokens, then resets for reuse.
    ///
    /// # Errors
    ///
    /// See [`tokenize`].
    pub fn end<S: TokenSink>(&mut self, sink: &mut S) -> Result<(), TokenizerError> {
        let Self {
            buffer,
            attributes,
            resume,
            context,
            max_buffered_bytes,
            ..
        } = self;
        let result = feed(
            buffer,
            attributes,
            resume,
            &[],
            &mut Standalone { sink, context },
            *max_buffered_bytes,
            true,
        );
        self.reset();
        result.map_err(|stopped| stopped.error)
    }

    /// [`write`](Self::write) for a consumer that supplies its own
    /// tree-construction context. Unlike `write` it keeps the pending input
    /// on error, see [`take_pending`](Self::take_pending).
    pub(crate) fn write_parse<P: ParseSink>(
        &mut self,
        chunk: &[u8],
        sink: &mut P,
    ) -> Result<(), Stopped> {
        feed(
            &mut self.buffer,
            &mut self.attributes,
            &mut self.resume,
            chunk,
            sink,
            self.max_buffered_bytes,
            false,
        )
    }

    /// [`end`](Self::end) for a consumer that supplies its own
    /// tree-construction context. Like [`write_parse`](Self::write_parse) it
    /// keeps the pending input on error.
    pub(crate) fn end_parse<P: ParseSink>(&mut self, sink: &mut P) -> Result<(), Stopped> {
        let result = feed(
            &mut self.buffer,
            &mut self.attributes,
            &mut self.resume,
            &[],
            sink,
            self.max_buffered_bytes,
            true,
        );
        if result.is_ok() {
            self.reset();
        }
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
    ) -> Result<(), TokenizerError> {
        if let Err(err) = self.write(input, sink) {
            self.reset();
            return Err(err);
        }
        self.end(sink)
    }

    fn reset(&mut self) {
        self.buffer.clear();
        self.buffer.shrink_to(SHRUNK_CAPACITY);
        self.attributes.ranges.clear();
        self.attributes
            .ranges
            .shrink_to(SHRUNK_CAPACITY / size_of::<AttrRange>());
        self.resume = None;
        self.context = ContextTracker::new(self.strict);
    }
}

#[cfg(test)]
impl Tokenizer {
    /// The capacity, in bytes, of the input buffer and attribute ranges.
    pub(super) fn held_capacity(&self) -> usize {
        self.buffer.capacity() + self.attributes.ranges.capacity() * size_of::<AttrRange>()
    }
}

/// Tokenizes `chunk` after the bytes retained from earlier calls. Without
/// retained bytes the chunk is scanned in place, and only its incomplete tail
/// is copied. A retained construct completes within `limit` bytes or fails,
/// so at most that much of the chunk is copied behind it at a time.
fn feed<P: ParseSink>(
    buffer: &mut Vec<u8>,
    attributes: &mut AttrBuf,
    resume: &mut Option<Resume>,
    chunk: &[u8],
    sink: &mut P,
    limit: usize,
    is_final: bool,
) -> Result<(), Stopped> {
    let limit = limit.clamp(MIN_LIMIT, MAX_LIMIT);
    attributes.max = limit / size_of::<AttrRange>();
    let mut rest = chunk;
    let result = loop {
        let offset = chunk.len() - rest.len();
        if buffer.is_empty() {
            let result = run(rest, attributes, resume, sink, limit, is_final);
            sink.flush(rest);
            match result {
                Ok(consumed) => {
                    let tail = rest.get(consumed..).unwrap_or_default();
                    reserve(buffer, tail.len(), limit + 1);
                    buffer.extend_from_slice(tail);
                    break Ok(());
                }
                Err(halt) => break Err(stopped(halt, limit, |at| offset + at)),
            }
        }
        let take = rest
            .len()
            .min((limit + 1).saturating_sub(buffer.len()).max(1));
        let (head, next) = rest.split_at(take);
        rest = next;
        reserve(buffer, head.len(), limit + 1);
        buffer.extend_from_slice(head);
        let result = run(
            buffer,
            attributes,
            resume,
            sink,
            limit,
            is_final && rest.is_empty(),
        );
        sink.flush(buffer);
        match result {
            Ok(consumed) => {
                buffer.drain(..consumed);
            }
            Err(halt) => {
                if let Halt::OverLimit { at } = halt {
                    buffer.drain(..at);
                }
                // The whole head is in the buffer now.
                break Err(stopped(halt, limit, |_| offset + take));
            }
        }
        if rest.is_empty() {
            break Ok(());
        }
    };
    shrink(buffer, &mut attributes.ranges);
    result
}

/// A [`feed`] that stopped: its error, and where the bytes not yet
/// tokenized continue in the chunk, after those left in the buffer.
#[derive(Debug)]
pub(crate) struct Stopped {
    pub(crate) error: TokenizerError,
    pub(crate) chunk_from: usize,
}

/// The [`Stopped`] for `halt`, with `chunk_from` mapping where the run
/// stopped in its input to the chunk.
fn stopped(halt: Halt, limit: usize, chunk_from: impl FnOnce(usize) -> usize) -> Stopped {
    match halt {
        Halt::Ambiguity(err) => Stopped {
            error: err.into(),
            chunk_from: chunk_from(0),
        },
        Halt::OverLimit { at } => Stopped {
            error: MemoryLimitExceededError::new(limit).into(),
            chunk_from: chunk_from(at),
        },
    }
}

/// Reserves room for `additional` more elements, doubling the capacity but
/// not past `cap` (unless more is needed).
fn reserve<T>(vec: &mut Vec<T>, additional: usize, cap: usize) {
    let needed = vec.len() + additional;
    if needed > vec.capacity() {
        let target = needed.max(vec.capacity() * 2).min(cap.max(needed));
        vec.reserve_exact(target - vec.len());
    }
}

/// Releases the capacity a large construct left behind once it is gone.
fn shrink(buffer: &mut Vec<u8>, ranges: &mut Vec<AttrRange>) {
    if buffer.capacity() > SHRINK_ABOVE && buffer.len() <= SHRUNK_CAPACITY {
        buffer.shrink_to(SHRUNK_CAPACITY);
    }
    let shrunk_ranges = SHRUNK_CAPACITY / size_of::<AttrRange>();
    if ranges.capacity() * size_of::<AttrRange>() > SHRINK_ABOVE && ranges.len() <= shrunk_ranges {
        ranges.shrink_to(shrunk_ranges);
    }
}

/// Why a run stopped before the end of its input.
enum Halt {
    Ambiguity(ParsingAmbiguityError),
    /// The construct at `at` does not fit the memory limit.
    OverLimit {
        at: usize,
    },
}

impl From<ParsingAmbiguityError> for Halt {
    fn from(err: ParsingAmbiguityError) -> Self {
        Self::Ambiguity(err)
    }
}

/// Fails the construct spanning `raw` with `attrs` attribute ranges when it
/// does not fit `limit`.
fn check_limit(limit: usize, raw: Span, attrs: usize) -> Result<(), Halt> {
    let size = (raw.end - raw.start).saturating_add(attrs.saturating_mul(size_of::<AttrRange>()));
    if size > limit {
        return Err(Halt::OverLimit { at: raw.start });
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
    attributes: &mut AttrBuf,
    resume: &mut Option<Resume>,
    sink: &mut P,
    limit: usize,
    is_final: bool,
) -> Result<usize, Halt> {
    let carried = resume.take();
    let mut pos = 0;
    // Start of the pending (not-yet-emitted) text run.
    let mut text_start = 0;
    if let Some(Resume::Text { name, mode, body }) = carried {
        match scan_body(name, mode, body, input, 0, resume, sink, limit, is_final)? {
            Step::Next(next) => {
                pos = next;
                text_start = next;
            }
            Step::Suspend(at) => return suspend(limit, input, at),
            Step::Incomplete => return Ok(0),
        }
    }

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
                let next = match process(
                    construct, attributes, from, resume, sink, input, lt, limit, is_final,
                )? {
                    Step::Next(next) => next,
                    Step::Suspend(at) => return suspend(limit, input, at),
                    Step::Incomplete => {
                        let attrs = match resume {
                            Some(Resume::StartTag(_)) => attributes.needed(),
                            _ => 0,
                        };
                        check_limit(limit, Span::new(lt, input.len()), attrs)?;
                        // Positions are absolute, so they hold only at offset 0.
                        if lt != 0 {
                            *resume = None;
                        }
                        return Ok(lt);
                    }
                };
                pos = next;
                text_start = next;
            }
        }
    }
}

/// How far [`process`] got with the construct at a `<`.
enum Step {
    /// It was emitted whole; tokenizing continues at this position.
    Next(usize),
    /// It is not complete: nothing was emitted and it is retained from its `<`.
    Incomplete,
    /// A text-mode body was emitted up to this position; the rest is retained
    /// with the progress in `resume`, relative to it.
    Suspend(usize),
}

/// Ends a run suspended in a text-mode body at `at`, charging what is retained.
fn suspend(limit: usize, input: &[u8], at: usize) -> Result<usize, Halt> {
    check_limit(limit, Span::new(at, input.len()), 0)?;
    Ok(at)
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
    /// Inside the body of the text-mode element `name`, its start tag emitted.
    Text {
        name: &'static [u8],
        mode: TextMode,
        body: BodyScan,
    },
    /// An end tag that is not closed yet.
    EndTag(TagScan),
    /// A comment, CDATA section, doctype or bogus comment whose terminator
    /// does not start before `from`.
    Delimited { from: usize },
}

/// Emits the construct at `lt`, see [`Step`]. When it is not complete yet
/// (only when `is_final` is false), `left` holds the progress to resume
/// from. A construct an earlier write left incomplete continues from `from`.
#[expect(clippy::too_many_arguments, reason = "the scan state of one construct")]
fn process<P: ParseSink>(
    construct: Construct,
    attributes: &mut AttrBuf,
    from: Option<&Resume>,
    left: &mut Option<Resume>,
    sink: &mut P,
    input: &[u8],
    lt: usize,
    limit: usize,
    is_final: bool,
) -> Result<Step, Halt> {
    let spans = match construct {
        Construct::StartTag => {
            return scan_start_tag(attributes, from, left, input, lt, sink, limit, is_final);
        }
        Construct::EndTag => {
            let next = scan_end_tag(from, left, input, lt, sink, limit, is_final)?;
            return Ok(next.map_or(Step::Incomplete, Step::Next));
        }
        Construct::Comment => {
            let data_start = lt + COMMENT_PREFIX.len();
            let end = find_terminator(from, left, input, data_start, COMMENT_SUFFIX);
            delimited(input, lt, data_start, end, COMMENT_SUFFIX.len(), is_final)
        }
        Construct::Cdata => {
            let data_start = lt + CDATA_PREFIX.len();
            let end = find_terminator(from, left, input, data_start, CDATA_SUFFIX);
            delimited(input, lt, data_start, end, CDATA_SUFFIX.len(), is_final)
        }
        Construct::Doctype => {
            let after_keyword = lt + MARKUP_DECL_PREFIX.len() + DOCTYPE_KEYWORD.len();
            let end = find_terminator(from, left, input, after_keyword, b">");
            delimited(input, lt, after_keyword, end, 1, is_final)
        }
        Construct::BogusComment(open) => {
            let data_start = lt + open;
            let end = find_terminator(from, left, input, data_start, b">");
            delimited(input, lt, data_start, end, 1, is_final)
        }
    };
    let Some((raw, data)) = spans else {
        return Ok(Step::Incomplete);
    };
    check_limit(limit, raw, 0)?;
    match construct {
        Construct::Cdata => sink.cdata(&Cdata { input, raw, data }),
        Construct::Doctype => {
            let name = parse_doctype_name(input, data.start, data.end);
            sink.doctype(&Doctype { input, raw, name });
        }
        _ => sink.comment(&Comment { input, raw, data }),
    }
    Ok(Step::Next(raw.end))
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

/// Emits a start tag, then streams the text-mode body it opens (if any) up
/// to and including its end tag, see [`scan_body`].
#[expect(clippy::too_many_arguments, reason = "the scan state of one construct")]
fn scan_start_tag<P: ParseSink>(
    attributes: &mut AttrBuf,
    from: Option<&Resume>,
    left: &mut Option<Resume>,
    input: &[u8],
    lt: usize,
    sink: &mut P,
    limit: usize,
    is_final: bool,
) -> Result<Step, Halt> {
    let name_start = lt + 1;
    attributes.base = lt;
    let scan = if let Some(&Resume::StartTag(scan)) = from {
        scan
    } else {
        attributes.overflow = false;
        TagScan::new(name_start)
    };
    let tag = match scan_tag(Some(attributes), input, scan) {
        Ok(tag) => tag,
        Err(cut) if is_final => cut.unclosed(input),
        Err(cut) => {
            *left = Some(Resume::StartTag(cut));
            return Ok(Step::Incomplete);
        }
    };
    check_limit(limit, Span::new(lt, tag.close), attributes.needed())?;
    let name_bytes = slice(input, name_start, tag.name_end);
    let name_hash = LocalNameHash::of(name_bytes);
    let text_mode = sink.text_mode(name_hash, name_bytes);
    sink.start_tag(&StartTag {
        input,
        raw: Span::new(lt, tag.close),
        name: Span::new(name_start, tag.name_end),
        name_hash,
        attributes: &attributes.ranges,
        self_closing: tag.self_closing,
    })?;
    // Done with: a large tag's ranges are then released by the next shrink.
    attributes.ranges.clear();
    let Some(mode) = text_mode else {
        return Ok(Step::Next(tag.close));
    };
    // Text modes come from `TEXT_ELEMENTS`; any other name runs to the end.
    let (name, mode) = TEXT_ELEMENTS
        .into_iter()
        .find(|name| name.eq_ignore_ascii_case(name_bytes))
        .map_or((&b""[..], TextMode::PlainText), |name| (name, mode));
    let body = BodyScan::start(tag.close);
    scan_body(
        name, mode, body, input, tag.close, left, sink, limit, is_final,
    )
}

/// Streams a text-mode body and its end tag, suspending so only a possible end tag is retained.
#[expect(clippy::too_many_arguments, reason = "the scan state of one body")]
fn scan_body<P: ParseSink>(
    name: &'static [u8],
    mode: TextMode,
    mut body: BodyScan,
    input: &[u8],
    start: usize,
    left: &mut Option<Resume>,
    sink: &mut P,
    limit: usize,
    is_final: bool,
) -> Result<Step, Halt> {
    find_body_end(mode, input, name, &mut body);
    let (lt, end_tag) = match body {
        BodyScan::EndTag { lt, scan } => match scan_tag(None, input, scan) {
            Ok(end_tag) => (lt, end_tag),
            Err(cut) if is_final => (lt, cut.unclosed(input)),
            Err(cut) => {
                emit_text(input, start, lt, sink);
                let body = BodyScan::EndTag {
                    lt: 0,
                    scan: cut.rebase(lt),
                };
                *left = Some(Resume::Text { name, mode, body });
                return Ok(Step::Suspend(lt));
            }
        },
        BodyScan::Search { from, script } => {
            if is_final {
                emit_text(input, start, input.len(), sink);
                return Ok(Step::Next(input.len()));
            }
            // No end tag starts before `from`; `<plaintext>` has none.
            let settled = if mode == TextMode::PlainText {
                input.len()
            } else {
                from
            };
            emit_text(input, start, settled, sink);
            let body = BodyScan::Search { from: 0, script };
            *left = Some(Resume::Text { name, mode, body });
            return Ok(Step::Suspend(settled));
        }
    };
    emit_text(input, start, lt, sink);
    check_limit(limit, Span::new(lt, end_tag.close), 0)?;
    emit_end_tag(input, lt, end_tag, sink, true);
    Ok(Step::Next(end_tag.close))
}

/// Emits an end tag, returning the position past it (`None` while it is
/// incomplete in a non-final run).
fn scan_end_tag<P: ParseSink>(
    from: Option<&Resume>,
    left: &mut Option<Resume>,
    input: &[u8],
    lt: usize,
    sink: &mut P,
    limit: usize,
    is_final: bool,
) -> Result<Option<usize>, Halt> {
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
            return Ok(None);
        }
    };
    check_limit(limit, Span::new(lt, tag.close), 0)?;
    emit_end_tag(input, lt, tag, sink, false);
    Ok(Some(tag.close))
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

impl AttrState {
    /// The state with every position moved `by` bytes back.
    fn rebase(self, by: usize) -> Self {
        let span = |span: Span| Span::new(span.start - by, span.end - by);
        match self {
            Self::Name { start } => Self::Name { start: start - by },
            Self::AfterName { name } => Self::AfterName { name: span(name) },
            Self::BeforeValue { name } => Self::BeforeValue { name: span(name) },
            Self::Quoted { name, quote, start } => Self::Quoted {
                name: span(name),
                quote,
                start: start - by,
            },
            Self::Unquoted { name, start } => Self::Unquoted {
                name: span(name),
                start: start - by,
            },
        }
    }
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

    /// The progress with every position moved `by` bytes back.
    fn rebase(self, by: usize) -> Self {
        let state = match self.state {
            TagState::Attr(attr) => TagState::Attr(attr.rebase(by)),
            state => state,
        };
        Self {
            state,
            pos: self.pos - by,
            name_end: self.name_end - by,
            attrs: self.attrs,
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
    mut attributes: Option<&mut AttrBuf>,
    input: &[u8],
    scan: TagScan,
) -> Result<ClosedTag, TagScan> {
    if let Some(attributes) = attributes.as_deref_mut() {
        attributes.ranges.truncate(scan.attrs);
    }
    let TagScan {
        state,
        pos,
        mut name_end,
        ..
    } = scan;
    let cut = |state, pos, name_end, attributes: Option<&AttrBuf>| {
        // The last recorded attribute is incomplete when the input cut it off.
        let partial = usize::from(matches!(state, TagState::Attr(_)));
        TagScan {
            state,
            pos,
            name_end,
            attrs: attributes.map_or(0, |attributes| {
                attributes.ranges.len().saturating_sub(partial)
            }),
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
    mut attributes: Option<&mut AttrBuf>,
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
type Attributes<'a> = Option<&'a mut AttrBuf>;

/// The position past a scanned attribute, or, when the input ends inside
/// it, the state to resume in.
type AttrScan = Result<usize, AttrState>;

/// Records an attribute, valueless when `value` is `None`. Past `max` ranges
/// (or offsets beyond `u32`) the tag is over the limit: only that is noted.
fn record(attributes: Attributes<'_>, name: Span, value: Option<Span>) {
    let Some(attributes) = attributes else {
        return;
    };
    let range = match value {
        Some(value) => AttrRange::valued(name, value, attributes.base),
        None => AttrRange::valueless(name, attributes.base),
    };
    match range {
        Some(range) if attributes.ranges.len() < attributes.max => {
            reserve(&mut attributes.ranges, 1, attributes.max);
            attributes.ranges.push(range);
        }
        _ => attributes.overflow = true,
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
        record(attributes, name, None);
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
            record(attributes, name, None);
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
            record(attributes, name, Some(Span::empty(i)));
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
        record(attributes, name, Some(Span::new(start, input.len())));
        return Err(AttrState::Quoted { name, quote, start });
    };
    record(attributes, name, Some(Span::new(start, i + rel)));
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
    record(attributes, name, Some(Span::new(start, end)));
    if end == input.len() {
        Err(AttrState::Unquoted { name, start })
    } else {
        Ok(end)
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
