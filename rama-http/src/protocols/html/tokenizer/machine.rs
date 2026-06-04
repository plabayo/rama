//! The scan-based HTML tokenizer.
//!
//! This first slice processes a complete input buffer in one pass (no
//! cross-chunk streaming yet — that is layered on later). It is built for
//! verbatim re-serialization: the `raw` spans of the emitted tokens
//! partition the input contiguously, so concatenating them reproduces the
//! input exactly (the *identity* property). Bytes that the HTML spec would
//! drop (e.g. a stray `<`) are preserved as text, since this is the
//! substrate for a byte-faithful rewriter, not a DOM builder.
//!
//! Text-mode switching for `<script>` / `<style>` / `<textarea>` / … and
//! foreign content is handled by a later slice; here every element body is
//! scanned as ordinary data, which is still byte-identical (only the token
//! *structure* inside such elements differs).

use memchr::memchr;

use super::name::LocalNameHash;
use super::sink::TokenSink;
use super::token::{AttrRange, Comment, Doctype, EndTag, Span, StartTag, Text};

/// `<!` — the markup-declaration opener.
const MARKUP_DECL_PREFIX: &[u8] = b"<!";
/// `<!--` — the comment opener.
const COMMENT_PREFIX: &[u8] = b"<!--";
/// `-->` — the comment closer.
const COMMENT_SUFFIX: &[u8] = b"-->";
/// The DOCTYPE keyword (matched ASCII case-insensitively).
const DOCTYPE_KEYWORD: &[u8] = b"doctype";

/// Streaming-safe HTML tokenizer (single-pass, in this slice).
///
/// Holds a reusable attribute buffer so tokenizing many documents does not
/// re-allocate per tag.
#[derive(Debug, Default)]
pub struct Tokenizer {
    attributes: Vec<AttrRange>,
}

/// Tokenizes `input` in one pass, dispatching events to `sink`.
pub fn tokenize<S: TokenSink>(input: &[u8], sink: &mut S) {
    Tokenizer::new().tokenize(input, sink);
}

impl Tokenizer {
    /// Creates a new tokenizer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Tokenizes `input`, dispatching token events to `sink`.
    pub fn tokenize<S: TokenSink>(&mut self, input: &[u8], sink: &mut S) {
        let mut pos = 0;
        let mut text_start = 0;

        while let Some(rel) = memchr(b'<', input.get(pos..).unwrap_or(&[])) {
            let lt = pos + rel;
            match classify(input, lt) {
                Construct::Text => {
                    // A `<` that doesn't begin markup stays part of the text run.
                    pos = lt + 1;
                }
                Construct::StartTag => {
                    emit_text(input, text_start, lt, sink);
                    pos = self.scan_start_tag(input, lt, sink);
                    text_start = pos;
                }
                Construct::EndTag => {
                    emit_text(input, text_start, lt, sink);
                    pos = self.scan_end_tag(input, lt, sink);
                    text_start = pos;
                }
                Construct::Comment => {
                    emit_text(input, text_start, lt, sink);
                    pos = scan_comment(input, lt, sink);
                    text_start = pos;
                }
                Construct::Doctype => {
                    emit_text(input, text_start, lt, sink);
                    pos = scan_doctype(input, lt, sink);
                    text_start = pos;
                }
                Construct::BogusComment(open_len) => {
                    emit_text(input, text_start, lt, sink);
                    pos = scan_bogus_comment(input, lt, open_len, sink);
                    text_start = pos;
                }
            }
        }

        emit_text(input, text_start, input.len(), sink);
    }

    fn scan_start_tag<S: TokenSink>(&mut self, input: &[u8], lt: usize, sink: &mut S) -> usize {
        let name_start = lt + 1;
        let name_end = scan_tag_name(input, name_start);
        let name_hash = LocalNameHash::of(slice(input, name_start, name_end));

        self.attributes.clear();
        let (close, self_closing) = self.scan_attributes(input, name_end);

        let tag = StartTag {
            input,
            raw: Span::new(lt, close),
            name: Span::new(name_start, name_end),
            name_hash,
            attributes: &self.attributes,
            self_closing,
        };
        sink.start_tag(&tag);
        close
    }

    fn scan_end_tag<S: TokenSink>(&mut self, input: &[u8], lt: usize, sink: &mut S) -> usize {
        let name_start = lt + 2;
        let name_end = scan_tag_name(input, name_start);
        let name_hash = LocalNameHash::of(slice(input, name_start, name_end));

        // End tags may carry (ignored) attributes; scan past them so that a
        // `>` inside a quoted value does not close the tag prematurely.
        self.attributes.clear();
        let (close, _self_closing) = self.scan_attributes(input, name_end);

        let tag = EndTag {
            input,
            raw: Span::new(lt, close),
            name: Span::new(name_start, name_end),
            name_hash,
        };
        sink.end_tag(&tag);
        close
    }

    /// Parses a tag's attribute list starting at `from` (just after the tag
    /// name), filling `self.attributes`. Returns the position just past the
    /// closing `>` (or end of input) and whether the tag was self-closing.
    fn scan_attributes(&mut self, input: &[u8], from: usize) -> (usize, bool) {
        let mut i = from;
        loop {
            i = skip_space(input, i);
            match input.get(i) {
                None => return (input.len(), false),
                Some(b'>') => return (i + 1, false),
                Some(b'/') => {
                    if input.get(i + 1) == Some(&b'>') {
                        return (i + 2, true);
                    }
                    i += 1; // stray solidus
                }
                Some(_) => i = self.scan_one_attribute(input, i),
            }
        }
    }

    fn scan_one_attribute(&mut self, input: &[u8], i: usize) -> usize {
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

        self.attributes.push(AttrRange {
            name: Span::new(name_start, name_end),
            value,
            has_value,
        });
        after
    }
}

#[derive(Debug, Clone, Copy)]
enum Construct {
    Text,
    StartTag,
    EndTag,
    Comment,
    Doctype,
    /// A bogus comment; the payload is the opener length to skip for `data`.
    BogusComment(usize),
}

/// Decides what construct (if any) the `<` at `lt` begins.
fn classify(input: &[u8], lt: usize) -> Construct {
    match input.get(lt + 1) {
        Some(b) if b.is_ascii_alphabetic() => Construct::StartTag,
        Some(b'/') => match input.get(lt + 2) {
            Some(c) if c.is_ascii_alphabetic() => Construct::EndTag,
            _ => Construct::BogusComment(2),
        },
        Some(b'!') => {
            if input
                .get(lt..)
                .is_some_and(|s| s.starts_with(COMMENT_PREFIX))
            {
                Construct::Comment
            } else if starts_with_ci(
                input.get(lt + MARKUP_DECL_PREFIX.len()..).unwrap_or(&[]),
                DOCTYPE_KEYWORD,
            ) {
                Construct::Doctype
            } else {
                Construct::BogusComment(MARKUP_DECL_PREFIX.len())
            }
        }
        Some(b'?') => Construct::BogusComment(1),
        _ => Construct::Text,
    }
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
        data: Span::new(data_start, data_end),
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
/// hot-path check is a single branchless byte load (mirrors the byte-set
/// tables in `rama-net`).
const HTML_SPACE: [bool; 256] = {
    let mut table = [false; 256];
    table[b' ' as usize] = true;
    table[b'\t' as usize] = true;
    table[b'\n' as usize] = true;
    table[0x0c] = true;
    table[b'\r' as usize] = true;
    table
};

#[inline]
const fn is_html_space(b: u8) -> bool {
    HTML_SPACE[b as usize]
}

fn starts_with_ci(haystack: &[u8], lower_needle: &[u8]) -> bool {
    haystack
        .get(..lower_needle.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(lower_needle))
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

fn slice(input: &[u8], start: usize, end: usize) -> &[u8] {
    input.get(start..end).unwrap_or(&[])
}
