//! Sans-IO framing of a `multipart/form-data` body (RFC 2046 §5.1.1).
//!
//! The parser is fed body chunks and steps through them as a sequence of
//! [`Event`]s. Part data is handed out as slices of the fed chunks; the only
//! bytes ever copied are part headers that straddle a chunk border.
//!
//! Framing is strict where leniency would let two parsers disagree on where a
//! part ends: lines end in CRLF only, a delimiter is followed by nothing but
//! `--` or transport padding and CRLF, and a body that ends before its close
//! delimiter is an error.

use super::Boundary;
use memchr::{memchr, memmem, memrchr};
use rama_core::bytes::{Buf as _, Bytes, BytesMut};
use rama_http_types::{HeaderMap, HeaderName, HeaderValue};
use rama_utils::octets::kib;
use std::{fmt, mem};

/// Upper bound for the header block of a single part.
const MAX_HEAD_SIZE: usize = kib(16);

/// Upper bound for the number of header lines of a single part.
const MAX_HEADERS: usize = 32;

const HEAD_END: &[u8] = b"\r\n\r\n";

/// Why a body is not a well-formed `multipart/form-data` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// The body ended before the close delimiter.
    Incomplete,
    /// A delimiter line carries something else than `--` or padding and CRLF.
    InvalidDelimiter,
    /// A part header line is malformed, folded or not ended by CRLF.
    InvalidHeaders,
    /// The header block of a part exceeds [`Parser::MAX_HEAD_SIZE`] or
    /// [`Parser::MAX_HEADERS`].
    HeadersTooLarge,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Incomplete => "multipart body ended before its close delimiter",
            Self::InvalidDelimiter => "multipart delimiter line is malformed",
            Self::InvalidHeaders => "multipart part headers are malformed",
            Self::HeadersTooLarge => "multipart part headers are too large",
        })
    }
}

impl std::error::Error for ParseError {}

/// A step of progress through a `multipart/form-data` body.
#[derive(Debug)]
pub enum Event {
    /// Every fed byte is consumed: feed another chunk or signal the end of input.
    NeedInput,
    /// A part opened, these are its headers.
    Part(HeaderMap),
    /// Data of the open part, never empty.
    Data(Bytes),
    /// The open part is complete.
    PartEnd,
    /// The close delimiter was read, whatever follows it is never looked at.
    End,
}

#[derive(Debug, Clone, Copy)]
enum State {
    Preamble,
    Tail(Tail),
    Head,
    Data,
    End,
    Failed(ParseError),
}

/// Position within the remainder of a delimiter line.
#[derive(Debug, Clone, Copy)]
enum Tail {
    Start,
    Dash,
    Padding,
    Cr,
}

enum Scan {
    NeedInput,
    Data(Bytes),
    Delimiter,
}

/// Sans-IO parser of a `multipart/form-data` body.
///
/// Drive it with [`step`](Self::step): on [`Event::NeedInput`] hand it the
/// next body chunk with [`feed`](Self::feed), or call
/// [`set_eof`](Self::set_eof) once the body is over. It never reads, waits or
/// buffers part data, so it serves a server reading a form as much as a proxy
/// rewriting one as it streams by (see [`Encoder`](super::Encoder)).
///
/// An error is final: every later step returns it again.
#[derive(Debug)]
pub struct Parser {
    finder: memmem::Finder<'static>,
    /// `CRLF "--" boundary`.
    delimiter: Bytes,
    /// Unconsumed rest of the chunk fed last.
    chunk: Bytes,
    /// Count of leading delimiter bytes matched at the end of what was read so far.
    matched: usize,
    /// Whether the CRLF counted in `matched` is not part of the input.
    implied_crlf: bool,
    /// Header block of the part being opened, used only when it spans chunks.
    head: BytesMut,
    state: State,
    eof: bool,
}

impl Parser {
    /// Upper bound for the header block of a single part, in bytes.
    pub const MAX_HEAD_SIZE: usize = MAX_HEAD_SIZE;

    /// Upper bound for the number of header lines of a single part.
    pub const MAX_HEADERS: usize = MAX_HEADERS;

    /// Create a parser for a body framed by `boundary`.
    #[must_use]
    pub fn new(boundary: &Boundary) -> Self {
        let delimiter = boundary.delimiter();
        Self {
            finder: memmem::Finder::new(&delimiter).into_owned(),
            delimiter,
            chunk: Bytes::new(),
            // the first delimiter needs no CRLF of its own: act as if one was just read
            matched: 2,
            implied_crlf: true,
            head: BytesMut::new(),
            state: State::Preamble,
            eof: false,
        }
    }

    /// Whether more input would be put to use: false once the close delimiter
    /// is read or parsing failed.
    #[must_use]
    pub fn wants_input(&self) -> bool {
        !matches!(self.state, State::End | State::Failed(_))
    }

    /// Hand over the next body chunk, only after [`Event::NeedInput`].
    pub fn feed(&mut self, chunk: Bytes) {
        debug_assert!(self.chunk.is_empty(), "previous chunk not consumed");
        if self.wants_input() {
            self.chunk = chunk;
        }
    }

    /// Signal that the body has no more chunks.
    pub fn set_eof(&mut self) {
        self.eof = true;
    }

    /// Advance to the next event.
    pub fn step(&mut self) -> Result<Event, ParseError> {
        loop {
            match self.state {
                State::Failed(err) => return Err(err),
                State::End => return Ok(Event::End),
                State::Preamble => match self.scan() {
                    Scan::Data(_) => {}
                    Scan::Delimiter => self.state = State::Tail(Tail::Start),
                    Scan::NeedInput => return self.need_input(),
                },
                State::Data => match self.scan() {
                    Scan::Data(data) => return Ok(Event::Data(data)),
                    Scan::Delimiter => {
                        self.state = State::Tail(Tail::Start);
                        return Ok(Event::PartEnd);
                    }
                    Scan::NeedInput => return self.need_input(),
                },
                State::Tail(tail) => match self.tail(tail) {
                    Ok(State::Tail(tail)) => {
                        self.state = State::Tail(tail);
                        return self.need_input();
                    }
                    Ok(state) => self.state = state,
                    Err(err) => return self.fail(err),
                },
                State::Head => match self.read_head() {
                    Ok(Some(headers)) => {
                        // the CRLF of the empty line also opens a delimiter: a part can
                        // go without data (RFC 2046 §5.1.1 `body-part`)
                        self.matched = 2;
                        self.implied_crlf = true;
                        self.state = State::Data;
                        return Ok(Event::Part(headers));
                    }
                    Ok(None) => return self.need_input(),
                    Err(err) => return self.fail(err),
                },
            }
        }
    }

    fn need_input(&mut self) -> Result<Event, ParseError> {
        if self.eof {
            self.fail(ParseError::Incomplete)
        } else {
            Ok(Event::NeedInput)
        }
    }

    fn fail(&mut self, err: ParseError) -> Result<Event, ParseError> {
        self.state = State::Failed(err);
        self.chunk = Bytes::new();
        self.head = BytesMut::new();
        Err(err)
    }

    /// Split the next run of data, or the next delimiter, off the current chunk.
    fn scan(&mut self) -> Scan {
        if self.chunk.is_empty() {
            return Scan::NeedInput;
        }
        let delimiter_len = self.delimiter.len();

        if self.matched > 0 {
            let rest = &self.delimiter[self.matched..];
            let n = rest.len().min(self.chunk.len());
            if self.chunk[..n] == rest[..n] {
                self.chunk.advance(n);
                self.matched += n;
                if self.matched < delimiter_len {
                    return Scan::NeedInput;
                }
                self.matched = 0;
                self.implied_crlf = false;
                return Scan::Delimiter;
            }
            // CR opens the delimiter and occurs nowhere else in it, so none can start
            // within the bytes held back: they are data, and scanning resumes at the chunk
            let from = if self.implied_crlf { 2 } else { 0 };
            let held_back = self.delimiter.slice(from..self.matched);
            self.matched = 0;
            self.implied_crlf = false;
            if !held_back.is_empty() {
                return Scan::Data(held_back);
            }
        }

        match self.finder.find(&self.chunk) {
            Some(0) => {
                self.chunk.advance(delimiter_len);
                Scan::Delimiter
            }
            Some(at) => Scan::Data(self.chunk.split_to(at)),
            None => {
                // only the last CR near the end can open a delimiter that the next chunk completes
                let len = self.chunk.len();
                let from = len.saturating_sub(delimiter_len - 1);
                if let Some(at) = memrchr(b'\r', &self.chunk[from..]).map(|at| from + at)
                    && self.delimiter.starts_with(&self.chunk[at..])
                {
                    self.matched = len - at;
                    let data = self.chunk.split_to(at);
                    self.chunk.clear();
                    if data.is_empty() {
                        return Scan::NeedInput;
                    }
                    return Scan::Data(data);
                }
                Scan::Data(mem::take(&mut self.chunk))
            }
        }
    }

    /// Read what follows the boundary on a delimiter line.
    fn tail(&mut self, mut tail: Tail) -> Result<State, ParseError> {
        let mut used = 0;
        let mut next = None;
        for &byte in &self.chunk {
            used += 1;
            tail = match (tail, byte) {
                (Tail::Start, b'-') => Tail::Dash,
                (Tail::Dash, b'-') => {
                    next = Some(State::End);
                    break;
                }
                (Tail::Start | Tail::Padding, b' ' | b'\t') => Tail::Padding,
                (Tail::Start | Tail::Padding, b'\r') => Tail::Cr,
                (Tail::Cr, b'\n') => {
                    next = Some(State::Head);
                    break;
                }
                _ => return Err(ParseError::InvalidDelimiter),
            };
        }
        match next {
            Some(State::End) => self.chunk = Bytes::new(),
            _ => self.chunk.advance(used),
        }
        Ok(next.unwrap_or(State::Tail(tail)))
    }

    /// Read the header block of a part, up to and including its empty line.
    fn read_head(&mut self) -> Result<Option<HeaderMap>, ParseError> {
        if self.head.is_empty()
            && let Some((head_len, consumed)) = find_head_end(&self.chunk, 0)
        {
            if head_len > MAX_HEAD_SIZE {
                return Err(ParseError::HeadersTooLarge);
            }
            let headers = parse_headers(&self.chunk[..head_len])?;
            self.chunk.advance(consumed);
            return Ok(Some(headers));
        }

        let old_len = self.head.len();
        let take = (MAX_HEAD_SIZE + HEAD_END.len() - old_len).min(self.chunk.len());
        self.head.extend_from_slice(&self.chunk[..take]);
        // the end may straddle the old and new bytes
        let from = old_len.saturating_sub(HEAD_END.len() - 1);
        let Some((head_len, consumed)) = find_head_end(&self.head, from) else {
            self.chunk.advance(take);
            if self.head.len() >= MAX_HEAD_SIZE + HEAD_END.len() {
                return Err(ParseError::HeadersTooLarge);
            }
            return Ok(None);
        };
        if head_len > MAX_HEAD_SIZE {
            return Err(ParseError::HeadersTooLarge);
        }
        let headers = parse_headers(&self.head[..head_len])?;
        // bytes copied past the empty line are part data and stay in the chunk
        self.chunk.advance(take - (self.head.len() - consumed));
        self.head.clear();
        Ok(Some(headers))
    }
}

/// Locate the empty line ending a header block within `buf`, searching from `from`.
///
/// Returns the length of the header lines and of the block including its empty line.
fn find_head_end(buf: &[u8], from: usize) -> Option<(usize, usize)> {
    if buf.starts_with(b"\r\n") {
        return Some((0, 2));
    }
    let at = from + memmem::find(buf.get(from..)?, HEAD_END)?;
    Some((at + 2, at + HEAD_END.len()))
}

/// Parse CRLF-terminated header lines; folded lines and bare LF or CR are rejected.
fn parse_headers(mut block: &[u8]) -> Result<HeaderMap, ParseError> {
    let mut headers = HeaderMap::new();
    let mut count = 0;
    while !block.is_empty() {
        count += 1;
        if count > MAX_HEADERS {
            return Err(ParseError::HeadersTooLarge);
        }
        let line_end = memchr(b'\n', block).ok_or(ParseError::InvalidHeaders)?;
        let line = block[..line_end]
            .strip_suffix(b"\r")
            .ok_or(ParseError::InvalidHeaders)?;
        block = &block[line_end + 1..];

        let colon = memchr(b':', line).ok_or(ParseError::InvalidHeaders)?;
        let name =
            HeaderName::from_bytes(&line[..colon]).map_err(|_e| ParseError::InvalidHeaders)?;
        let value = HeaderValue::from_bytes(line[colon + 1..].trim_ascii())
            .map_err(|_e| ParseError::InvalidHeaders)?;
        headers.append(name, value);
    }
    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct Part {
        headers: Vec<(String, String)>,
        data: Vec<u8>,
    }

    fn part(headers: &[(&str, &str)], data: &[u8]) -> Part {
        Part {
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
            data: data.to_vec(),
        }
    }

    /// Parse `body` fed in the given chunks; an `Err` carries the parts completed before it.
    fn parse_chunks<'a>(
        boundary: &str,
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Vec<Part>, (Vec<Part>, ParseError)> {
        let mut parser = Parser::new(&Boundary::new(boundary).unwrap());
        let mut chunks = chunks.into_iter();
        let mut parts = Vec::new();
        let mut open: Option<Part> = None;
        loop {
            match parser.step() {
                Ok(Event::NeedInput) => match chunks.next() {
                    Some(chunk) => parser.feed(Bytes::copy_from_slice(chunk)),
                    None => parser.set_eof(),
                },
                Ok(Event::Part(headers)) => {
                    assert!(open.is_none(), "part opened within a part");
                    open = Some(Part {
                        headers: headers
                            .iter()
                            .map(|(name, value)| {
                                (
                                    name.as_str().to_owned(),
                                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                                )
                            })
                            .collect(),
                        data: Vec::new(),
                    });
                }
                Ok(Event::Data(data)) => {
                    assert!(!data.is_empty(), "empty data event");
                    open.as_mut()
                        .expect("data outside of a part")
                        .data
                        .extend_from_slice(&data);
                }
                Ok(Event::PartEnd) => parts.push(open.take().expect("end outside of a part")),
                Ok(Event::End) => {
                    assert!(open.is_none(), "stream ended within a part");
                    assert!(matches!(parser.step(), Ok(Event::End)));
                    return Ok(parts);
                }
                Err(err) => {
                    assert_eq!(parser.step().unwrap_err(), err, "errors repeat");
                    return Err((parts, err));
                }
            }
        }
    }

    fn parse(boundary: &str, body: &[u8]) -> Result<Vec<Part>, ParseError> {
        parse_chunks(boundary, [body]).map_err(|(_, err)| err)
    }

    /// Assert that `body` parses the same whole, byte by byte and split in two at every offset.
    fn assert_every_split(boundary: &str, body: &[u8]) -> Result<Vec<Part>, ParseError> {
        let whole = parse_chunks(boundary, [body]);
        let bytewise = parse_chunks(boundary, body.chunks(1));
        assert_eq!(whole, bytewise, "byte by byte: {:?}", body.escape_ascii());
        for at in 1..body.len() {
            let (head, tail) = body.split_at(at);
            let split = parse_chunks(boundary, [head, tail]);
            assert_eq!(whole, split, "split at {at}: {:?}", body.escape_ascii());
        }
        whole.map_err(|(_, err)| err)
    }

    fn form(boundary: &str, parts: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in parts {
            out.extend_from_slice(b"--");
            out.extend_from_slice(boundary.as_bytes());
            out.extend_from_slice(b"\r\nContent-Disposition: form-data; name=\"");
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b"\"\r\n\r\n");
            out.extend_from_slice(data);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"--");
        out.extend_from_slice(boundary.as_bytes());
        out.extend_from_slice(b"--\r\n");
        out
    }

    fn field(name: &str, data: &[u8]) -> Part {
        let disposition = ["form-data; name=\"", name, "\""].concat();
        part(&[("content-disposition", &disposition)], data)
    }

    #[test]
    fn empty_form() {
        for body in ["--b--\r\n", "--b--", "\r\n--b--\r\n", "--b--\r\nepilogue"] {
            assert_eq!(
                assert_every_split("b", body.as_bytes()),
                Ok(vec![]),
                "{body:?}"
            );
        }
    }

    #[test]
    fn fields_at_every_split() {
        let parts: [(&str, &[u8]); 4] = [
            ("empty", b""),
            ("text", b"hello world"),
            ("lines", b"\r\nline one\r\nline two\r\n"),
            ("binary", &[0, 13, 10, 45, 45, 255, 13, 13, 10, 10]),
        ];
        let expected: Vec<_> = parts.iter().map(|(name, data)| field(name, data)).collect();
        for boundary in [
            "b",
            "-",
            "---",
            "-boundary",
            "boundary",
            "----WebKitFormBoundary7MA4YWxkTrZu0gW",
        ] {
            let body = form(boundary, &parts);
            assert_eq!(
                assert_every_split(boundary, &body).as_ref(),
                Ok(&expected),
                "{boundary:?}"
            );
        }
    }

    #[test]
    fn data_that_resembles_the_delimiter() {
        for data in [
            &b"-"[..],
            b"--",
            b"--B",
            b"x--b",
            b"\r",
            b"\r\n",
            b"\r\n-",
            b"\r\n--",
            b"\r\r\n--",
            b"\r\n--\r\n-\r\n--",
            b"\r\n--\r\n--B",
            b"x\r\n-\r\n--a\r\r\r\n\r\n--",
            b"\n--b\r\n",
            b"\r--b\r\n",
            b"x--b\r\nContent-Disposition: form-data; name=\"inner\"\r\n\r\n",
        ] {
            let body = form("b", &[("a", data), ("z", b"after")]);
            assert_eq!(
                assert_every_split("b", &body),
                Ok(vec![field("a", data), field("z", b"after")]),
                "{:?}",
                data.escape_ascii()
            );
        }
    }

    /// The CRLF of the empty line ending the headers opens a delimiter too, as it does for
    /// parsers that scan the body for `CRLF "--" boundary`.
    #[test]
    fn delimiter_right_after_the_head_ends_the_part() {
        assert_eq!(
            assert_every_split("b", b"--b\r\nA: 1\r\n\r\n--b\r\n\r\n--b--"),
            Ok(vec![part(&[("A", "1")], b""), part(&[], b"")])
        );
        assert_eq!(
            assert_every_split("b", b"--b\r\nA: 1\r\n\r\n--b--\r\n--b\r\n\r\nx\r\n--b--"),
            Ok(vec![part(&[("A", "1")], b"")])
        );
        assert_eq!(
            assert_every_split("b", b"--b\r\nA: 1\r\n\r\n--bX\r\n--b--"),
            Err(ParseError::InvalidDelimiter)
        );
        assert_eq!(
            assert_every_split("b", b"--b\r\n\r\n--b\r\n--b\r\n\r\n\r\n--b--"),
            Err(ParseError::InvalidHeaders)
        );
    }

    #[test]
    fn longer_boundary_sharing_a_prefix_is_rejected() {
        // a line opening with the delimiter is a delimiter: what follows decides its validity,
        // never whether the part goes on
        for tail in ["X\r\n", "-\r\n", "\r", "\n", "-", " x\r\n", "\rx"] {
            let body = [
                "--b\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--b",
                tail,
                "y\r\n--b--\r\n",
            ]
            .concat();
            assert_eq!(
                assert_every_split("b", body.as_bytes()),
                Err(ParseError::InvalidDelimiter),
                "{tail:?}"
            );
        }
    }

    #[test]
    fn preamble_and_epilogue_are_ignored() {
        let expected = Ok(vec![field("a", b"v")]);
        let body = form("b", &[("a", b"v")]);
        for preamble in [
            "\r\n",
            "preamble\r\n",
            "--\r\n",
            "x--b",
            "x--bx\r\n--B\r\n",
            "junk--b\r\n",
            "\n--b\n",
            "\r\n\r\n\r\n",
        ] {
            let mut with = preamble.as_bytes().to_vec();
            if !preamble.ends_with("\r\n") {
                with.extend_from_slice(b"\r\n");
            }
            with.extend_from_slice(&body);
            with.extend_from_slice(b"epilogue\r\n--b\r\n--b--\r\n");
            assert_eq!(assert_every_split("b", &with), expected, "{preamble:?}");
        }
    }

    #[test]
    fn preamble_without_delimiter_is_incomplete() {
        for body in [
            "",
            "junk",
            "junk--b--\r\n",
            "\n--b--\r\n",
            "--B--\r\n",
            "-b--",
        ] {
            assert_eq!(
                assert_every_split("b", body.as_bytes()),
                Err(ParseError::Incomplete),
                "{body:?}"
            );
        }
    }

    #[test]
    fn transport_padding() {
        let body = b"--b \t \r\nA: 1\r\n\r\nv\r\n--b\t\r\n\r\nw\r\n--b--";
        assert_eq!(
            assert_every_split("b", body),
            Ok(vec![part(&[("A", "1")], b"v"), part(&[], b"w")])
        );
        // padding belongs before the CRLF of an open delimiter only
        for body in ["--b --\r\n", "--b\t--", "--b- -\r\n", "--b \n"] {
            assert_eq!(
                assert_every_split("b", body.as_bytes()),
                Err(ParseError::InvalidDelimiter),
                "{body:?}"
            );
        }
    }

    #[test]
    fn bare_line_endings_are_rejected() {
        assert_eq!(
            assert_every_split("b", b"--b\nA: 1\n\nv\n--b--\n"),
            Err(ParseError::InvalidDelimiter)
        );
        assert_eq!(
            assert_every_split("b", b"--b\r\nA: 1\nB: 2\r\n\r\nv\r\n--b--\r\n"),
            Err(ParseError::InvalidHeaders)
        );
        assert_eq!(
            assert_every_split("b", b"--b\r\nA: 1\rB: 2\r\n\r\nv\r\n--b--\r\n"),
            Err(ParseError::InvalidHeaders)
        );
        // a header block ended by bare LFs never ends
        assert_eq!(
            assert_every_split("b", b"--b\r\nA: 1\n\nv\r\n--b--\r\n"),
            Err(ParseError::Incomplete)
        );
    }

    #[test]
    fn truncated_bodies_are_incomplete() {
        let body = form("b", &[("a", b"value"), ("z", b"")]);
        // every proper prefix, up to the second dash of the close delimiter
        for len in 0..body.len() - 2 {
            let result = parse_chunks("b", [&body[..len]]);
            assert_eq!(
                result.as_ref().map_err(|(_, err)| *err),
                Err(ParseError::Incomplete),
                "{:?}",
                body[..len].escape_ascii()
            );
        }
        assert_eq!(
            parse("b", &body[..body.len() - 2]),
            Ok(vec![field("a", b"value"), field("z", b"")])
        );
    }

    #[test]
    fn parts_before_an_error_are_complete() {
        let body = b"--b\r\n\r\nfirst\r\n--b\r\n\r\nsecond";
        let (parts, err) = parse_chunks("b", [&body[..]]).unwrap_err();
        assert_eq!(parts, vec![part(&[], b"first")]);
        assert_eq!(err, ParseError::Incomplete);
    }

    #[test]
    fn part_headers() {
        let body = b"--b\r\n\
            Content-Disposition: form-data; name=\"a\"\r\n\
            content-type:text/plain\r\n\
            X-Empty:\r\n\
            X-Padded: \t value with: colon \t\r\n\
            X-Dup: 1\r\n\
            X-Dup: 2\r\n\
            \r\nv\r\n--b--\r\n";
        assert_eq!(
            assert_every_split("b", body),
            Ok(vec![part(
                &[
                    ("content-disposition", "form-data; name=\"a\""),
                    ("content-type", "text/plain"),
                    ("X-Empty", ""),
                    ("X-Padded", "value with: colon"),
                    ("X-Dup", "1"),
                    ("X-Dup", "2"),
                ],
                b"v"
            )])
        );
    }

    #[test]
    fn part_without_headers() {
        assert_eq!(
            assert_every_split("b", b"--b\r\n\r\n\r\n--b\r\n\r\nA: 1\r\n\r\n\r\n--b--"),
            Ok(vec![part(&[], b""), part(&[], b"A: 1\r\n\r\n")])
        );
    }

    #[test]
    fn invalid_header_lines() {
        for line in [
            "no colon",
            ": no name",
            "bad name: v",
            " folded: v",
            "\tfolded",
            "A: nul\0",
            "A\0: v",
            "A: line\u{b}feed",
        ] {
            let body = ["--b\r\nA: 1\r\n", line, "\r\n\r\nv\r\n--b--\r\n"].concat();
            assert_eq!(
                assert_every_split("b", body.as_bytes()),
                Err(ParseError::InvalidHeaders),
                "{line:?}"
            );
        }
    }

    fn body_with_head(head: &[u8]) -> Vec<u8> {
        [b"--b\r\n", head, b"\r\nv\r\n--b--\r\n"].concat()
    }

    #[test]
    fn head_size_limit_is_exact() {
        let line = |len: usize| {
            let mut line = b"A: ".to_vec();
            line.resize(len - 2, b'x');
            line.extend_from_slice(b"\r\n");
            line
        };
        let fits = body_with_head(&line(MAX_HEAD_SIZE));
        let too_large = body_with_head(&line(MAX_HEAD_SIZE + 1));
        for chunk_size in [1, 7, MAX_HEAD_SIZE - 1, MAX_HEAD_SIZE, usize::MAX] {
            let parts = parse_chunks("b", fits.chunks(chunk_size.min(fits.len())))
                .unwrap_or_else(|(_, err)| panic!("chunks of {chunk_size}: {err:?}"));
            assert_eq!(parts[0].data, b"v", "chunks of {chunk_size}");
            assert_eq!(
                parse_chunks("b", too_large.chunks(chunk_size.min(too_large.len())))
                    .map_err(|(_, err)| err),
                Err(ParseError::HeadersTooLarge),
                "chunks of {chunk_size}"
            );
        }
    }

    #[test]
    fn head_without_end_fails_within_the_limit() {
        let mut parser = Parser::new(&Boundary::new("b").unwrap());
        assert!(matches!(parser.step(), Ok(Event::NeedInput)));
        parser.feed(Bytes::from_static(b"--b\r\nA: 1\r\n"));
        let mut fed = 0;
        let err = loop {
            match parser.step() {
                Ok(Event::NeedInput) => {
                    parser.feed(Bytes::from_static(b"X: y\r\n"));
                    fed += 6;
                }
                Ok(event) => panic!("unexpected event: {event:?}"),
                Err(err) => break err,
            }
        };
        assert_eq!(err, ParseError::HeadersTooLarge);
        assert!(fed <= MAX_HEAD_SIZE + 16, "{fed} bytes fed");
    }

    #[test]
    fn header_count_limit() {
        let head = |count: usize| "A: 1\r\n".repeat(count).into_bytes();
        let parts = parse("b", &body_with_head(&head(MAX_HEADERS))).unwrap();
        assert_eq!(parts[0].headers.len(), MAX_HEADERS);
        assert_eq!(
            assert_every_split("b", &body_with_head(&head(MAX_HEADERS + 1))),
            Err(ParseError::HeadersTooLarge)
        );
    }

    #[test]
    fn data_is_sliced_from_the_fed_chunks() {
        let body = Bytes::from(form("b", &[("a", b"0123456789")]));
        let range = body.as_ptr_range();
        let mut parser = Parser::new(&Boundary::new("b").unwrap());
        let mut fed = false;
        let mut seen = 0;
        loop {
            match parser.step().unwrap() {
                Event::NeedInput => {
                    assert!(!fed);
                    fed = true;
                    parser.feed(body.clone());
                }
                Event::Data(data) => {
                    assert!(range.contains(&data.as_ptr()), "data was copied");
                    seen += data.len();
                }
                Event::End => break,
                Event::Part(_) | Event::PartEnd => {}
            }
        }
        assert_eq!(seen, 10);
    }

    #[test]
    fn nothing_is_consumed_past_the_close_delimiter() {
        let mut parser = Parser::new(&Boundary::new("b").unwrap());
        assert!(matches!(parser.step(), Ok(Event::NeedInput)));
        assert!(parser.wants_input());
        parser.feed(Bytes::from_static(b"--b--"));
        assert!(matches!(parser.step(), Ok(Event::End)));
        assert!(!parser.wants_input());
        parser.set_eof();
        assert!(matches!(parser.step(), Ok(Event::End)));
    }

    /// Carriage returns that never complete a delimiter cost one pass, not one per chunk.
    #[test]
    fn carriage_return_runs_stay_linear() {
        let data = b"\r".repeat(256 * 1024);
        let body = form("boundary", &[("a", &data)]);
        for chunk_size in [1, 3, 4096] {
            let mut parser = Parser::new(&Boundary::new("boundary").unwrap());
            let mut chunks = body.chunks(chunk_size);
            let (mut steps, mut seen) = (0usize, 0usize);
            loop {
                steps += 1;
                match parser.step().unwrap() {
                    Event::NeedInput => parser.feed(Bytes::copy_from_slice(chunks.next().unwrap())),
                    Event::Data(data) => seen += data.len(),
                    Event::End => break,
                    Event::Part(_) | Event::PartEnd => {}
                }
            }
            assert_eq!(seen, data.len());
            assert!(
                steps <= 4 * body.len(),
                "{steps} steps, chunks of {chunk_size}"
            );
        }
    }
}
