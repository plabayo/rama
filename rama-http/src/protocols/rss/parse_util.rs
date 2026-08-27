//! Low-level parsing helpers shared by the streaming readers and the
//! extension accumulator. None of this is part of the public API.
//!
//! Each helper is intentionally cheap: they operate on a `BytesStart`
//! reference (no buffer ownership), parse one attribute or one field, and
//! return owned data. The streaming readers call them per element.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use jiff::Timestamp;
use quick_xml::XmlVersion;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesEnd, BytesRef, BytesText};
use rama_core::telemetry::tracing;
use rama_net::uri::Uri;
use tokio::io::{AsyncBufRead, AsyncRead, BufReader, ReadBuf};

use super::atom::{AtomCategory, AtomLink, AtomText};
use super::error::FeedParseError;
use super::feed_ext::names::attr;
use super::rss2::Rss2Enclosure;

/// Short alias kept so attribute-extraction helper signatures fit on a line.
pub(super) type Attrs<'a> = quick_xml::events::BytesStart<'a>;

pub(super) type XmlReader = Pin<Box<dyn AsyncBufRead + Send>>;

pub(super) fn xml_reader<R>(reader: R, strict: bool) -> XmlReader
where
    R: AsyncBufRead + Unpin + Send + 'static,
{
    if strict {
        Box::pin(reader)
    } else {
        Box::pin(BufReader::new(LossyUtf8Reader::new(reader)))
    }
}

struct LossyUtf8Reader<R> {
    inner: R,
    output: Vec<u8>,
    output_offset: usize,
    pending: Vec<u8>,
    eof: bool,
}

impl<R> LossyUtf8Reader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            output: Vec::new(),
            output_offset: 0,
            pending: Vec::with_capacity(4),
            eof: false,
        }
    }

    fn fill_output(&mut self, bytes: &[u8]) {
        let mut combined = std::mem::take(&mut self.pending);
        combined.extend_from_slice(bytes);
        let mut remaining = combined.as_slice();
        loop {
            match std::str::from_utf8(remaining) {
                Ok(_) => {
                    self.output.extend_from_slice(remaining);
                    return;
                }
                Err(error) => {
                    let valid = error.valid_up_to();
                    self.output.extend_from_slice(&remaining[..valid]);
                    if let Some(invalid) = error.error_len() {
                        self.output.extend_from_slice("\u{fffd}".as_bytes());
                        remaining = &remaining[valid + invalid..];
                    } else {
                        self.pending.extend_from_slice(&remaining[valid..]);
                        return;
                    }
                }
            }
        }
    }
}

impl<R> AsyncRead for LossyUtf8Reader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.output_offset < this.output.len() {
                let count = output
                    .remaining()
                    .min(this.output.len() - this.output_offset);
                output.put_slice(&this.output[this.output_offset..this.output_offset + count]);
                this.output_offset += count;
                if this.output_offset == this.output.len() {
                    this.output.clear();
                    this.output_offset = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                if !this.pending.is_empty() {
                    this.pending.clear();
                    this.output.extend_from_slice("\u{fffd}".as_bytes());
                    continue;
                }
                return Poll::Ready(Ok(()));
            }

            let mut bytes = [0_u8; 8192];
            let mut read = ReadBuf::new(&mut bytes);
            match Pin::new(&mut this.inner).poll_read(context, &mut read) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) if read.filled().is_empty() => {
                    this.eof = true;
                }
                Poll::Ready(Ok(())) => this.fill_output(read.filled()),
            }
        }
    }
}

/// Extract the finished pieces of an `Event::End` — the element's local name
/// and its reassembled text — so the caller can release the read-buffer borrow
/// `e` holds before taking `&mut self` to dispatch them. Shared verbatim by the
/// Atom and RSS2 streaming readers' `step` loops.
///
/// The local name is copied into `name_buf` (a stack buffer) and `e` is
/// consumed, dropping its borrow on the reader's read buffer. This avoids the
/// per-event `String` allocation the borrow-checker would otherwise force on
/// this hot path. 64 bytes covers every Atom/RSS/extension element name in our
/// vocabulary; longer names are truncated and fall through to a value that
/// matches nothing — the same outcome as a heap copy.
///
/// The text is trimmed once (the readers run with `trim_text(false)`), dropping
/// a field's surrounding whitespace while preserving whitespace interior to it.
pub(in crate::protocols::rss) fn end_event_parts<'b>(
    e: BytesEnd<'_>,
    name_buf: &'b mut [u8; 64],
    text_buf: &mut String,
) -> (&'b str, String) {
    let local_name = e.local_name();
    let local_bytes = local_name.as_ref().as_bytes();
    let n = local_bytes.len().min(name_buf.len());
    name_buf[..n].copy_from_slice(&local_bytes[..n]);
    // Done with `e`: drop it to release its read-buffer borrow before we return
    // (so the caller can take `&mut self`).
    drop(e);
    let local = std::str::from_utf8(&name_buf[..n]).unwrap_or("");

    let mut text = std::mem::take(text_buf);
    let trimmed = text.trim();
    if trimmed.len() != text.len() {
        text = trimmed.to_owned();
    }
    (local, text)
}

/// Read an attribute by qualified name and XML-unescape its value. Returns
/// `None` if absent, malformed, or carrying an unresolvable entity — the
/// caller treats that the same as "missing".
pub(super) fn attr_value(e: &Attrs<'_>, name: &str) -> Option<String> {
    e.attributes()
        .filter_map(|a| a.ok())
        .find(|a| a.key.as_ref() == name)
        // quick-xml renamed `unescape_value` -> `normalized_value` (the latter
        // also applies XML attribute-value whitespace normalization). `Implicit1_0`
        // preserves the prior behaviour: UTF-8 decode + the five predefined
        // entities, no DTD entity expansion.
        .and_then(|a| {
            a.normalized_value(XmlVersion::Implicit1_0)
                .ok()
                .map(|v| v.into_owned())
        })
}

pub(super) fn parse_uri(s: &str) -> Option<Uri> {
    Uri::parse(s.trim()).ok()
}

pub(super) fn parse_uri_reference(s: &str) -> Option<Uri> {
    Uri::parse_reference(s.trim()).ok()
}

pub(super) fn attr_uri(e: &Attrs<'_>, name: &str) -> Option<Uri> {
    attr_value(e, name).and_then(|v| parse_uri(&v))
}

pub(super) fn attr_uri_reference(e: &Attrs<'_>, name: &str) -> Option<Uri> {
    attr_value(e, name).and_then(|v| parse_uri_reference(&v))
}

/// Parse an RSS 2.0 date — RFC 822 first (the spec) with RFC 3339 as a
/// fallback for feeds that emit ISO 8601 anyway.
pub(super) fn parse_rss2_date(s: &str) -> Option<Timestamp> {
    use jiff::fmt::rfc2822;
    let s = s.trim();
    rfc2822::parse(s)
        .ok()
        .map(|zdt| zdt.timestamp())
        // s is already trimmed; parse directly to avoid the second trim.
        .or_else(|| s.parse::<Timestamp>().ok())
}

pub(super) fn parse_rfc3339_lax(s: &str) -> Option<Timestamp> {
    s.trim().parse::<Timestamp>().ok()
}

/// Translate Atom's `type` attribute (`text`/`html`/`xhtml`) into the matching
/// [`AtomText`] variant.
pub(super) fn make_atom_text(type_attr: &str, value: String) -> AtomText {
    match type_attr {
        "html" | "text/html" => AtomText::html_raw(value),
        "xhtml" => AtomText::xhtml(value),
        _ => AtomText::text(value),
    }
}

pub(super) fn enclosure_from_attrs(e: &Attrs<'_>) -> Option<Rss2Enclosure> {
    Some(Rss2Enclosure {
        url: attr_uri(e, attr::URL)?,
        length: attr_value(e, attr::LENGTH)
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or_default(),
        type_: attr_value(e, attr::TYPE).unwrap_or_default(),
    })
}

pub(super) fn atom_link_from_attrs(e: &Attrs<'_>) -> Option<AtomLink> {
    Some(AtomLink {
        href: attr_uri_reference(e, attr::HREF)?,
        rel: attr_value(e, attr::REL),
        type_: attr_value(e, attr::TYPE),
        hreflang: attr_value(e, attr::HREFLANG),
        title: attr_value(e, attr::TITLE),
        length: attr_value(e, attr::LENGTH).and_then(|v| v.parse().ok()),
    })
}

pub(super) fn atom_category_from_attrs(e: &Attrs<'_>) -> AtomCategory {
    AtomCategory {
        term: attr_value(e, attr::TERM).unwrap_or_default(),
        scheme: attr_value(e, attr::SCHEME),
        label: attr_value(e, attr::LABEL),
    }
}

// ---------------------------------------------------------------------------
// Text / entity accumulation — shared by the Atom and RSS 2.0 streaming
// readers, which both accumulate element text into a `String` buffer.
// ---------------------------------------------------------------------------

/// Append the decoded content of an `Event::Text` to `buf`.
///
/// quick-xml 0.40 stopped expanding entities inside text: a run like
/// `a &amp; b` now arrives as `Text("a ")`, `GeneralRef("amp")`, `Text(" b")`,
/// so the already-decoded event string yields the literal run and each entity
/// is appended separately by [`push_general_ref`]. Lenient readers replace
/// invalid UTF-8 before it reaches quick-xml; strict readers propagate it.
pub(super) fn push_text(buf: &mut String, e: &BytesText<'_>) {
    buf.push_str(e.as_ref());
}

/// Append a resolved general entity reference (`Event::GeneralRef`) to `buf`.
///
/// quick-xml 0.40 emits each `&name;` / `&#nnn;` as its own event and leaves
/// resolution to the caller. Numeric character references and the five XML
/// predefined entities (`lt`, `gt`, `amp`, `quot`, `apos`) are resolved here;
/// feeds carry no DTD, so any other entity is undefined — it propagates as an
/// error in strict mode and is re-emitted verbatim (`&name;`) in lenient mode,
/// mirroring how the old `unescape` surfaced an unresolvable reference.
pub(super) fn push_general_ref(
    buf: &mut String,
    e: &BytesRef<'_>,
    strict: bool,
) -> Result<(), FeedParseError> {
    match e.resolve_char_ref() {
        Ok(Some(ch)) => {
            buf.push(ch);
            return Ok(());
        }
        Ok(None) => {} // a named entity — resolve below
        Err(err) => {
            if strict {
                return Err(FeedParseError::new(format!(
                    "invalid character reference: {err}"
                )));
            }
        }
    }
    let name = e.as_ref();
    if let Some(replacement) = resolve_predefined_entity(name) {
        buf.push_str(replacement);
        return Ok(());
    }
    if strict {
        return Err(FeedParseError::new(format!(
            "unresolvable entity reference: &{name};"
        )));
    }
    tracing::debug!("rss feed unknown entity (lenient): &{name};");
    buf.push('&');
    buf.push_str(name);
    buf.push(';');
    Ok(())
}

// ---------------------------------------------------------------------------
// Format detection — used by `FeedStream::new` to pick a reader.
// ---------------------------------------------------------------------------

/// Sniff whether the byte stream looks like an Atom 1.0 document. We look at
/// the first *real element* (skipping `<?xml…?>`, comments and DOCTYPE) and
/// check that its local name is `feed`. This catches both plain `<feed
/// xmlns=…>` and a prefix-bound root like `<a:feed xmlns:a="http://www.w3.org/
/// 2005/Atom">` without false-positiving on an RSS feed that merely declares
/// the Atom namespace prefix (e.g. for `<atom:link rel="self"/>`).
pub(super) fn detect_atom(s: &str) -> bool {
    first_element_local_name(probe_prefix(s, 2048)) == Some("feed")
}

/// Sniff whether the byte stream looks like an RSS 2.0 document — first
/// element is `rss` (or `channel`, if some upstream stripped the wrapping
/// `<rss>` shell).
pub(super) fn detect_rss(s: &str) -> bool {
    matches!(
        first_element_local_name(probe_prefix(s, 1024)),
        Some("rss" | "channel")
    )
}

/// Find the local name of the first real element in `s`, skipping the XML
/// declaration, comments and DOCTYPE. Returns `None` if no element is found
/// inside the probed window.
fn first_element_local_name(s: &str) -> Option<&str> {
    let mut rest = s;
    loop {
        let lt = rest.find('<')?;
        rest = &rest[lt + 1..];
        if let Some(after) = rest.strip_prefix("?xml") {
            let end = after.find("?>")?;
            rest = &after[end + 2..];
            continue;
        }
        if let Some(after) = rest.strip_prefix("!--") {
            let end = after.find("-->")?;
            rest = &after[end + 3..];
            continue;
        }
        if let Some(after) = rest.strip_prefix("!DOCTYPE") {
            let end = after.find('>')?;
            rest = &after[end + 1..];
            continue;
        }
        if rest.starts_with('!') || rest.starts_with('?') {
            let end = rest.find('>')?;
            rest = &rest[end + 1..];
            continue;
        }
        let qname_end = rest
            .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
            .unwrap_or(rest.len());
        let qname = &rest[..qname_end];
        // `str::rsplit(':').next()` is always `Some` (an empty string
        // yields `Some("")`), but `unwrap_or_default()` documents the
        // safe fallback without an unreachable panic path.
        return Some(qname.rsplit(':').next().unwrap_or_default());
    }
}

/// Largest prefix of `s` no longer than `max` bytes that doesn't split a
/// multi-byte UTF-8 char (plain byte slicing would panic on a non-boundary).
fn probe_prefix(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}
