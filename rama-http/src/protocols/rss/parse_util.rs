//! Low-level parsing helpers shared by the streaming readers and the
//! extension accumulator. None of this is part of the public API.
//!
//! Each helper is intentionally cheap: they operate on a `BytesStart`
//! reference (no buffer ownership), parse one attribute or one field, and
//! return owned data. The streaming readers call them per element.

use jiff::Timestamp;
use quick_xml::XmlVersion;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesRef, BytesText};
use rama_core::telemetry::tracing;
use rama_net::uri::Uri;

use super::atom::{AtomCategory, AtomLink, AtomText};
use super::error::FeedParseError;
use super::feed_ext::names::attr;
use super::rss2::Rss2Enclosure;

/// Short alias kept so attribute-extraction helper signatures fit on a line.
pub(super) type Attrs<'a> = quick_xml::events::BytesStart<'a>;

/// Expand the `Event::End` arm shared verbatim by the Atom and RSS2 streaming
/// readers' `step` loops. `$self` is the reader, `$e` the `BytesEnd`, `$rr` the
/// resolved namespace.
///
/// Decrements depth, classifies the namespace, then copies the element's local
/// name into a 64-byte stack buffer so the borrow on the reader's read buffer
/// (held by `$e`) is released before `handle_end` takes `&mut self`. This
/// avoids the per-event `String` allocation the borrow-checker would otherwise
/// force on this hot path. 64 bytes covers every Atom/RSS/extension element
/// name in our vocabulary; longer or non-UTF-8 names fall through to `""`
/// (which matches nothing) — same outcome as a heap copy. The reassembled text
/// is trimmed once (the readers run with `trim_text(false)`), dropping a
/// field's surrounding whitespace while preserving whitespace interior to it.
macro_rules! feed_reader_handle_end_event {
    ($self:ident, $e:ident, $rr:ident) => {{
        $self.depth -= 1;
        let ns = $crate::protocols::rss::feed_ext::parse::classify_ns(&$rr);
        let mut stack = [0u8; 64];
        let local_bytes = $e.local_name();
        let n = local_bytes.as_ref().len().min(stack.len());
        stack[..n].copy_from_slice(&local_bytes.as_ref()[..n]);
        drop($e);
        let local = ::std::str::from_utf8(&stack[..n]).unwrap_or("");
        let mut text = ::std::mem::take(&mut $self.text_buf);
        let trimmed = text.trim();
        if trimmed.len() != text.len() {
            text = trimmed.to_owned();
        }
        $self.handle_end(ns, local, text)
    }};
}
pub(in crate::protocols::rss) use feed_reader_handle_end_event;

/// Read an attribute by qualified name and XML-unescape its value. Returns
/// `None` if absent, malformed, or carrying an unresolvable entity — the
/// caller treats that the same as "missing".
pub(super) fn attr_value(e: &Attrs<'_>, name: &str) -> Option<String> {
    let needle = name.as_bytes();
    e.attributes()
        .filter_map(|a| a.ok())
        .find(|a| a.key.as_ref() == needle)
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
/// so `decode()` (bytes → str, no entity resolution) yields the literal run and
/// each entity is appended separately by [`push_general_ref`]. On a decode
/// error this propagates in strict mode and appends a lossy rendering in
/// lenient mode — the same split the old `BytesText::unescape` path had.
pub(super) fn push_text(
    buf: &mut String,
    e: &BytesText<'_>,
    strict: bool,
) -> Result<(), FeedParseError> {
    match e.decode() {
        Ok(t) => buf.push_str(&t),
        Err(err) => {
            if strict {
                return Err(FeedParseError::new(format!("invalid text content: {err}")));
            }
            tracing::debug!("rss feed text decode error (lenient): {err}");
            buf.push_str(&String::from_utf8_lossy(e.as_ref()));
        }
    }
    Ok(())
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
    let name = e.decode().unwrap_or_default();
    if let Some(replacement) = resolve_predefined_entity(&name) {
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
    buf.push_str(&name);
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
