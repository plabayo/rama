//! Low-level parsing helpers shared by the streaming readers and the
//! extension accumulator. None of this is part of the public API.
//!
//! Each helper is intentionally cheap: they operate on a `BytesStart`
//! reference (no buffer ownership), parse one attribute or one field, and
//! return owned data. The streaming readers call them per element.

use jiff::Timestamp;

use super::atom::{AtomCategory, AtomLink, AtomText};
use super::ext_names::attr;
use super::rss2::Rss2Enclosure;

/// Short alias kept so attribute-extraction helper signatures fit on a line.
pub(super) type Attrs<'a> = quick_xml::events::BytesStart<'a>;

/// Read an attribute by qualified name and XML-unescape its value. Returns
/// `None` if absent, malformed, or carrying an unresolvable entity — the
/// caller treats that the same as "missing".
pub(super) fn attr_value(e: &Attrs<'_>, name: &str) -> Option<String> {
    let needle = name.as_bytes();
    e.attributes()
        .filter_map(|a| a.ok())
        .find(|a| a.key.as_ref() == needle)
        .and_then(|a| a.unescape_value().ok().map(|v| v.into_owned()))
}

/// Parse an RSS 2.0 date — RFC 822 first (the spec) with RFC 3339 as a
/// fallback for feeds that emit ISO 8601 anyway.
pub(super) fn parse_rss2_date(s: &str) -> Option<Timestamp> {
    use jiff::fmt::rfc2822;
    let s = s.trim();
    rfc2822::parse(s)
        .ok()
        .map(|zdt| zdt.timestamp())
        .or_else(|| parse_rfc3339_lax(s))
}

pub(super) fn parse_rfc3339_lax(s: &str) -> Option<Timestamp> {
    s.trim().parse::<Timestamp>().ok()
}

/// Translate Atom's `type` attribute (`text`/`html`/`xhtml`) into the matching
/// [`AtomText`] variant.
pub(super) fn make_atom_text(type_attr: &str, value: String) -> AtomText {
    match type_attr {
        "html" | "text/html" => AtomText::html(value),
        "xhtml" => AtomText::xhtml(value),
        _ => AtomText::text(value),
    }
}

pub(super) fn enclosure_from_attrs(e: &Attrs<'_>) -> Rss2Enclosure {
    Rss2Enclosure {
        url: attr_value(e, attr::URL).unwrap_or_default(),
        length: attr_value(e, attr::LENGTH)
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or_default(),
        type_: attr_value(e, attr::TYPE).unwrap_or_default(),
    }
}

pub(super) fn atom_link_from_attrs(e: &Attrs<'_>) -> AtomLink {
    AtomLink {
        href: attr_value(e, attr::HREF).unwrap_or_default(),
        rel: attr_value(e, attr::REL),
        type_: attr_value(e, attr::TYPE),
        hreflang: attr_value(e, attr::HREFLANG),
        title: attr_value(e, attr::TITLE),
        length: attr_value(e, attr::LENGTH).and_then(|v| v.parse().ok()),
    }
}

pub(super) fn atom_category_from_attrs(e: &Attrs<'_>) -> AtomCategory {
    AtomCategory {
        term: attr_value(e, attr::TERM).unwrap_or_default(),
        scheme: attr_value(e, attr::SCHEME),
        label: attr_value(e, attr::LABEL),
    }
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
        return Some(qname.rsplit(':').next().unwrap_or(qname));
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
