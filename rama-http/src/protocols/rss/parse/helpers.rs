//! Small parsing primitives shared by the RSS 2.0 and Atom 1.0 parsers.
//!
//! [`attr_value`], [`parse_rss2_date`] and the [`Attrs`] alias are also
//! re-exported by [`super`] so the extension accumulator and the writers can
//! reuse them without importing this module directly.

use jiff::Timestamp;

use super::super::atom::{AtomCategory, AtomLink, AtomText};
use super::super::rss2::Rss2Enclosure;

/// Read an attribute by qualified name and XML-unescape its value. Returns
/// `None` if absent, malformed, or carrying an unresolvable entity — the
/// caller treats that the same as "missing".
pub(crate) fn attr_value(e: &quick_xml::events::BytesStart<'_>, name: &[u8]) -> Option<String> {
    e.attributes()
        .filter_map(|a| a.ok())
        .find(|a| a.key.as_ref() == name)
        .and_then(|a| a.unescape_value().ok().map(|v| v.into_owned()))
}

/// Parse an RSS 2.0 date — RFC 822 first (the spec) with RFC 3339 as a
/// fallback for feeds that emit ISO 8601 anyway.
pub(crate) fn parse_rss2_date(s: &str) -> Option<Timestamp> {
    use jiff::fmt::rfc2822;
    let s = s.trim();
    rfc2822::parse(s)
        .ok()
        .map(|zdt| zdt.timestamp())
        .or_else(|| parse_rfc3339_lax(s))
}

/// Alias kept short so attribute-extraction helper signatures fit on one line.
pub(crate) type Attrs<'a> = quick_xml::events::BytesStart<'a>;

pub(crate) fn enclosure_from_attrs(e: &Attrs<'_>) -> Rss2Enclosure {
    Rss2Enclosure {
        url: attr_value(e, b"url").unwrap_or_default(),
        length: attr_value(e, b"length")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or_default(),
        type_: attr_value(e, b"type").unwrap_or_default(),
    }
}

pub(crate) fn atom_link_from_attrs(e: &Attrs<'_>) -> AtomLink {
    AtomLink {
        href: attr_value(e, b"href").unwrap_or_default(),
        rel: attr_value(e, b"rel"),
        type_: attr_value(e, b"type"),
        hreflang: attr_value(e, b"hreflang"),
        title: attr_value(e, b"title"),
        length: attr_value(e, b"length").and_then(|v| v.parse().ok()),
    }
}

pub(crate) fn atom_category_from_attrs(e: &Attrs<'_>) -> AtomCategory {
    AtomCategory {
        term: attr_value(e, b"term").unwrap_or_default(),
        scheme: attr_value(e, b"scheme"),
        label: attr_value(e, b"label"),
    }
}

pub(crate) fn parse_rfc3339_lax(s: &str) -> Option<Timestamp> {
    s.trim().parse::<Timestamp>().ok()
}

pub(crate) fn make_atom_text(type_attr: &str, value: String) -> AtomText {
    match type_attr {
        "html" | "text/html" => AtomText::Html(value),
        "xhtml" => AtomText::Xhtml(value),
        _ => AtomText::Text(value),
    }
}
