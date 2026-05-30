//! Canonical XML namespace URIs and prefixes for RSS 2.0, Atom 1.0, and their
//! recognised extension namespaces.
//!
//! Centralising these here lets the writer (which declares `xmlns:…`
//! attributes) and the parser (which routes elements by resolved namespace
//! URI) agree byte-for-byte on every URI. The per-extension `push_xmlns_*`
//! helpers also keep `BytesStart` construction terse at the call site.

use quick_xml::events::BytesStart;

// ---------------------------------------------------------------------------
// Namespace URIs
// ---------------------------------------------------------------------------

/// Atom 1.0 — RFC 4287 §1.2.
pub(super) const ATOM_NS: &str = "http://www.w3.org/2005/Atom";

/// XHTML 1.0 — used inside Atom `type="xhtml"` text constructs per RFC 4287 §3.1.1.3.
pub(super) const XHTML_NS: &str = "http://www.w3.org/1999/xhtml";

/// Apple iTunes podcast extension.
pub(super) const ITUNES_NS: &str = "http://www.itunes.com/dtds/podcast-1.0.dtd";

/// Podcasting 2.0 — <https://podcastindex.org/namespace/1.0>.
pub(super) const PODCAST_NS: &str = "https://podcastindex.org/namespace/1.0";

/// Dublin Core Metadata Element Set.
pub(super) const DC_NS: &str = "http://purl.org/dc/elements/1.1/";

/// Media RSS — <https://www.rssboard.org/media-rss>.
pub(super) const MEDIA_NS: &str = "http://search.yahoo.com/mrss/";

/// RSS 1.0 content module — carries `content:encoded` inside RSS 2.0 feeds.
pub(super) const CONTENT_NS: &str = "http://purl.org/rss/1.0/modules/content/";

// ---------------------------------------------------------------------------
// `xmlns:<prefix>` attribute helpers
// ---------------------------------------------------------------------------
//
// Each helper pushes the corresponding `xmlns:<prefix>="URI"` declaration onto
// a `BytesStart`. The prefix is part of the constant so call sites stay
// allocation-free — there is no per-call `format!("xmlns:{prefix}")`.

/// Declare the default `xmlns="http://www.w3.org/2005/Atom"` on an Atom root.
pub(super) fn push_xmlns_atom_default(tag: &mut BytesStart<'_>) {
    tag.push_attribute(("xmlns", ATOM_NS));
}

/// Declare the conventional `xmlns:atom="…"` (used on an `<rss>` root that
/// embeds an `<atom:link rel="self" …/>`).
pub(super) fn push_xmlns_atom(tag: &mut BytesStart<'_>) {
    tag.push_attribute(("xmlns:atom", ATOM_NS));
}

/// Declare `xmlns:itunes` on the feed root.
pub(super) fn push_xmlns_itunes(tag: &mut BytesStart<'_>) {
    tag.push_attribute(("xmlns:itunes", ITUNES_NS));
}

/// Declare `xmlns:podcast` on the feed root.
pub(super) fn push_xmlns_podcast(tag: &mut BytesStart<'_>) {
    tag.push_attribute(("xmlns:podcast", PODCAST_NS));
}

/// Declare `xmlns:dc` on the feed root.
pub(super) fn push_xmlns_dc(tag: &mut BytesStart<'_>) {
    tag.push_attribute(("xmlns:dc", DC_NS));
}

/// Declare `xmlns:media` on the feed root.
pub(super) fn push_xmlns_media(tag: &mut BytesStart<'_>) {
    tag.push_attribute(("xmlns:media", MEDIA_NS));
}

/// Declare `xmlns:content` on the feed root.
pub(super) fn push_xmlns_content(tag: &mut BytesStart<'_>) {
    tag.push_attribute(("xmlns:content", CONTENT_NS));
}
