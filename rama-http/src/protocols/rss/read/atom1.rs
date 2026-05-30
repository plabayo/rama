//! Async streaming Atom 1.0 reader.
//!
//! Symmetric to [`super::rss2`]: yields an [`AtomReadEvent::Feed`] event with
//! feed-level metadata up to (and excluding) the first `<entry>`, then one
//! [`AtomReadEvent::Entry`] per entry, then [`AtomReadEvent::Eof`].
//!
//! [`collect_atom`] is the in-memory adapter.

use jiff::Timestamp;
use quick_xml::NsReader;
use quick_xml::events::Event;
use rama_core::futures::Stream;
use rama_core::futures::async_stream::stream_fn;
use rama_core::telemetry::tracing;
use tokio::io::AsyncBufRead;

use super::super::atom::{
    AtomCategory, AtomContent, AtomEntry, AtomFeed, AtomGenerator, AtomLink, AtomPerson,
    AtomSource, AtomText,
};
use super::super::ext_parse::{FeedExtAcc, ItemExtAcc, Ns, classify_ns};
use super::super::feed_ext::FeedExtensions;
use super::super::parse::{Attrs, FeedParseError, attr_value};

/// Feed-level metadata of an Atom 1.0 feed — [`AtomFeed`] without `entries`.
#[derive(Debug, Clone, PartialEq)]
pub struct AtomHeader {
    pub id: String,
    pub title: AtomText,
    pub updated: Timestamp,
    pub authors: Vec<AtomPerson>,
    pub links: Vec<AtomLink>,
    pub categories: Vec<AtomCategory>,
    pub contributors: Vec<AtomPerson>,
    pub generator: Option<AtomGenerator>,
    pub icon: Option<String>,
    pub logo: Option<String>,
    pub rights: Option<AtomText>,
    pub subtitle: Option<AtomText>,
    pub extensions: FeedExtensions,
}

impl Default for AtomHeader {
    fn default() -> Self {
        Self {
            id: String::new(),
            title: AtomText::text(""),
            updated: Timestamp::UNIX_EPOCH,
            authors: Vec::new(),
            links: Vec::new(),
            categories: Vec::new(),
            contributors: Vec::new(),
            generator: None,
            icon: None,
            logo: None,
            rights: None,
            subtitle: None,
            extensions: FeedExtensions::default(),
        }
    }
}

impl AtomHeader {
    /// Combine this header with an iterator of entries into a full feed.
    #[must_use]
    pub fn into_feed_with_entries<I>(self, entries: I) -> AtomFeed
    where
        I: IntoIterator<Item = AtomEntry>,
    {
        AtomFeed {
            id: self.id,
            title: self.title,
            updated: self.updated,
            authors: self.authors,
            links: self.links,
            categories: self.categories,
            contributors: self.contributors,
            generator: self.generator,
            icon: self.icon,
            logo: self.logo,
            rights: self.rights,
            subtitle: self.subtitle,
            entries: entries.into_iter().collect(),
            extensions: self.extensions,
        }
    }
}

/// One step of an Atom 1.0 streaming parse.
#[derive(Debug, Clone, PartialEq)]
#[expect(
    clippy::large_enum_variant,
    reason = "internal event type: the size disparity (Feed header vs. boxed Entry) \
              only lives across one yield boundary inside the stream, not in user-visible APIs"
)]
pub(super) enum AtomReadEvent {
    /// Feed-level metadata, emitted once before any [`Entry`](Self::Entry).
    Feed(AtomHeader),
    /// One fully-parsed `<entry>`.
    Entry(Box<AtomEntry>),
    /// End of feed (the matching `</feed>` end or EOF in lenient mode).
    Eof,
}

/// Construct an async stream yielding Atom 1.0 events from `reader`.
///
/// `strict = true` requires `<id>`, `<title>` and a parseable `<updated>` both
/// at feed and entry level. Lenient mode tolerates missing/unparseable values.
#[expect(
    clippy::too_many_lines,
    reason = "single-state-machine streaming parser; splitting hurts readability"
)]
pub(super) fn atom_event_stream<R>(
    reader: R,
    strict: bool,
) -> impl Stream<Item = Result<AtomReadEvent, FeedParseError>> + Send
where
    R: AsyncBufRead + Unpin + Send + 'static,
{
    stream_fn(move |mut yielder| async move {
        let mut nsr = NsReader::from_reader(reader);
        nsr.config_mut().trim_text(true);
        let mut buf: Vec<u8> = Vec::with_capacity(4096);

        // Feed-level state, yielded as `AtomReadEvent::Feed` on first <entry>
        // (or at EOF for entry-less feeds).
        let mut header = AtomHeader::default();
        let mut feed_acc = FeedExtAcc::default();
        let mut feed_updated_parsed = false;
        let mut header_yielded = false;
        let mut saw_root = false;
        let mut pending_generator: Option<AtomGenerator> = None;

        // Entry / sub-element state — same shape as the sync parser.
        let mut in_entry = false;
        let mut in_author = false;
        let mut in_feed_author = false;
        let mut in_contributor = false;
        let mut in_feed_contributor = false;
        let mut in_source = false;
        let mut current_entry = AtomEntry::new("", AtomText::text(""), Timestamp::UNIX_EPOCH);
        let mut current_entry_id_set = false;
        let mut current_entry_title_set = false;
        let mut current_entry_updated_parsed = false;
        let mut entry_acc = ItemExtAcc::default();
        let mut current_author = AtomPerson::new("");
        let mut current_contributor = AtomPerson::new("");
        let mut current_source = AtomSource {
            id: None,
            title: None,
            updated: None,
        };

        let mut current_title_type = String::from("text");
        let mut current_summary_type = String::from("text");
        let mut current_content_type = String::from("text");
        let mut current_rights_type = String::from("text");
        let mut current_subtitle_type = String::from("text");

        let mut text_buf = String::new();
        let mut depth: i32 = 0;

        macro_rules! yield_err {
            ($expr:expr) => {{
                yielder.yield_item(Err($expr)).await;
                return;
            }};
        }
        macro_rules! flush_header {
            () => {{
                if !header_yielded {
                    let mut h = std::mem::take(&mut header);
                    h.extensions = std::mem::take(&mut feed_acc).finish();
                    header_yielded = true;
                    yielder.yield_item(Ok(AtomReadEvent::Feed(h))).await;
                }
            }};
        }

        loop {
            buf.clear();
            let (rr, ev) = match nsr.read_resolved_event_into_async(&mut buf).await {
                Ok(p) => p,
                Err(e) => {
                    if strict {
                        yield_err!(FeedParseError {
                            message: format!("xml error: {e}"),
                        });
                    }
                    tracing::debug!("atom stream xml error (lenient): {e}");
                    break;
                }
            };

            match ev {
                Event::Start(e) => {
                    depth += 1;
                    let ns = classify_ns(&rr);
                    let local_name = e.local_name();
                    let local = std::str::from_utf8(local_name.as_ref()).unwrap_or("");
                    text_buf.clear();

                    let consumed = if in_entry {
                        entry_acc.on_start(ns, local, &e)
                    } else {
                        feed_acc.on_start(ns, local, &e)
                    };
                    if consumed {
                        continue;
                    }
                    if ns != Ns::Atom {
                        continue;
                    }

                    match local {
                        "feed" => saw_root = true,
                        "entry" => {
                            flush_header!();
                            in_entry = true;
                            current_entry =
                                AtomEntry::new("", AtomText::text(""), Timestamp::UNIX_EPOCH);
                            current_entry_id_set = false;
                            current_entry_title_set = false;
                            current_entry_updated_parsed = false;
                            entry_acc = ItemExtAcc::default();
                        }
                        "author" if !in_source => {
                            current_author = AtomPerson::new("");
                            if in_entry {
                                in_author = true;
                            } else {
                                in_feed_author = true;
                            }
                        }
                        "contributor" if !in_source => {
                            current_contributor = AtomPerson::new("");
                            if in_entry {
                                in_contributor = true;
                            } else {
                                in_feed_contributor = true;
                            }
                        }
                        "source" if in_entry && !in_source => {
                            in_source = true;
                            current_source = AtomSource {
                                id: None,
                                title: None,
                                updated: None,
                            };
                        }
                        "link" if !in_source => {
                            let link = atom_link_from_attrs(&e);
                            if in_entry {
                                current_entry.links.push(link);
                            } else {
                                header.links.push(link);
                            }
                        }
                        "category" if !in_source => {
                            let cat = atom_category_from_attrs(&e);
                            if in_entry {
                                current_entry.categories.push(cat);
                            } else {
                                header.categories.push(cat);
                            }
                        }
                        "title" => {
                            let t = attr_value(&e, b"type").unwrap_or_else(|| "text".into());
                            if t == "xhtml" {
                                let xml =
                                    match capture_xhtml_subtree_async(&mut nsr, &mut buf).await {
                                        Ok(s) => s,
                                        Err(err) => yield_err!(err),
                                    };
                                if in_entry {
                                    current_entry.title = AtomText::Xhtml(xml);
                                    current_entry_title_set = true;
                                } else {
                                    header.title = AtomText::Xhtml(xml);
                                }
                                depth -= 1;
                                continue;
                            }
                            current_title_type = t;
                        }
                        "summary" if in_entry => {
                            let t = attr_value(&e, b"type").unwrap_or_else(|| "text".into());
                            if t == "xhtml" {
                                let xml =
                                    match capture_xhtml_subtree_async(&mut nsr, &mut buf).await {
                                        Ok(s) => s,
                                        Err(err) => yield_err!(err),
                                    };
                                current_entry.summary = Some(AtomText::Xhtml(xml));
                                depth -= 1;
                                continue;
                            }
                            current_summary_type = t;
                        }
                        "content" if in_entry && !in_source => {
                            let t = attr_value(&e, b"type").unwrap_or_else(|| "text".into());
                            if t == "xhtml" {
                                let xml =
                                    match capture_xhtml_subtree_async(&mut nsr, &mut buf).await {
                                        Ok(s) => s,
                                        Err(err) => yield_err!(err),
                                    };
                                current_entry.content = Some(AtomContent {
                                    value: AtomText::Xhtml(xml),
                                    src: None,
                                });
                                depth -= 1;
                                continue;
                            }
                            current_content_type = t;
                        }
                        "rights" => {
                            let t = attr_value(&e, b"type").unwrap_or_else(|| "text".into());
                            if t == "xhtml" {
                                let xml =
                                    match capture_xhtml_subtree_async(&mut nsr, &mut buf).await {
                                        Ok(s) => s,
                                        Err(err) => yield_err!(err),
                                    };
                                if in_entry {
                                    current_entry.rights = Some(AtomText::Xhtml(xml));
                                } else {
                                    header.rights = Some(AtomText::Xhtml(xml));
                                }
                                depth -= 1;
                                continue;
                            }
                            current_rights_type = t;
                        }
                        "subtitle" if !in_entry => {
                            let t = attr_value(&e, b"type").unwrap_or_else(|| "text".into());
                            if t == "xhtml" {
                                let xml =
                                    match capture_xhtml_subtree_async(&mut nsr, &mut buf).await {
                                        Ok(s) => s,
                                        Err(err) => yield_err!(err),
                                    };
                                header.subtitle = Some(AtomText::Xhtml(xml));
                                depth -= 1;
                                continue;
                            }
                            current_subtitle_type = t;
                        }
                        "generator" if !in_source => {
                            pending_generator = Some(AtomGenerator {
                                value: String::new(),
                                uri: attr_value(&e, b"uri"),
                                version: attr_value(&e, b"version"),
                            });
                        }
                        _ => {}
                    }
                }
                Event::Empty(e) => {
                    let ns = classify_ns(&rr);
                    let local_name = e.local_name();
                    let local = std::str::from_utf8(local_name.as_ref()).unwrap_or("");

                    let consumed = if in_entry {
                        entry_acc.on_empty(ns, local, &e)
                    } else {
                        feed_acc.on_empty(ns, local, &e)
                    };
                    if consumed || ns != Ns::Atom {
                        continue;
                    }
                    match local {
                        "link" if !in_source => {
                            let link = atom_link_from_attrs(&e);
                            if in_entry {
                                current_entry.links.push(link);
                            } else {
                                header.links.push(link);
                            }
                        }
                        "category" if !in_source => {
                            let cat = atom_category_from_attrs(&e);
                            if in_entry {
                                current_entry.categories.push(cat);
                            } else {
                                header.categories.push(cat);
                            }
                        }
                        "content" if in_entry && !in_source => {
                            // Out-of-line <content src=".." type=".."/>.
                            if let Some(src) = attr_value(&e, b"src") {
                                let type_ =
                                    attr_value(&e, b"type").unwrap_or_else(|| "text".into());
                                current_entry.content = Some(AtomContent {
                                    value: AtomText::Text(type_),
                                    src: Some(src),
                                });
                            }
                        }
                        _ => {}
                    }
                }
                Event::Text(e) => match e.unescape() {
                    Ok(t) => text_buf.push_str(&t),
                    Err(err) => {
                        if strict {
                            yield_err!(FeedParseError {
                                message: format!("invalid text content: {err}"),
                            });
                        }
                        tracing::debug!("atom stream unescape error (lenient): {err}");
                        text_buf.push_str(&String::from_utf8_lossy(e.as_ref()));
                    }
                },
                Event::CData(e) => match std::str::from_utf8(e.as_ref()) {
                    Ok(t) => text_buf.push_str(t),
                    Err(err) => {
                        if strict {
                            yield_err!(FeedParseError {
                                message: format!("invalid CDATA: {err}"),
                            });
                        }
                        tracing::debug!("atom stream CDATA utf8 error (lenient): {err}");
                        text_buf.push_str(&String::from_utf8_lossy(e.as_ref()));
                    }
                },
                Event::End(e) => {
                    depth -= 1;
                    let ns = classify_ns(&rr);
                    let local_name = e.local_name();
                    let local = std::str::from_utf8(local_name.as_ref()).unwrap_or("");
                    let text = std::mem::take(&mut text_buf);

                    if in_author {
                        if ns != Ns::Atom {
                            continue;
                        }
                        match local {
                            "name" => current_author.name = text,
                            "email" => current_author.email = Some(text),
                            "uri" => current_author.uri = Some(text),
                            "author" => {
                                current_entry.authors.push(std::mem::replace(
                                    &mut current_author,
                                    AtomPerson::new(""),
                                ));
                                in_author = false;
                            }
                            _ => {}
                        }
                    } else if in_feed_author {
                        if ns != Ns::Atom {
                            continue;
                        }
                        match local {
                            "name" => current_author.name = text,
                            "email" => current_author.email = Some(text),
                            "uri" => current_author.uri = Some(text),
                            "author" => {
                                header.authors.push(std::mem::replace(
                                    &mut current_author,
                                    AtomPerson::new(""),
                                ));
                                in_feed_author = false;
                            }
                            _ => {}
                        }
                    } else if in_contributor {
                        if ns != Ns::Atom {
                            continue;
                        }
                        match local {
                            "name" => current_contributor.name = text,
                            "email" => current_contributor.email = Some(text),
                            "uri" => current_contributor.uri = Some(text),
                            "contributor" => {
                                current_entry.contributors.push(std::mem::replace(
                                    &mut current_contributor,
                                    AtomPerson::new(""),
                                ));
                                in_contributor = false;
                            }
                            _ => {}
                        }
                    } else if in_feed_contributor {
                        if ns != Ns::Atom {
                            continue;
                        }
                        match local {
                            "name" => current_contributor.name = text,
                            "email" => current_contributor.email = Some(text),
                            "uri" => current_contributor.uri = Some(text),
                            "contributor" => {
                                header.contributors.push(std::mem::replace(
                                    &mut current_contributor,
                                    AtomPerson::new(""),
                                ));
                                in_feed_contributor = false;
                            }
                            _ => {}
                        }
                    } else if in_source {
                        if ns != Ns::Atom {
                            continue;
                        }
                        match local {
                            "id" => current_source.id = Some(text),
                            "title" => {
                                current_source.title =
                                    Some(make_atom_text(&current_title_type, text));
                            }
                            "updated" => current_source.updated = parse_rfc3339_lax(&text),
                            "source" => {
                                current_entry.source = Some(std::mem::replace(
                                    &mut current_source,
                                    AtomSource {
                                        id: None,
                                        title: None,
                                        updated: None,
                                    },
                                ));
                                in_source = false;
                            }
                            _ => {}
                        }
                    } else if in_entry {
                        let Some(text) = entry_acc.on_end(ns, local, text) else {
                            continue;
                        };
                        if ns != Ns::Atom {
                            continue;
                        }
                        match local {
                            "id" => {
                                current_entry.id = text;
                                current_entry_id_set = true;
                            }
                            "title" => {
                                current_entry.title = make_atom_text(&current_title_type, text);
                                current_entry_title_set = true;
                            }
                            "updated" => {
                                if let Some(ts) = parse_rfc3339_lax(&text) {
                                    current_entry.updated = ts;
                                    current_entry_updated_parsed = true;
                                }
                            }
                            "published" => current_entry.published = parse_rfc3339_lax(&text),
                            "summary" => {
                                current_entry.summary =
                                    Some(make_atom_text(&current_summary_type, text));
                            }
                            "content" => {
                                let v = make_atom_text(&current_content_type, text);
                                current_entry.content = Some(AtomContent {
                                    value: v,
                                    src: None,
                                });
                            }
                            "rights" => {
                                current_entry.rights =
                                    Some(make_atom_text(&current_rights_type, text));
                            }
                            "entry" => {
                                if strict
                                    && (!current_entry_id_set
                                        || !current_entry_title_set
                                        || !current_entry_updated_parsed)
                                {
                                    yield_err!(FeedParseError {
                                        message:
                                            "Atom entry missing required <id>/<title>/<updated>"
                                                .to_owned(),
                                    });
                                }
                                current_entry.extensions = std::mem::take(&mut entry_acc).finish();
                                let entry = std::mem::replace(
                                    &mut current_entry,
                                    AtomEntry::new("", AtomText::text(""), Timestamp::UNIX_EPOCH),
                                );
                                in_entry = false;
                                yielder
                                    .yield_item(Ok(AtomReadEvent::Entry(Box::new(entry))))
                                    .await;
                            }
                            _ => {}
                        }
                    } else {
                        let Some(text) = feed_acc.on_end(ns, local, text) else {
                            continue;
                        };
                        if ns != Ns::Atom {
                            continue;
                        }
                        match local {
                            "id" => header.id = text,
                            "title" => {
                                header.title = make_atom_text(&current_title_type, text);
                            }
                            "updated" => {
                                if let Some(ts) = parse_rfc3339_lax(&text) {
                                    header.updated = ts;
                                    feed_updated_parsed = true;
                                }
                            }
                            "subtitle" => {
                                header.subtitle =
                                    Some(make_atom_text(&current_subtitle_type, text));
                            }
                            "rights" => {
                                header.rights = Some(make_atom_text(&current_rights_type, text));
                            }
                            "logo" => header.logo = Some(text),
                            "icon" => header.icon = Some(text),
                            "generator" => {
                                if let Some(mut g) = pending_generator.take() {
                                    g.value = text;
                                    header.generator = Some(g);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Event::Eof => break,
                _ => {}
            }
        }

        if strict && depth > 0 {
            yield_err!(FeedParseError {
                message: format!("truncated Atom document ({depth} unclosed elements at EOF)"),
            });
        }
        if strict {
            if header.id.is_empty() {
                yield_err!(FeedParseError {
                    message: "Atom feed missing required <id>".to_owned(),
                });
            }
            if header.title.value().is_empty() {
                yield_err!(FeedParseError {
                    message: "Atom feed missing required <title>".to_owned(),
                });
            }
            if !feed_updated_parsed {
                yield_err!(FeedParseError {
                    message: "Atom feed missing required <updated>".to_owned(),
                });
            }
        }
        if !saw_root {
            return;
        }

        if !header_yielded {
            let mut h = std::mem::take(&mut header);
            h.extensions = std::mem::take(&mut feed_acc).finish();
            yielder.yield_item(Ok(AtomReadEvent::Feed(h))).await;
        }
        yielder.yield_item(Ok(AtomReadEvent::Eof)).await;
    })
}

fn atom_link_from_attrs(e: &Attrs<'_>) -> AtomLink {
    AtomLink {
        href: attr_value(e, b"href").unwrap_or_default(),
        rel: attr_value(e, b"rel"),
        type_: attr_value(e, b"type"),
        hreflang: attr_value(e, b"hreflang"),
        title: attr_value(e, b"title"),
        length: attr_value(e, b"length").and_then(|v| v.parse().ok()),
    }
}

fn atom_category_from_attrs(e: &Attrs<'_>) -> AtomCategory {
    AtomCategory {
        term: attr_value(e, b"term").unwrap_or_default(),
        scheme: attr_value(e, b"scheme"),
        label: attr_value(e, b"label"),
    }
}

fn make_atom_text(type_attr: &str, value: String) -> AtomText {
    match type_attr {
        "html" | "text/html" => AtomText::Html(value),
        "xhtml" => AtomText::Xhtml(value),
        _ => AtomText::Text(value),
    }
}

fn parse_rfc3339_lax(s: &str) -> Option<Timestamp> {
    s.trim().parse::<Timestamp>().ok()
}

/// Async sibling of `parse::atom1::capture_xhtml_subtree`. Reads events from
/// `nsr` and re-emits Start/End/Empty/Text/CData/Comment into an internal
/// buffer until the matching End of the caller's currently-open element. The
/// first child Start (the wrapping XHTML `<div>` per RFC 4287 §3.1.1.3) and
/// its closing End are dropped so the captured string matches what
/// [`super::super::atom::AtomText::Xhtml`] expects (raw inner markup, which
/// the writer re-wraps in `<div xmlns="…xhtml">`).
async fn capture_xhtml_subtree_async<R>(
    nsr: &mut NsReader<R>,
    buf: &mut Vec<u8>,
) -> Result<String, FeedParseError>
where
    R: AsyncBufRead + Unpin,
{
    use quick_xml::Writer;
    let mut captured = Vec::<u8>::new();
    let mut depth: i32 = 0;
    let mut saw_wrapper = false;
    let mut writer = Writer::new(&mut captured);
    loop {
        buf.clear();
        let (_, ev) =
            nsr.read_resolved_event_into_async(buf)
                .await
                .map_err(|e| FeedParseError {
                    message: format!("xhtml capture: {e}"),
                })?;
        match ev {
            Event::Start(e) => {
                if depth == 0 && !saw_wrapper && e.local_name().as_ref() == b"div" {
                    saw_wrapper = true;
                    depth += 1;
                } else {
                    depth += 1;
                    writer
                        .write_event(Event::Start(e))
                        .map_err(|err| FeedParseError {
                            message: format!("xhtml write: {err}"),
                        })?;
                }
            }
            Event::End(e) => {
                if depth == 0 {
                    drop(writer);
                    return String::from_utf8(captured).map_err(|err| FeedParseError {
                        message: format!("xhtml inner is not utf-8: {err}"),
                    });
                }
                depth -= 1;
                if depth == 0 && saw_wrapper {
                    // closing the wrapper <div> — drop it
                } else {
                    writer
                        .write_event(Event::End(e))
                        .map_err(|err| FeedParseError {
                            message: format!("xhtml write: {err}"),
                        })?;
                }
            }
            Event::Empty(e) => {
                writer
                    .write_event(Event::Empty(e))
                    .map_err(|err| FeedParseError {
                        message: format!("xhtml write: {err}"),
                    })?
            }
            Event::Text(e) => writer
                .write_event(Event::Text(e))
                .map_err(|err| FeedParseError {
                    message: format!("xhtml write: {err}"),
                })?,
            Event::CData(e) => {
                writer
                    .write_event(Event::CData(e))
                    .map_err(|err| FeedParseError {
                        message: format!("xhtml write: {err}"),
                    })?
            }
            Event::Comment(e) => {
                writer
                    .write_event(Event::Comment(e))
                    .map_err(|err| FeedParseError {
                        message: format!("xhtml write: {err}"),
                    })?
            }
            Event::Eof => {
                return Err(FeedParseError {
                    message: "unexpected EOF in xhtml content".to_owned(),
                });
            }
            // DocType / PI / Decl are not legal inside Atom xhtml content; drop.
            _ => {}
        }
    }
}
