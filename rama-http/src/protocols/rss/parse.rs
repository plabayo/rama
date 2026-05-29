//! Lenient (default) and strict RSS 2.0 / Atom 1.0 parsing.
//!
//! The entry points are [`Feed::parse`] (lenient) and [`Feed::parse_strict`]
//! (strict). Lenient parsing silently skips elements it cannot understand;
//! strict parsing returns an error for any structural violation.

use jiff::Timestamp;
use quick_xml::{NsReader, events::Event};
use rama_core::telemetry::tracing;

use super::atom::{
    AtomCategory, AtomContent, AtomEntry, AtomFeed, AtomGenerator, AtomLink, AtomPerson,
    AtomSource, AtomText,
};
use super::ext_parse::{FeedExtAcc, ItemExtAcc, Ns, classify_ns};
use super::feed::Feed;
use super::rss2::{
    Rss2Category, Rss2Enclosure, Rss2Feed, Rss2Guid, Rss2Image, Rss2Item, Rss2Source,
};

// ---------------------------------------------------------------------------
// Public error type
// ---------------------------------------------------------------------------

/// Returned by strict-mode parsing when the document structure is invalid.
#[derive(Debug, Clone, PartialEq)]
pub struct FeedParseError {
    pub message: String,
}

impl FeedParseError {
    fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }
}

impl std::fmt::Display for FeedParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "feed parse error: {}", self.message)
    }
}

impl std::error::Error for FeedParseError {}

// ---------------------------------------------------------------------------
// Parse entry points
// ---------------------------------------------------------------------------

pub(super) fn parse_feed(input: &str, strict: bool) -> Result<Feed, FeedParseError> {
    // Quick sniff for format detection before full parse.
    let trimmed = input.trim_start();
    let is_atom = detect_atom(trimmed);
    let is_rss = !is_atom && detect_rss(trimmed);

    // Each parser reports whether it actually saw a recognized root element
    // (`<rss>`/`<channel>` or `<feed>`); without one the input is not a feed,
    // so even lenient parsing returns an error rather than an empty feed.
    if is_atom {
        let (feed, saw_root) = parse_atom(input, strict)?;
        if saw_root {
            return Ok(Feed::Atom(feed));
        }
    } else if is_rss {
        let (feed, saw_root) = parse_rss2(input, strict)?;
        if saw_root {
            return Ok(Feed::Rss2(feed));
        }
    }

    if strict {
        return Err(FeedParseError::new(
            "document is neither RSS 2.0 nor Atom 1.0",
        ));
    }

    // Lenient fallback: accept only if a recognized feed root is present.
    if let Ok((feed, true)) = parse_rss2(input, false) {
        return Ok(Feed::Rss2(feed));
    }
    if let Ok((feed, true)) = parse_atom(input, false) {
        return Ok(Feed::Atom(feed));
    }
    Err(FeedParseError::new("unrecognized feed format"))
}

fn detect_atom(s: &str) -> bool {
    // Either the Atom namespace URI is declared (any prefix), or a bare
    // `<feed>` element is present. Looking for the URI alone catches prefixed
    // roots like `<a:feed xmlns:a="http://www.w3.org/2005/Atom">`.
    let probe = probe_prefix(s, 2048);
    probe.contains("w3.org/2005/Atom") || probe.contains("<feed>") || probe.contains("<feed ")
}

fn detect_rss(s: &str) -> bool {
    let probe = probe_prefix(s, 1024);
    probe.contains("<rss") || probe.contains("<channel")
}

/// Largest prefix of `s` no longer than `max` bytes, never splitting a
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

// ---------------------------------------------------------------------------
// RSS 2.0 parser
// ---------------------------------------------------------------------------

fn parse_rss2(input: &str, strict: bool) -> Result<(Rss2Feed, bool), FeedParseError> {
    let mut reader = NsReader::from_str(input);
    reader.config_mut().trim_text(true);

    let mut saw_root = false;

    // Channel state
    let mut title = String::new();
    let mut link = String::new();
    let mut description = String::new();
    let mut language: Option<String> = None;
    let mut copyright: Option<String> = None;
    let mut managing_editor: Option<String> = None;
    let mut web_master: Option<String> = None;
    let mut pub_date: Option<Timestamp> = None;
    let mut last_build_date: Option<Timestamp> = None;
    let mut generator: Option<String> = None;
    let mut docs: Option<String> = None;
    let mut ttl: Option<u32> = None;
    let mut categories: Vec<Rss2Category> = Vec::new();
    let mut image: Option<Rss2Image> = None;
    let mut image_url = String::new();
    let mut image_title = String::new();
    let mut image_link = String::new();
    let mut image_width: Option<u32> = None;
    let mut image_height: Option<u32> = None;
    let mut image_description: Option<String> = None;
    let mut items: Vec<Rss2Item> = Vec::new();
    let mut atom_links: Vec<AtomLink> = Vec::new();
    let mut feed_acc = FeedExtAcc::default();

    // Item state
    let mut in_item = false;
    let mut in_image_block = false;
    let mut current_item = Rss2Item::default();
    let mut item_acc = ItemExtAcc::default();

    // Pending `<category domain="..">name</category>` domain attribute and
    // `<source url="..">title</source>` url attribute.
    let mut pending_category_domain: Option<String> = None;
    let mut pending_source_url: Option<String> = None;

    let mut text_buf = String::new();
    // Tracks `<x>` minus `</x>` so we can flag truncated documents at EOF.
    let mut depth: i32 = 0;

    loop {
        match reader.read_resolved_event() {
            Ok((rr, Event::Start(e))) => {
                depth += 1;
                let ns = classify_ns(&rr);
                let local_name = e.local_name();
                let local = std::str::from_utf8(local_name.as_ref()).unwrap_or("");
                text_buf.clear();
                let consumed = if in_item {
                    item_acc.on_start(ns, local, &e)
                } else {
                    feed_acc.on_start(ns, local, &e)
                };
                if !consumed && !in_item && ns == Ns::Atom && local == "link" {
                    // Channel-level `<atom:link>` (commonly `rel="self"`).
                    atom_links.push(atom_link_from_attrs(&e));
                    continue;
                }
                if !consumed && ns == Ns::None {
                    match local {
                        "rss" | "channel" => saw_root = true,
                        "item" => {
                            if in_item {
                                // Malformed input nested another `<item>`
                                // inside the current one. Flush what we have
                                // so the outer item isn't silently clobbered;
                                // the outer's `</item>` will then no-op below.
                                current_item.extensions = std::mem::take(&mut item_acc).finish();
                                items.push(std::mem::take(&mut current_item));
                            }
                            in_item = true;
                            current_item = Rss2Item::default();
                            item_acc = ItemExtAcc::default();
                        }
                        "image" if !in_item => in_image_block = true,
                        "enclosure" if in_item => {
                            current_item.enclosures.push(enclosure_from_attrs(&e));
                        }
                        "guid" if in_item => {
                            let permalink = attr_value(&e, b"isPermaLink")
                                .map(|v| v != "false")
                                .unwrap_or(true);
                            // value is captured later on the text event
                            current_item.guid = Some(Rss2Guid {
                                value: String::new(),
                                permalink,
                            });
                        }
                        "source" if in_item => pending_source_url = attr_value(&e, b"url"),
                        "category" => pending_category_domain = attr_value(&e, b"domain"),
                        _ => {}
                    }
                }
            }
            Ok((rr, Event::Empty(e))) => {
                let ns = classify_ns(&rr);
                let local_name = e.local_name();
                let local = std::str::from_utf8(local_name.as_ref()).unwrap_or("");
                let consumed = if in_item {
                    item_acc.on_empty(ns, local, &e)
                } else {
                    feed_acc.on_empty(ns, local, &e)
                };
                if consumed {
                    continue;
                }
                if !in_item && ns == Ns::Atom && local == "link" {
                    // Channel-level `<atom:link/>`.
                    atom_links.push(atom_link_from_attrs(&e));
                    continue;
                }
                if ns == Ns::None && in_item && local == "enclosure" {
                    current_item.enclosures.push(enclosure_from_attrs(&e));
                }
            }
            Ok((_, Event::Text(e))) => match e.unescape() {
                Ok(t) => text_buf.push_str(&t),
                Err(err) => {
                    if strict {
                        return Err(FeedParseError::new(format!("invalid text content: {err}")));
                    }
                    // Preserve the raw bytes in lenient mode rather than
                    // silently dropping the entire chunk: a stray entity in a
                    // wild feed shouldn't erase the surrounding visible text.
                    tracing::debug!("rss2 unescape error (lenient): {err}");
                    text_buf.push_str(&String::from_utf8_lossy(e.as_ref()));
                }
            },
            Ok((_, Event::CData(e))) => match std::str::from_utf8(e.as_ref()) {
                Ok(t) => text_buf.push_str(t),
                Err(err) => {
                    if strict {
                        return Err(FeedParseError::new(format!("invalid CDATA: {err}")));
                    }
                    tracing::debug!("rss2 CDATA utf8 error (lenient): {err}");
                    text_buf.push_str(&String::from_utf8_lossy(e.as_ref()));
                }
            },
            Ok((rr, Event::End(e))) => {
                depth -= 1;
                let ns = classify_ns(&rr);
                let local_name = e.local_name();
                let local = std::str::from_utf8(local_name.as_ref()).unwrap_or("");
                let text = std::mem::take(&mut text_buf);

                if in_item {
                    let Some(text) = item_acc.on_end(ns, local, text) else {
                        continue;
                    };
                    if ns == Ns::None {
                        match local {
                            "title" => current_item.title = Some(text),
                            "link" => current_item.link = Some(text),
                            "description" => current_item.description = Some(text),
                            "author" => current_item.author = Some(text),
                            "comments" => current_item.comments = Some(text),
                            "pubDate" => current_item.pub_date = parse_rss2_date(&text),
                            "guid" => {
                                if let Some(guid) = &mut current_item.guid {
                                    guid.value = text;
                                }
                            }
                            "category" => current_item.categories.push(Rss2Category {
                                name: text,
                                domain: pending_category_domain.take(),
                            }),
                            "source" => {
                                current_item.source = Some(Rss2Source {
                                    title: text,
                                    url: pending_source_url.take().unwrap_or_default(),
                                });
                            }
                            "item" => {
                                current_item.extensions = std::mem::take(&mut item_acc).finish();
                                items.push(std::mem::take(&mut current_item));
                                in_item = false;
                            }
                            _ => {}
                        }
                    }
                } else if in_image_block {
                    if ns == Ns::None {
                        match local {
                            "url" => image_url = text,
                            "title" => image_title = text,
                            "link" => image_link = text,
                            "width" => image_width = text.parse().ok(),
                            "height" => image_height = text.parse().ok(),
                            "description" => image_description = Some(text),
                            "image" => {
                                in_image_block = false;
                                image = Some(Rss2Image {
                                    url: std::mem::take(&mut image_url),
                                    title: std::mem::take(&mut image_title),
                                    link: std::mem::take(&mut image_link),
                                    width: image_width.take(),
                                    height: image_height.take(),
                                    description: image_description.take(),
                                });
                            }
                            _ => {}
                        }
                    }
                } else {
                    let Some(text) = feed_acc.on_end(ns, local, text) else {
                        continue;
                    };
                    if ns == Ns::None {
                        match local {
                            "title" => title = text,
                            "link" => link = text,
                            "description" => description = text,
                            "language" => language = Some(text),
                            "copyright" => copyright = Some(text),
                            "managingEditor" => managing_editor = Some(text),
                            "webMaster" => web_master = Some(text),
                            "pubDate" => pub_date = parse_rss2_date(&text),
                            "lastBuildDate" => last_build_date = parse_rss2_date(&text),
                            "generator" => generator = Some(text),
                            "ttl" => ttl = text.parse().ok(),
                            "docs" => docs = Some(text),
                            "category" => categories.push(Rss2Category {
                                name: text,
                                domain: pending_category_domain.take(),
                            }),
                            _ => {}
                        }
                    }
                }
            }
            Ok((_, Event::Eof)) => {
                if depth > 0 {
                    return Err(FeedParseError::new(format!(
                        "truncated feed: {depth} unclosed element(s) at end of input"
                    )));
                }
                break;
            }
            Err(e) => {
                // Surface XML errors in both modes. Lenient is a stance on
                // unknown / unrecognised elements, not on broken documents:
                // silently truncating a mid-stream cut would let callers
                // mistake "TCP cut" for "feed empty".
                tracing::debug!("rss2 parse xml error: {e}");
                return Err(FeedParseError::new(format!("xml error: {e}")));
            }
            _ => {}
        }
    }

    if strict && title.is_empty() {
        return Err(FeedParseError::new(
            "RSS 2.0 channel missing required <title>",
        ));
    }
    if strict && link.is_empty() {
        return Err(FeedParseError::new(
            "RSS 2.0 channel missing required <link>",
        ));
    }

    Ok((
        Rss2Feed {
            title,
            link,
            description,
            language,
            copyright,
            managing_editor,
            web_master,
            pub_date,
            last_build_date,
            categories,
            generator,
            docs,
            ttl,
            image,
            atom_links,
            items,
            extensions: feed_acc.finish(),
        },
        saw_root,
    ))
}

/// Consume events until the matching End of the caller's currently-open
/// element, returning the inner XML as a `String`. Used by the Atom parser to
/// capture `type="xhtml"` text constructs, which are subtrees rather than
/// flat text.
///
/// Per RFC 4287 §3.1.1.3 the inner content is wrapped in a single XHTML-
/// namespaced `<div>`; if the very first child Start is a `<div>` we drop its
/// open/close tags from the captured output so callers can write it back
/// through the standard xhtml writer (which adds the wrapping div again).
/// In lenient mode we accept a missing wrapper too.
fn capture_xhtml_subtree(reader: &mut NsReader<&[u8]>) -> Result<String, FeedParseError> {
    let mut captured = Vec::<u8>::new();
    let mut depth: i32 = 0;
    let mut saw_wrapper = false;
    {
        let mut writer = quick_xml::Writer::new(&mut captured);
        loop {
            let ev = reader
                .read_resolved_event()
                .map_err(|e| FeedParseError::new(format!("xhtml capture: {e}")))?;
            match ev {
                (_, Event::Start(e)) => {
                    if depth == 0 && !saw_wrapper && e.local_name().as_ref() == b"div" {
                        // wrapping XHTML <div> — don't emit, just enter
                        saw_wrapper = true;
                        depth += 1;
                    } else {
                        depth += 1;
                        writer
                            .write_event(Event::Start(e))
                            .map_err(|e| FeedParseError::new(format!("xhtml write: {e}")))?;
                    }
                }
                (_, Event::End(e)) => {
                    if depth == 0 {
                        // End of the outer element — done.
                        return String::from_utf8(captured).map_err(|err| {
                            FeedParseError::new(format!("xhtml inner is not utf-8: {err}"))
                        });
                    }
                    depth -= 1;
                    if depth == 0 && saw_wrapper {
                        // closing the wrapper div — skip it
                    } else {
                        writer
                            .write_event(Event::End(e))
                            .map_err(|err| FeedParseError::new(format!("xhtml write: {err}")))?;
                    }
                }
                (_, Event::Empty(e)) => writer
                    .write_event(Event::Empty(e))
                    .map_err(|err| FeedParseError::new(format!("xhtml write: {err}")))?,
                (_, Event::Text(e)) => writer
                    .write_event(Event::Text(e))
                    .map_err(|err| FeedParseError::new(format!("xhtml write: {err}")))?,
                (_, Event::CData(e)) => writer
                    .write_event(Event::CData(e))
                    .map_err(|err| FeedParseError::new(format!("xhtml write: {err}")))?,
                (_, Event::Comment(e)) => writer
                    .write_event(Event::Comment(e))
                    .map_err(|err| FeedParseError::new(format!("xhtml write: {err}")))?,
                (_, Event::Eof) => {
                    return Err(FeedParseError::new("unexpected EOF in xhtml content"));
                }
                // Drop document-level constructs (DOCTYPE / PI / Decl) — these
                // are not legal inside Atom xhtml content.
                _ => {}
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Atom parser
// ---------------------------------------------------------------------------

fn parse_atom(input: &str, strict: bool) -> Result<(AtomFeed, bool), FeedParseError> {
    let mut reader = NsReader::from_str(input);
    reader.config_mut().trim_text(true);

    let mut saw_root = false;

    // Feed state
    let mut feed_id = String::new();
    let mut feed_title = AtomText::text("");
    let mut feed_updated = Timestamp::UNIX_EPOCH;
    // True iff `<updated>` was seen *and* parsed as a valid RFC 3339 timestamp.
    // Used by strict mode to reject both missing and unparseable values.
    let mut feed_updated_parsed = false;
    let mut feed_authors: Vec<AtomPerson> = Vec::new();
    let mut feed_contributors: Vec<AtomPerson> = Vec::new();
    let mut feed_links: Vec<AtomLink> = Vec::new();
    let mut feed_categories: Vec<AtomCategory> = Vec::new();
    let mut feed_generator: Option<AtomGenerator> = None;
    let mut feed_icon: Option<String> = None;
    let mut feed_logo: Option<String> = None;
    let mut feed_rights: Option<AtomText> = None;
    let mut feed_subtitle: Option<AtomText> = None;
    let mut entries: Vec<AtomEntry> = Vec::new();
    let mut feed_acc = FeedExtAcc::default();

    // Entry state
    let mut in_entry = false;
    let mut in_author = false;
    let mut in_feed_author = false;
    let mut in_contributor = false;
    let mut in_feed_contributor = false;
    let mut in_source = false;
    let mut current_entry_id = String::new();
    let mut current_entry_id_set = false;
    let mut current_entry_title = AtomText::text("");
    let mut current_entry_title_set = false;
    let mut current_entry_updated = Timestamp::UNIX_EPOCH;
    let mut current_entry_updated_parsed = false;
    let mut current_entry_authors: Vec<AtomPerson> = Vec::new();
    let mut current_entry_contributors: Vec<AtomPerson> = Vec::new();
    let mut current_entry_links: Vec<AtomLink> = Vec::new();
    let mut current_entry_categories: Vec<AtomCategory> = Vec::new();
    let mut current_entry_summary: Option<AtomText> = None;
    let mut current_entry_content: Option<AtomContent> = None;
    let mut current_entry_published: Option<Timestamp> = None;
    let mut current_entry_rights: Option<AtomText> = None;
    let mut current_entry_source: Option<AtomSource> = None;
    let mut entry_acc = ItemExtAcc::default();

    // Shared sub-element state
    let mut current_author = AtomPerson::new("");
    let mut current_contributor = AtomPerson::new("");
    let mut current_source = AtomSource {
        id: None,
        title: None,
        updated: None,
    };
    let mut pending_generator: Option<AtomGenerator> = None;
    let mut current_content_type = String::from("text");
    let mut current_title_type = String::from("text");
    let mut current_summary_type = String::from("text");
    let mut current_subtitle_type = String::from("text");
    let mut current_rights_type = String::from("text");

    let mut text_buf = String::new();
    // Tracks `<x>` minus `</x>` so we can flag truncated documents at EOF.
    let mut depth: i32 = 0;

    loop {
        match reader.read_resolved_event() {
            Ok((rr, Event::Start(e))) => {
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

                // Typed-text elements (RFC 4287 §3.1) with type="xhtml" are
                // *subtrees*, not flat text. Capture the inner markup here so
                // we don't lose it in the text-accumulator path. The capture
                // also consumes the matching End event, so the normal End
                // handler never sees this element.
                if matches!(
                    local,
                    "title" | "summary" | "content" | "rights" | "subtitle"
                ) && attr_value(&e, b"type").as_deref() == Some("xhtml")
                {
                    let which = local.to_owned();
                    let scope_in_entry = in_entry;
                    let scope_in_source = in_source;
                    drop(e);
                    drop(rr);
                    let xhtml_inner = capture_xhtml_subtree(&mut reader)?;
                    // capture_xhtml_subtree consumed the outer End event too,
                    // so balance the depth counter for it (we already
                    // incremented for the outer Start above).
                    depth -= 1;
                    let value = AtomText::Xhtml(xhtml_inner);
                    match (which.as_str(), scope_in_source, scope_in_entry) {
                        ("title", true, _) => current_source.title = Some(value),
                        ("title", false, true) => {
                            current_entry_title = value;
                            current_entry_title_set = true;
                        }
                        ("title", false, false) => feed_title = value,
                        ("summary", _, true) => current_entry_summary = Some(value),
                        ("content", _, true) => {
                            current_entry_content = Some(AtomContent { value, src: None });
                        }
                        ("rights", _, true) => current_entry_rights = Some(value),
                        ("rights", _, false) => feed_rights = Some(value),
                        ("subtitle", _, false) => feed_subtitle = Some(value),
                        _ => {}
                    }
                    continue;
                }

                match local {
                    "feed" => saw_root = true,
                    "entry" => {
                        in_entry = true;
                        current_entry_id = String::new();
                        current_entry_id_set = false;
                        current_entry_title = AtomText::text("");
                        current_entry_title_set = false;
                        current_entry_updated = Timestamp::UNIX_EPOCH;
                        current_entry_updated_parsed = false;
                        current_entry_authors = Vec::new();
                        current_entry_contributors = Vec::new();
                        current_entry_links = Vec::new();
                        current_entry_categories = Vec::new();
                        current_entry_summary = None;
                        current_entry_content = None;
                        current_entry_published = None;
                        current_entry_rights = None;
                        current_entry_source = None;
                        entry_acc = ItemExtAcc::default();
                    }
                    // RFC 4287 §4.2.11: `<source>` carries the entry's
                    // *origin* feed's metadata. Its child elements must not
                    // leak into the enclosing entry's collections — anything
                    // we don't model (author/contributor/link/category/etc.)
                    // is dropped while `in_source`.
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
                            current_entry_links.push(link);
                        } else {
                            feed_links.push(link);
                        }
                    }
                    "category" if !in_source => {
                        let cat = atom_category_from_attrs(&e);
                        if in_entry {
                            current_entry_categories.push(cat);
                        } else {
                            feed_categories.push(cat);
                        }
                    }
                    "title" => {
                        current_title_type =
                            attr_value(&e, b"type").unwrap_or_else(|| "text".into());
                    }
                    "summary" => {
                        current_summary_type =
                            attr_value(&e, b"type").unwrap_or_else(|| "text".into());
                    }
                    "content" => {
                        current_content_type =
                            attr_value(&e, b"type").unwrap_or_else(|| "text".into());
                    }
                    "subtitle" => {
                        current_subtitle_type =
                            attr_value(&e, b"type").unwrap_or_else(|| "text".into());
                    }
                    "rights" => {
                        current_rights_type =
                            attr_value(&e, b"type").unwrap_or_else(|| "text".into());
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
            Ok((rr, Event::Empty(e))) => {
                let ns = classify_ns(&rr);
                let local_name = e.local_name();
                let local = std::str::from_utf8(local_name.as_ref()).unwrap_or("");

                let consumed = if in_entry {
                    entry_acc.on_empty(ns, local, &e)
                } else {
                    feed_acc.on_empty(ns, local, &e)
                };
                if consumed {
                    continue;
                }

                if ns != Ns::Atom {
                    continue;
                }
                match local {
                    "link" if !in_source => {
                        let link = atom_link_from_attrs(&e);
                        if in_entry {
                            current_entry_links.push(link);
                        } else {
                            feed_links.push(link);
                        }
                    }
                    "category" if !in_source => {
                        let cat = atom_category_from_attrs(&e);
                        if in_entry {
                            current_entry_categories.push(cat);
                        } else {
                            feed_categories.push(cat);
                        }
                    }
                    "content" if in_entry && !in_source => {
                        // Out-of-line content: <content src=".." type=".."/>
                        if let Some(src) = attr_value(&e, b"src") {
                            let type_ = attr_value(&e, b"type").unwrap_or_else(|| "text".into());
                            current_entry_content = Some(AtomContent {
                                value: AtomText::Text(type_),
                                src: Some(src),
                            });
                        }
                    }
                    _ => {}
                }
            }
            Ok((_, Event::Text(e))) => match e.unescape() {
                Ok(t) => text_buf.push_str(&t),
                Err(err) => {
                    if strict {
                        return Err(FeedParseError::new(format!("invalid text content: {err}")));
                    }
                    // See parse_rss2's matching branch — preserve raw bytes so
                    // surrounding text isn't lost to a stray entity.
                    tracing::debug!("atom unescape error (lenient): {err}");
                    text_buf.push_str(&String::from_utf8_lossy(e.as_ref()));
                }
            },
            Ok((_, Event::CData(e))) => match std::str::from_utf8(e.as_ref()) {
                Ok(t) => text_buf.push_str(t),
                Err(err) => {
                    if strict {
                        return Err(FeedParseError::new(format!("invalid CDATA: {err}")));
                    }
                    tracing::debug!("atom CDATA utf8 error (lenient): {err}");
                    text_buf.push_str(&String::from_utf8_lossy(e.as_ref()));
                }
            },
            Ok((rr, Event::End(e))) => {
                depth -= 1;
                let ns = classify_ns(&rr);
                let local_name = e.local_name();
                let local = std::str::from_utf8(local_name.as_ref()).unwrap_or("");
                let text = std::mem::take(&mut text_buf);

                if in_author && ns == Ns::Atom {
                    match local {
                        "name" => current_author.name = text,
                        "email" => current_author.email = Some(text),
                        "uri" => current_author.uri = Some(text),
                        "author" => {
                            current_entry_authors
                                .push(std::mem::replace(&mut current_author, AtomPerson::new("")));
                            in_author = false;
                        }
                        _ => {}
                    }
                } else if in_feed_author && ns == Ns::Atom {
                    match local {
                        "name" => current_author.name = text,
                        "email" => current_author.email = Some(text),
                        "uri" => current_author.uri = Some(text),
                        "author" => {
                            feed_authors
                                .push(std::mem::replace(&mut current_author, AtomPerson::new("")));
                            in_feed_author = false;
                        }
                        _ => {}
                    }
                } else if in_contributor && ns == Ns::Atom {
                    match local {
                        "name" => current_contributor.name = text,
                        "email" => current_contributor.email = Some(text),
                        "uri" => current_contributor.uri = Some(text),
                        "contributor" => {
                            current_entry_contributors.push(std::mem::replace(
                                &mut current_contributor,
                                AtomPerson::new(""),
                            ));
                            in_contributor = false;
                        }
                        _ => {}
                    }
                } else if in_feed_contributor && ns == Ns::Atom {
                    match local {
                        "name" => current_contributor.name = text,
                        "email" => current_contributor.email = Some(text),
                        "uri" => current_contributor.uri = Some(text),
                        "contributor" => {
                            feed_contributors.push(std::mem::replace(
                                &mut current_contributor,
                                AtomPerson::new(""),
                            ));
                            in_feed_contributor = false;
                        }
                        _ => {}
                    }
                } else if in_source && ns == Ns::Atom {
                    match local {
                        "id" => current_source.id = Some(text),
                        "title" => {
                            current_source.title = Some(make_atom_text(&current_title_type, text));
                        }
                        "updated" => current_source.updated = parse_rfc3339_lax(&text),
                        "source" => {
                            current_entry_source = Some(std::mem::replace(
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
                            current_entry_id = text;
                            current_entry_id_set = true;
                        }
                        "title" => {
                            current_entry_title = make_atom_text(&current_title_type, text);
                            current_entry_title_set = true;
                        }
                        "updated" => {
                            if let Some(ts) = parse_rfc3339_lax(&text) {
                                current_entry_updated = ts;
                                current_entry_updated_parsed = true;
                            }
                        }
                        "published" => current_entry_published = parse_rfc3339_lax(&text),
                        "summary" => {
                            current_entry_summary =
                                Some(make_atom_text(&current_summary_type, text));
                        }
                        "content" => {
                            let at = make_atom_text(&current_content_type, text);
                            current_entry_content = Some(AtomContent {
                                value: at,
                                src: None,
                            });
                        }
                        "rights" => {
                            current_entry_rights = Some(make_atom_text(&current_rights_type, text));
                        }
                        "entry" => {
                            if strict {
                                if !current_entry_id_set || current_entry_id.is_empty() {
                                    return Err(FeedParseError::new(
                                        "Atom entry missing required <id>",
                                    ));
                                }
                                if !current_entry_title_set {
                                    return Err(FeedParseError::new(
                                        "Atom entry missing required <title>",
                                    ));
                                }
                                if !current_entry_updated_parsed {
                                    return Err(FeedParseError::new(
                                        "Atom entry missing or unparseable <updated>",
                                    ));
                                }
                            }
                            let entry = AtomEntry {
                                id: std::mem::take(&mut current_entry_id),
                                title: std::mem::replace(
                                    &mut current_entry_title,
                                    AtomText::text(""),
                                ),
                                updated: current_entry_updated,
                                authors: std::mem::take(&mut current_entry_authors),
                                content: current_entry_content.take(),
                                links: std::mem::take(&mut current_entry_links),
                                summary: current_entry_summary.take(),
                                categories: std::mem::take(&mut current_entry_categories),
                                contributors: std::mem::take(&mut current_entry_contributors),
                                published: current_entry_published.take(),
                                rights: current_entry_rights.take(),
                                source: current_entry_source.take(),
                                extensions: std::mem::take(&mut entry_acc).finish(),
                            };
                            entries.push(entry);
                            in_entry = false;
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
                        "id" => feed_id = text,
                        "title" => {
                            feed_title = make_atom_text(&current_title_type, text);
                        }
                        "updated" => {
                            if let Some(ts) = parse_rfc3339_lax(&text) {
                                feed_updated = ts;
                                feed_updated_parsed = true;
                            }
                        }
                        "subtitle" => {
                            feed_subtitle = Some(make_atom_text(&current_subtitle_type, text));
                        }
                        "rights" => {
                            feed_rights = Some(make_atom_text(&current_rights_type, text));
                        }
                        "logo" => feed_logo = Some(text),
                        "icon" => feed_icon = Some(text),
                        "generator" => {
                            if let Some(mut g) = pending_generator.take() {
                                g.value = text;
                                feed_generator = Some(g);
                            }
                        }
                        _ => {}
                    }
                }
            }
            Ok((_, Event::Eof)) => {
                if depth > 0 {
                    return Err(FeedParseError::new(format!(
                        "truncated feed: {depth} unclosed element(s) at end of input"
                    )));
                }
                break;
            }
            Err(e) => {
                // See parse_rss2: XML errors are surfaced in both modes so a
                // truncated document doesn't masquerade as a successful parse.
                tracing::debug!("atom parse xml error: {e}");
                return Err(FeedParseError::new(format!("xml error: {e}")));
            }
            _ => {}
        }
    }

    if strict {
        if feed_id.is_empty() {
            return Err(FeedParseError::new("Atom feed missing required <id>"));
        }
        if feed_title.value().is_empty() {
            return Err(FeedParseError::new("Atom feed missing required <title>"));
        }
        if !feed_updated_parsed {
            return Err(FeedParseError::new(
                "Atom feed missing or unparseable <updated>",
            ));
        }
    }

    Ok((
        AtomFeed {
            id: feed_id,
            title: feed_title,
            updated: feed_updated,
            authors: feed_authors,
            links: feed_links,
            categories: feed_categories,
            contributors: feed_contributors,
            generator: feed_generator,
            icon: feed_icon,
            logo: feed_logo,
            rights: feed_rights,
            subtitle: feed_subtitle,
            entries,
            extensions: feed_acc.finish(),
        },
        saw_root,
    ))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read an attribute by qualified name and XML-unescape its value. Returns
/// `None` if absent, malformed, or carrying an unresolvable entity — the caller
/// treats that the same as "missing".
pub(super) fn attr_value(e: &quick_xml::events::BytesStart<'_>, name: &[u8]) -> Option<String> {
    e.attributes()
        .filter_map(|a| a.ok())
        .find(|a| a.key.as_ref() == name)
        .and_then(|a| a.unescape_value().ok().map(|v| v.into_owned()))
}

pub(super) fn parse_rss2_date(s: &str) -> Option<Timestamp> {
    use jiff::fmt::rfc2822;
    let s = s.trim();
    rfc2822::parse(s)
        .ok()
        .map(|zdt| zdt.timestamp())
        .or_else(|| parse_rfc3339_lax(s))
}

pub(super) type Attrs<'a> = quick_xml::events::BytesStart<'a>;

fn enclosure_from_attrs(e: &Attrs<'_>) -> Rss2Enclosure {
    Rss2Enclosure {
        url: attr_value(e, b"url").unwrap_or_default(),
        length: attr_value(e, b"length")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or_default(),
        type_: attr_value(e, b"type").unwrap_or_default(),
    }
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

fn parse_rfc3339_lax(s: &str) -> Option<Timestamp> {
    s.trim().parse::<Timestamp>().ok()
}

fn make_atom_text(type_attr: &str, value: String) -> AtomText {
    match type_attr {
        "html" | "text/html" => AtomText::Html(value),
        "xhtml" => AtomText::Xhtml(value),
        _ => AtomText::Text(value),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_RSS2: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>My Blog</title>
    <link>https://example.com</link>
    <description>A sample blog</description>
    <language>en</language>
    <item>
      <title>First Post</title>
      <link>https://example.com/1</link>
      <description>Hello world</description>
      <guid isPermaLink="true">https://example.com/1</guid>
    </item>
  </channel>
</rss>"#;

    const SAMPLE_ATOM: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>https://example.com/feed</id>
  <title type="text">My Blog</title>
  <updated>2024-01-15T00:00:00Z</updated>
  <author><name>Alice</name></author>
  <entry>
    <id>https://example.com/1</id>
    <title type="text">First Post</title>
    <updated>2024-01-15T00:00:00Z</updated>
    <summary>Hello world</summary>
  </entry>
</feed>"#;

    #[test]
    fn detects_and_parses_rss2() {
        let feed = parse_feed(SAMPLE_RSS2, false).unwrap();
        let Feed::Rss2(rss) = feed else {
            panic!("expected RSS 2.0")
        };
        assert_eq!(rss.title, "My Blog");
        assert_eq!(rss.link, "https://example.com");
        assert_eq!(rss.items.len(), 1);
        assert_eq!(rss.items[0].title.as_deref(), Some("First Post"));
    }

    #[test]
    fn detects_and_parses_atom() {
        let feed = parse_feed(SAMPLE_ATOM, false).unwrap();
        let Feed::Atom(atom) = feed else {
            panic!("expected Atom")
        };
        assert_eq!(atom.id, "https://example.com/feed");
        assert_eq!(atom.entries.len(), 1);
        assert_eq!(atom.entries[0].id, "https://example.com/1");
    }

    #[test]
    fn strict_errors_on_missing_rss2_required_fields() {
        parse_feed(
            "<rss><channel><description>x</description></channel></rss>",
            true,
        )
        .unwrap_err();
    }

    #[test]
    fn parse_does_not_panic_on_utf8_boundary() {
        // Regression: format detection used to byte-slice at index 2048/1024,
        // panicking when that index fell inside a multi-byte UTF-8 char.
        let mut s = String::from("<?xml version=\"1.0\"?>\n");
        while s.len() < 2047 {
            s.push('a');
        }
        s.push('€'); // 3 bytes spanning index 2047..2050
        while s.len() < 4096 {
            s.push('b');
        }
        _ = parse_feed(&s, false);
        _ = parse_feed(&s, true);
    }

    #[test]
    fn rss2_parses_channel_image() {
        let xml = r#"<rss version="2.0"><channel>
            <title>T</title><link>https://e.com</link><description>D</description>
            <image>
                <url>https://e.com/i.png</url>
                <title>Logo</title>
                <link>https://e.com</link>
                <width>88</width>
            </image>
        </channel></rss>"#;
        let Feed::Rss2(rss) = parse_feed(xml, false).unwrap() else {
            panic!("expected RSS 2.0")
        };
        let img = rss.image.expect("channel image should be parsed");
        assert_eq!(img.url, "https://e.com/i.png");
        assert_eq!(img.title, "Logo");
        assert_eq!(img.width, Some(88));
        // the image's inner <title>/<link> must not clobber the channel's
        assert_eq!(rss.title, "T");
    }

    #[test]
    fn atom_strict_requires_id_title_updated() {
        // missing <updated>
        parse_feed(
            r#"<feed xmlns="http://www.w3.org/2005/Atom"><id>urn:f</id><title>T</title></feed>"#,
            true,
        )
        .unwrap_err();
        // missing <title>
        parse_feed(
            r#"<feed xmlns="http://www.w3.org/2005/Atom"><id>urn:f</id><updated>2024-01-01T00:00:00Z</updated></feed>"#,
            true,
        )
        .unwrap_err();
        // all present -> ok
        parse_feed(
            r#"<feed xmlns="http://www.w3.org/2005/Atom"><id>urn:f</id><title>T</title><updated>2024-01-01T00:00:00Z</updated></feed>"#,
            true,
        )
        .unwrap();
    }

    #[test]
    fn atom_parses_entry_category_and_typed_summary() {
        let xml = r#"<feed xmlns="http://www.w3.org/2005/Atom">
            <id>urn:f</id><title>T</title><updated>2024-01-01T00:00:00Z</updated>
            <entry>
                <id>urn:1</id><title>E</title><updated>2024-01-01T00:00:00Z</updated>
                <category term="rust" label="Rust"/>
                <summary type="html">&lt;b&gt;hi&lt;/b&gt;</summary>
            </entry>
        </feed>"#;
        let Feed::Atom(atom) = parse_feed(xml, false).unwrap() else {
            panic!("expected Atom")
        };
        let entry = &atom.entries[0];
        assert_eq!(entry.categories.len(), 1, "entry category should be parsed");
        assert_eq!(entry.categories[0].term, "rust");
        assert!(matches!(entry.summary, Some(AtomText::Html(_))));
    }

    #[test]
    fn rss2_extensions_round_trip() {
        use super::super::feed_ext::{
            Content, DublinCore, DublinCoreFeed, FeedExtensions, ITunes, ITunesFeed,
            ItemExtensions, MediaContent, MediaRss, MediaThumbnail, Podcast, PodcastEpisode,
            PodcastFeed, PodcastFunding, PodcastPerson, PodcastSeason, PodcastSoundbite,
            PodcastTranscript,
        };

        let feed = Rss2Feed::builder()
            .title("Pod")
            .link("https://e.com")
            .description("D")
            .feed_extensions(FeedExtensions {
                itunes: Some(ITunesFeed {
                    author: Some("Host".into()),
                    owner_name: Some("Owner".into()),
                    owner_email: Some("o@e.com".into()),
                    new_feed_url: Some("https://e.com/new".into()),
                    block: Some(true),
                    complete: Some(false),
                    categories: vec!["Tech".into()],
                    ..Default::default()
                }),
                podcast: Some(PodcastFeed {
                    guid: Some("g".into()),
                    locked: Some(true),
                    medium: Some("podcast".into()),
                    fundings: vec![PodcastFunding {
                        url: "https://fund".into(),
                        title: Some("Support".into()),
                    }],
                    ..Default::default()
                }),
                dublin_core: Some(DublinCoreFeed {
                    creator: Some("DC".into()),
                    ..Default::default()
                }),
            })
            .item(
                Rss2Item::new()
                    .with_title("E1")
                    .with_extensions(ItemExtensions {
                        itunes: Some(ITunes {
                            duration: Some("10:00".into()),
                            episode: Some(1),
                            season: Some(2),
                            keywords: Some("k".into()),
                            block: Some(true),
                            ..Default::default()
                        }),
                        podcast: Some(Podcast {
                            persons: vec![PodcastPerson {
                                name: "Jane".into(),
                                role: Some("host".into()),
                                group: None,
                                img: None,
                                href: None,
                            }],
                            season: Some(PodcastSeason {
                                number: 2,
                                name: Some("S2".into()),
                            }),
                            episode: Some(PodcastEpisode {
                                number: 1.0,
                                display: None,
                            }),
                            transcripts: vec![PodcastTranscript {
                                url: "https://t".into(),
                                type_: "text/vtt".into(),
                                language: Some("en".into()),
                                rel: None,
                            }],
                            soundbites: vec![PodcastSoundbite {
                                start_time: 1.0,
                                duration: 5.0,
                                title: Some("clip".into()),
                            }],
                            ..Default::default()
                        }),
                        dublin_core: Some(DublinCore {
                            creator: Some("Writer".into()),
                            ..Default::default()
                        }),
                        media: Some(MediaRss {
                            contents: vec![MediaContent {
                                url: Some("https://m.mp3".into()),
                                type_: Some("audio/mpeg".into()),
                                title: Some("MT".into()),
                                ..Default::default()
                            }],
                            thumbnail: Some(MediaThumbnail {
                                url: "https://th".into(),
                                width: Some(10),
                                height: Some(20),
                            }),
                            keywords: Some("mk".into()),
                            ..Default::default()
                        }),
                        content: Some(Content {
                            encoded: Some("<p>x</p>".into()),
                        }),
                    }),
            )
            .build();

        let xml = feed.to_string();
        let Feed::Rss2(got) = parse_feed(&xml, false).unwrap() else {
            panic!("expected RSS 2.0")
        };

        let it = got.extensions.itunes.as_ref().expect("feed itunes");
        assert_eq!(it.owner_name.as_deref(), Some("Owner"));
        assert_eq!(it.owner_email.as_deref(), Some("o@e.com"));
        assert_eq!(it.new_feed_url.as_deref(), Some("https://e.com/new"));
        assert_eq!(it.block, Some(true));
        assert_eq!(it.complete, Some(false));

        let pf = got.extensions.podcast.as_ref().expect("feed podcast");
        assert_eq!(pf.guid.as_deref(), Some("g"));
        assert_eq!(pf.locked, Some(true));
        assert_eq!(pf.fundings.len(), 1);
        assert_eq!(pf.fundings[0].title.as_deref(), Some("Support"));

        assert_eq!(
            got.extensions
                .dublin_core
                .as_ref()
                .unwrap()
                .creator
                .as_deref(),
            Some("DC")
        );

        let item = &got.items[0];
        let iit = item.itunes().expect("item itunes");
        assert_eq!(iit.episode, Some(1));
        assert_eq!(iit.season, Some(2));
        assert_eq!(iit.keywords.as_deref(), Some("k"));
        assert_eq!(iit.block, Some(true));

        let pod = item.podcast().expect("item podcast");
        assert_eq!(pod.persons.len(), 1);
        assert_eq!(pod.persons[0].name, "Jane");
        assert_eq!(pod.persons[0].role.as_deref(), Some("host"));
        assert_eq!(pod.season.as_ref().unwrap().number, 2);
        assert!((pod.episode.as_ref().unwrap().number - 1.0).abs() < f64::EPSILON);
        assert_eq!(pod.transcripts.len(), 1);
        assert_eq!(pod.soundbites.len(), 1);
        assert_eq!(pod.soundbites[0].title.as_deref(), Some("clip"));

        assert_eq!(
            item.dublin_core().unwrap().creator.as_deref(),
            Some("Writer")
        );

        let media = item.media().expect("item media");
        assert_eq!(media.contents.len(), 1);
        assert_eq!(media.contents[0].url.as_deref(), Some("https://m.mp3"));
        assert_eq!(media.contents[0].title.as_deref(), Some("MT"));
        assert_eq!(media.thumbnail.as_ref().unwrap().url, "https://th");
        assert_eq!(media.keywords.as_deref(), Some("mk"));

        assert_eq!(item.content().unwrap().encoded.as_deref(), Some("<p>x</p>"));
    }

    #[test]
    fn rss2_category_domain_round_trips() {
        let feed = Rss2Feed::builder()
            .title("T")
            .link("https://e.com")
            .description("D")
            .category(Rss2Category::new("Tech").with_domain("https://taxonomy"))
            .item(
                Rss2Item::new()
                    .with_title("I")
                    .with_category(Rss2Category::new("Sub").with_domain("https://d2")),
            )
            .build();
        let xml = feed.to_string();
        let Feed::Rss2(got) = parse_feed(&xml, false).unwrap() else {
            panic!("expected RSS 2.0")
        };
        assert_eq!(got.categories.len(), 1);
        assert_eq!(got.categories[0].name, "Tech");
        assert_eq!(
            got.categories[0].domain.as_deref(),
            Some("https://taxonomy")
        );
        assert_eq!(got.items[0].categories[0].name, "Sub");
        assert_eq!(
            got.items[0].categories[0].domain.as_deref(),
            Some("https://d2")
        );
    }

    #[test]
    fn atom_extensions_round_trip() {
        use super::super::feed_ext::{
            DublinCore, DublinCoreFeed, FeedExtensions, ITunes, ITunesFeed, ItemExtensions,
            MediaContent, MediaRss, Podcast, PodcastFeed, PodcastPerson,
        };

        let ts = jiff::Timestamp::UNIX_EPOCH;
        let feed = AtomFeed::builder()
            .id("urn:f")
            .title("F")
            .updated(ts)
            .feed_extensions(FeedExtensions {
                itunes: Some(ITunesFeed {
                    author: Some("Host".into()),
                    owner_name: Some("O".into()),
                    categories: vec!["Tech".into()],
                    explicit: Some(true),
                    ..Default::default()
                }),
                podcast: Some(PodcastFeed {
                    guid: Some("g".into()),
                    locked: Some(true),
                    persons: vec![PodcastPerson {
                        name: "Jane".into(),
                        role: Some("host".into()),
                        group: None,
                        img: None,
                        href: None,
                    }],
                    ..Default::default()
                }),
                dublin_core: Some(DublinCoreFeed {
                    creator: Some("DC".into()),
                    ..Default::default()
                }),
            })
            .entry(
                AtomEntry::new("urn:1", "E", ts).with_extensions(ItemExtensions {
                    itunes: Some(ITunes {
                        duration: Some("9:00".into()),
                        episode: Some(3),
                        ..Default::default()
                    }),
                    podcast: Some(Podcast {
                        persons: vec![PodcastPerson {
                            name: "Bob".into(),
                            role: Some("guest".into()),
                            group: None,
                            img: None,
                            href: None,
                        }],
                        ..Default::default()
                    }),
                    dublin_core: Some(DublinCore {
                        creator: Some("W".into()),
                        ..Default::default()
                    }),
                    media: Some(MediaRss {
                        contents: vec![MediaContent {
                            url: Some("https://m".into()),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            )
            .build();

        let xml = feed.to_string();
        let Feed::Atom(got) = parse_feed(&xml, false).unwrap() else {
            panic!("expected Atom")
        };

        let fit = got.extensions.itunes.as_ref().expect("feed itunes");
        assert_eq!(fit.author.as_deref(), Some("Host"));
        assert_eq!(fit.owner_name.as_deref(), Some("O"));
        assert_eq!(fit.explicit, Some(true));
        let fp = got.extensions.podcast.as_ref().expect("feed podcast");
        assert_eq!(fp.guid.as_deref(), Some("g"));
        assert_eq!(fp.locked, Some(true));
        assert_eq!(fp.persons.len(), 1);
        assert_eq!(fp.persons[0].name, "Jane");
        assert_eq!(
            got.extensions
                .dublin_core
                .as_ref()
                .unwrap()
                .creator
                .as_deref(),
            Some("DC")
        );

        let entry = &got.entries[0];
        assert_eq!(entry.itunes().expect("entry itunes").episode, Some(3));
        assert_eq!(
            entry.podcast().expect("entry podcast").persons[0].name,
            "Bob"
        );
        assert_eq!(entry.dublin_core().unwrap().creator.as_deref(), Some("W"));
        assert_eq!(
            entry.media().unwrap().contents[0].url.as_deref(),
            Some("https://m")
        );
    }

    #[test]
    fn atom_full_fields_round_trip() {
        let ts = jiff::Timestamp::UNIX_EPOCH;
        let mut entry = AtomEntry::new("urn:e1", AtomText::text("Entry Title"), ts);
        entry
            .contributors
            .push(AtomPerson::new("Carol").with_email("carol@example.com"));
        entry.rights = Some(AtomText::text("CC-BY"));
        entry.source = Some(AtomSource {
            id: Some("urn:src".into()),
            title: Some(AtomText::text("Origin")),
            updated: Some(ts),
        });
        entry.links.push(AtomLink {
            href: "https://e.com/x".into(),
            rel: Some("related".into()),
            type_: Some("text/html".into()),
            hreflang: Some("en".into()),
            title: Some("X".into()),
            length: Some(7),
        });
        entry.content = Some(AtomContent::out_of_line(
            "https://cdn/x.bin",
            "application/octet-stream",
        ));

        let feed = AtomFeed::builder()
            .id("urn:f")
            .title("Feed")
            .updated(ts)
            .generator(AtomGenerator {
                value: "rama".into(),
                uri: Some("https://r".into()),
                version: Some("1".into()),
            })
            .icon("https://e.com/icon.png")
            .contributor(AtomPerson::new("Dave"))
            .rights(AtomText::text("Public"))
            .entry(entry)
            .build();

        let xml = feed.to_string();
        let Feed::Atom(got) = parse_feed(&xml, false).unwrap() else {
            panic!("expected Atom")
        };

        let g = got.generator.expect("generator");
        assert_eq!(g.value, "rama");
        assert_eq!(g.uri.as_deref(), Some("https://r"));
        assert_eq!(g.version.as_deref(), Some("1"));
        assert_eq!(got.icon.as_deref(), Some("https://e.com/icon.png"));
        assert_eq!(got.contributors.len(), 1);
        assert_eq!(got.contributors[0].name, "Dave");
        assert!(got.rights.is_some());

        let e = &got.entries[0];
        // critically: <source> children must NOT overwrite the entry's own id/title/updated
        assert_eq!(e.id, "urn:e1");
        assert_eq!(e.title, AtomText::text("Entry Title"));
        assert_eq!(e.updated, ts);
        assert_eq!(e.contributors.len(), 1);
        assert_eq!(e.contributors[0].name, "Carol");
        assert_eq!(
            e.contributors[0].email.as_deref(),
            Some("carol@example.com")
        );
        assert!(e.rights.is_some());
        let src = e.source.as_ref().expect("entry source");
        assert_eq!(src.id.as_deref(), Some("urn:src"));
        assert_eq!(src.title.as_ref().map(AtomText::value), Some("Origin"));
        assert_eq!(src.updated, Some(ts));
        let link = e
            .links
            .iter()
            .find(|l| l.hreflang.is_some())
            .expect("link with hreflang");
        assert_eq!(link.hreflang.as_deref(), Some("en"));
        assert_eq!(link.title.as_deref(), Some("X"));
        assert_eq!(link.length, Some(7));
        let content = e.content.as_ref().expect("content");
        assert_eq!(content.src.as_deref(), Some("https://cdn/x.bin"));
        assert_eq!(content.value.value(), "application/octet-stream");
    }

    #[test]
    fn rss2_item_source_round_trips() {
        let feed = Rss2Feed::builder()
            .title("T")
            .link("https://e.com")
            .description("D")
            .item(Rss2Item::new().with_title("I").with_source(Rss2Source {
                title: "Origin".into(),
                url: "https://origin".into(),
            }))
            .build();
        let xml = feed.to_string();
        let Feed::Rss2(got) = parse_feed(&xml, false).unwrap() else {
            panic!("expected RSS 2.0")
        };
        let src = got.items[0].source.as_ref().expect("item source");
        assert_eq!(src.title, "Origin");
        assert_eq!(src.url, "https://origin");
    }

    #[test]
    fn lenient_rejects_non_feed() {
        parse_feed("<html><body>not a feed</body></html>", false).unwrap_err();
        parse_feed("just some text, definitely not xml", false).unwrap_err();
        // a real feed still parses fine in lenient mode
        parse_feed(
            r#"<rss version="2.0"><channel><title>T</title><link>l</link><description>d</description></channel></rss>"#,
            false,
        )
        .unwrap();
    }

    #[test]
    fn rss2_recognises_arbitrary_extension_prefix() {
        // Bind the Podcasting 2.0 namespace to a non-standard prefix and verify
        // the parser resolves by namespace URI rather than literal prefix.
        let xml = r#"<?xml version="1.0"?>
<rss version="2.0" xmlns:pod="https://podcastindex.org/namespace/1.0">
  <channel>
    <title>T</title><link>https://e.com</link><description>D</description>
    <item>
      <title>E</title>
      <pod:person role="host">Jane</pod:person>
    </item>
  </channel>
</rss>"#;
        let Feed::Rss2(feed) = parse_feed(xml, false).unwrap() else {
            panic!("expected RSS 2.0")
        };
        let podcast = feed.items[0]
            .podcast()
            .expect("podcast extension parsed via non-standard prefix");
        assert_eq!(podcast.persons.len(), 1);
        assert_eq!(podcast.persons[0].name, "Jane");
        assert_eq!(podcast.persons[0].role.as_deref(), Some("host"));
    }

    #[test]
    fn atom_parses_with_prefixed_root() {
        // Atom feed with a non-default prefix for the Atom namespace itself.
        let xml = r#"<?xml version="1.0"?>
<a:feed xmlns:a="http://www.w3.org/2005/Atom">
  <a:id>urn:f</a:id>
  <a:title>T</a:title>
  <a:updated>2024-01-01T00:00:00Z</a:updated>
  <a:entry>
    <a:id>urn:1</a:id>
    <a:title>E</a:title>
    <a:updated>2024-01-01T00:00:00Z</a:updated>
    <a:summary>hi</a:summary>
  </a:entry>
</a:feed>"#;
        let Feed::Atom(feed) = parse_feed(xml, false).unwrap() else {
            panic!("expected Atom")
        };
        assert_eq!(feed.id, "urn:f");
        assert_eq!(feed.entries.len(), 1);
        assert_eq!(feed.entries[0].id, "urn:1");
        match &feed.entries[0].summary {
            Some(AtomText::Text(s)) => assert_eq!(s, "hi"),
            other => panic!("unexpected summary: {other:?}"),
        }
    }

    // ---------------------------------------------------------------------
    // Regression tests for the audit findings
    // ---------------------------------------------------------------------

    #[test]
    fn rss2_attr_unescape_round_trips() {
        // URLs containing `&` are the dominant real-world case the
        // attr_value-without-unescape bug corrupted.
        use super::super::rss2::Rss2Enclosure;
        let feed = Rss2Feed::builder()
            .title("T")
            .link("https://e.com")
            .description("D")
            .item(
                Rss2Item::new()
                    .with_title("I")
                    .with_enclosure(Rss2Enclosure::new(
                        "https://e.com/x?a=1&b=2",
                        1,
                        "audio/mpeg",
                    )),
            )
            .build();
        let Feed::Rss2(got) = parse_feed(&feed.to_string(), false).unwrap() else {
            panic!("expected RSS")
        };
        assert_eq!(
            got.items[0].enclosures[0].url, "https://e.com/x?a=1&b=2",
            "& in url should be unescaped on parse"
        );
    }

    #[test]
    fn rss2_content_encoded_with_cdata_terminator_round_trips() {
        use super::super::feed_ext::{Content, ItemExtensions};
        let payload = "before ]]> after <script>".to_owned();
        let feed = Rss2Feed::builder()
            .title("T")
            .link("https://e.com")
            .description("D")
            .item(
                Rss2Item::new()
                    .with_title("I")
                    .with_extensions(ItemExtensions {
                        content: Some(Content {
                            encoded: Some(payload.clone()),
                        }),
                        ..Default::default()
                    }),
            )
            .build();
        let wire = feed.to_string();
        let Feed::Rss2(got) = parse_feed(&wire, false).unwrap() else {
            panic!("expected RSS")
        };
        assert_eq!(
            got.items[0].content().unwrap().encoded.as_deref(),
            Some(payload.as_str()),
            "`]]>` inside content:encoded must round-trip exactly"
        );
    }

    #[test]
    fn rss2_multiple_enclosures_round_trip() {
        use super::super::rss2::Rss2Enclosure;
        let feed = Rss2Feed::builder()
            .title("T")
            .link("https://e.com")
            .description("D")
            .item(
                Rss2Item::new()
                    .with_title("I")
                    .with_enclosure(Rss2Enclosure::new("https://a.mp3", 1, "audio/mpeg"))
                    .with_enclosure(Rss2Enclosure::new("https://b.aac", 2, "audio/aac")),
            )
            .build();
        let Feed::Rss2(got) = parse_feed(&feed.to_string(), false).unwrap() else {
            panic!()
        };
        assert_eq!(got.items[0].enclosures.len(), 2);
        assert_eq!(got.items[0].enclosures[1].url, "https://b.aac");
    }

    #[test]
    fn rss2_atom_self_link_round_trips() {
        use super::super::atom::AtomLink;
        let feed = Rss2Feed::builder()
            .title("T")
            .link("https://e.com")
            .description("D")
            .atom_link(AtomLink::self_link("https://e.com/feed.rss"))
            .build();
        let wire = feed.to_string();
        assert!(wire.contains(r#"xmlns:atom="http://www.w3.org/2005/Atom""#));
        let Feed::Rss2(got) = parse_feed(&wire, false).unwrap() else {
            panic!()
        };
        assert_eq!(got.atom_links.len(), 1);
        assert_eq!(got.atom_links[0].href, "https://e.com/feed.rss");
        assert_eq!(got.atom_links[0].rel.as_deref(), Some("self"));
    }

    #[test]
    fn rss2_lenient_preserves_text_around_bad_entity() {
        let xml = r#"<rss version="2.0"><channel>
            <title>T</title><link>l</link>
            <description>before&junk;after</description>
        </channel></rss>"#;
        let Feed::Rss2(f) = parse_feed(xml, false).unwrap() else {
            panic!()
        };
        let d = &f.description;
        assert!(
            d.contains("before") && d.contains("after"),
            "lenient must keep surrounding text around an unknown entity: {d:?}"
        );
    }

    #[test]
    fn lenient_rejects_truncated_input() {
        let xml = "<rss version=\"2.0\"><channel><title>Real</title>";
        parse_feed(xml, false).unwrap_err();
    }

    #[test]
    fn rss2_nested_item_preserves_outer() {
        let xml = r#"<rss version="2.0"><channel>
            <title>T</title><link>l</link><description>D</description>
            <item><title>Outer</title>
                <item><title>Inner</title></item>
            </item>
        </channel></rss>"#;
        let Feed::Rss2(f) = parse_feed(xml, false).unwrap() else {
            panic!()
        };
        let titles: Vec<_> = f.items.iter().filter_map(|i| i.title.clone()).collect();
        assert!(titles.contains(&"Outer".to_owned()), "{titles:?}");
        assert!(titles.contains(&"Inner".to_owned()), "{titles:?}");
    }

    #[test]
    fn atom_source_children_do_not_leak_into_entry() {
        let xml = r#"<feed xmlns="http://www.w3.org/2005/Atom">
            <id>urn:f</id><title>T</title><updated>2024-01-01T00:00:00Z</updated>
            <entry><id>urn:e</id><title>E</title><updated>2024-01-01T00:00:00Z</updated>
                <source>
                    <id>urn:src</id>
                    <title>SrcTitle</title>
                    <updated>2000-01-01T00:00:00Z</updated>
                    <author><name>SrcAuthor</name></author>
                    <contributor><name>SrcContrib</name></contributor>
                    <link href="https://src.example/feed"/>
                    <category term="src-cat"/>
                </source>
            </entry>
        </feed>"#;
        let Feed::Atom(f) = parse_feed(xml, false).unwrap() else {
            panic!()
        };
        let e = &f.entries[0];
        assert_eq!(e.id, "urn:e", "source.id must not overwrite entry.id");
        assert!(
            e.authors.is_empty(),
            "source.author must not leak into entry.authors"
        );
        assert!(
            e.contributors.is_empty(),
            "source.contributor must not leak into entry.contributors"
        );
        assert!(
            e.links.is_empty(),
            "source.link must not leak into entry.links"
        );
        assert!(
            e.categories.is_empty(),
            "source.category must not leak into entry.categories"
        );
        let src = e.source.as_ref().expect("source preserved");
        assert_eq!(src.id.as_deref(), Some("urn:src"));
    }

    #[test]
    fn atom_strict_per_entry_required_fields() {
        // missing entry <id>
        parse_feed(
            r#"<feed xmlns="http://www.w3.org/2005/Atom">
                <id>urn:f</id><title>F</title><updated>2024-01-01T00:00:00Z</updated>
                <entry><title>E</title><updated>2024-01-01T00:00:00Z</updated></entry>
            </feed>"#,
            true,
        )
        .unwrap_err();
        // unparseable feed <updated>
        parse_feed(
            r#"<feed xmlns="http://www.w3.org/2005/Atom">
                <id>urn:f</id><title>F</title><updated>not-a-date</updated>
            </feed>"#,
            true,
        )
        .unwrap_err();
        // unparseable entry <updated>
        parse_feed(
            r#"<feed xmlns="http://www.w3.org/2005/Atom">
                <id>urn:f</id><title>F</title><updated>2024-01-01T00:00:00Z</updated>
                <entry><id>urn:e</id><title>E</title><updated>not-a-date</updated></entry>
            </feed>"#,
            true,
        )
        .unwrap_err();
    }

    #[test]
    fn atom_xhtml_round_trips_inner_markup() {
        use jiff::Timestamp;
        let ts = Timestamp::UNIX_EPOCH;
        let feed = AtomFeed::builder()
            .id("urn:f")
            .title("T")
            .updated(ts)
            .entry(AtomEntry::new("urn:e", "E", ts).with_content(AtomContent {
                value: AtomText::xhtml("<p>hello <em>world</em></p>"),
                src: None,
            }))
            .build();
        let wire = feed.to_string();
        let Feed::Atom(got) = parse_feed(&wire, false).unwrap() else {
            panic!()
        };
        match &got.entries[0].content.as_ref().unwrap().value {
            AtomText::Xhtml(s) => {
                assert!(s.contains("<p>"), "xhtml inner markup dropped: {s:?}");
                assert!(s.contains("<em>"), "xhtml inner markup dropped: {s:?}");
            }
            other => panic!("expected xhtml, got {other:?}"),
        }
    }

    #[test]
    fn podcast_soundbite_rejects_nan_inf() {
        use super::super::feed_ext::{ItemExtensions, MediaRss};
        // Build a feed by hand-crafting XML so we control attribute values.
        let xml = r#"<rss version="2.0" xmlns:podcast="https://podcastindex.org/namespace/1.0">
            <channel><title>T</title><link>l</link><description>D</description>
                <item><title>I</title>
                    <podcast:soundbite startTime="NaN" duration="-inf"/>
                </item>
            </channel>
        </rss>"#;
        let Feed::Rss2(f) = parse_feed(xml, false).unwrap() else {
            panic!()
        };
        let sb = &f.items[0].podcast().expect("podcast ext").soundbites[0];
        assert!(sb.start_time.is_finite(), "NaN must be rejected");
        assert!(sb.duration.is_finite(), "-inf must be rejected");
        // unused imports silenced
        let _ = ItemExtensions::default();
        let _ = MediaRss::default();
    }

    #[test]
    fn nested_media_content_preserves_outer() {
        let xml = r#"<rss version="2.0" xmlns:media="http://search.yahoo.com/mrss/">
            <channel><title>T</title><link>l</link><description>D</description>
                <item><title>I</title>
                    <media:content url="outer" type="application/octet-stream">
                        <media:content url="inner" type="application/octet-stream"/>
                    </media:content>
                </item>
            </channel>
        </rss>"#;
        let Feed::Rss2(f) = parse_feed(xml, false).unwrap() else {
            panic!()
        };
        let urls: Vec<_> = f.items[0]
            .media()
            .expect("media")
            .contents
            .iter()
            .filter_map(|c| c.url.clone())
            .collect();
        assert!(urls.contains(&"outer".to_owned()), "{urls:?}");
        assert!(urls.contains(&"inner".to_owned()), "{urls:?}");
    }

    #[test]
    fn display_does_not_panic_on_malformed_xhtml() {
        use jiff::Timestamp;
        let ts = Timestamp::UNIX_EPOCH;
        let mut feed = AtomFeed::builder()
            .id("urn:f")
            .title("T")
            .updated(ts)
            .build();
        feed.entries
            .push(AtomEntry::new("urn:e", "E", ts).with_content(AtomContent {
                value: AtomText::xhtml("<p>broken"),
                src: None,
            }));
        // Must not panic: Display falls back to an error comment.
        let s = feed.to_string();
        assert!(s.contains("serialization error"), "{s:?}");
    }
}
