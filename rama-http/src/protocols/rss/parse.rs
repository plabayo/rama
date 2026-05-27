//! Lenient (default) and strict RSS 2.0 / Atom 1.0 parsing.
//!
//! The entry points are [`Feed::parse`] (lenient) and [`Feed::parse_strict`]
//! (strict). Lenient parsing silently skips elements it cannot understand;
//! strict parsing returns an error for any structural violation.

use jiff::Timestamp;
use quick_xml::{Reader, events::Event};
use rama_core::telemetry::tracing;

use super::atom::{AtomCategory, AtomContent, AtomEntry, AtomFeed, AtomLink, AtomPerson, AtomText};
use super::ext_parse::{FeedExtAcc, ItemExtAcc};
use super::feed::Feed;
use super::rss2::{Rss2Category, Rss2Enclosure, Rss2Feed, Rss2Guid, Rss2Image, Rss2Item};

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

    if is_atom {
        parse_atom(input, strict).map(Feed::Atom)
    } else if is_rss {
        parse_rss2(input, strict).map(Feed::Rss2)
    } else if strict {
        Err(FeedParseError::new(
            "document is neither RSS 2.0 nor Atom 1.0",
        ))
    } else {
        // Try RSS 2.0 as a fallback
        parse_rss2(input, false)
            .map(Feed::Rss2)
            .or_else(|_err| parse_atom(input, false).map(Feed::Atom))
            .map_err(|_err| FeedParseError::new("unrecognized feed format"))
    }
}

fn detect_atom(s: &str) -> bool {
    // Look for `<feed` with the Atom namespace within the first few KB.
    let probe = probe_prefix(s, 2048);
    probe.contains("<feed") && (probe.contains("w3.org/2005/Atom") || probe.contains("<feed>"))
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

fn parse_rss2(input: &str, strict: bool) -> Result<Rss2Feed, FeedParseError> {
    let mut reader = Reader::from_str(input);
    reader.config_mut().trim_text(true);

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
    let mut feed_acc = FeedExtAcc::default();

    // Item state
    let mut in_item = false;
    let mut in_image_block = false;
    let mut current_item = Rss2Item::default();
    let mut item_acc = ItemExtAcc::default();

    // Pending `<category domain="..">name</category>` domain attribute.
    let mut pending_category_domain: Option<String> = None;

    let mut text_buf = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let full_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                text_buf.clear();
                let consumed = if in_item {
                    item_acc.on_start(&full_tag, &e)
                } else {
                    feed_acc.on_start(&full_tag, &e)
                };
                if !consumed {
                    match full_tag.as_str() {
                        "item" => {
                            in_item = true;
                            current_item = Rss2Item::default();
                            item_acc = ItemExtAcc::default();
                        }
                        "image" if !in_item => in_image_block = true,
                        "enclosure" if in_item => {
                            current_item.enclosure = Some(enclosure_from_attrs(&e));
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
                        "category" => pending_category_domain = attr_value(&e, b"domain"),
                        _ => {}
                    }
                }
            }
            Ok(Event::Empty(e)) => {
                let full_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let consumed = if in_item {
                    item_acc.on_empty(&full_tag, &e)
                } else {
                    feed_acc.on_empty(&full_tag, &e)
                };
                if !consumed && in_item && full_tag == "enclosure" {
                    current_item.enclosure = Some(enclosure_from_attrs(&e));
                }
            }
            Ok(Event::Text(e)) => {
                if let Ok(t) = e.unescape() {
                    text_buf.push_str(&t);
                }
            }
            Ok(Event::CData(e)) => {
                if let Ok(t) = std::str::from_utf8(e.as_ref()) {
                    text_buf.push_str(t);
                }
            }
            Ok(Event::End(e)) => {
                let full_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let text = std::mem::take(&mut text_buf);

                if in_item {
                    let Some(text) = item_acc.on_end(&full_tag, text) else {
                        continue;
                    };
                    match full_tag.as_str() {
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
                        "item" => {
                            current_item.extensions = std::mem::take(&mut item_acc).finish();
                            items.push(std::mem::take(&mut current_item));
                            in_item = false;
                        }
                        _ => {}
                    }
                } else if in_image_block {
                    match full_tag.as_str() {
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
                } else {
                    let Some(text) = feed_acc.on_end(&full_tag, text) else {
                        continue;
                    };
                    match full_tag.as_str() {
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
            Ok(Event::Eof) => break,
            Err(e) => {
                if strict {
                    return Err(FeedParseError::new(format!("xml error: {e}")));
                }
                tracing::debug!("rss2 parse xml error (lenient): {e}");
                break;
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

    Ok(Rss2Feed {
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
        items,
        extensions: feed_acc.finish(),
    })
}

// ---------------------------------------------------------------------------
// Atom parser
// ---------------------------------------------------------------------------

fn parse_atom(input: &str, strict: bool) -> Result<AtomFeed, FeedParseError> {
    let mut reader = Reader::from_str(input);
    reader.config_mut().trim_text(true);

    let mut feed_id = String::new();
    let mut feed_title = AtomText::text("");
    let mut feed_updated = Timestamp::UNIX_EPOCH;
    let mut feed_updated_set = false;
    let mut feed_authors: Vec<AtomPerson> = Vec::new();
    let mut feed_links: Vec<AtomLink> = Vec::new();
    let mut feed_categories: Vec<AtomCategory> = Vec::new();
    let mut feed_subtitle: Option<AtomText> = None;
    let mut feed_rights: Option<AtomText> = None;
    let mut feed_logo: Option<String> = None;
    let mut entries: Vec<AtomEntry> = Vec::new();
    let mut feed_acc = FeedExtAcc::default();

    let mut in_entry = false;
    let mut in_author = false;
    let mut in_feed_author = false;
    let mut current_entry_id = String::new();
    let mut current_entry_title = AtomText::text("");
    let mut current_entry_updated = Timestamp::UNIX_EPOCH;
    let mut current_entry_authors: Vec<AtomPerson> = Vec::new();
    let mut current_entry_links: Vec<AtomLink> = Vec::new();
    let mut current_entry_categories: Vec<AtomCategory> = Vec::new();
    let mut current_entry_summary: Option<AtomText> = None;
    let mut current_entry_content: Option<AtomContent> = None;
    let mut current_entry_published: Option<Timestamp> = None;
    let mut entry_acc = ItemExtAcc::default();
    let mut current_author = AtomPerson::new("");
    let mut current_content_type = String::from("text");
    let mut current_title_type = String::from("text");
    let mut current_summary_type = String::from("text");

    let mut text_buf = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let full_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                text_buf.clear();

                let consumed = if in_entry {
                    entry_acc.on_start(&full_tag, &e)
                } else {
                    feed_acc.on_start(&full_tag, &e)
                };
                if consumed {
                    continue;
                }

                match full_tag.as_str() {
                    "entry" => {
                        in_entry = true;
                        current_entry_id = String::new();
                        current_entry_title = AtomText::text("");
                        current_entry_updated = Timestamp::UNIX_EPOCH;
                        current_entry_authors = Vec::new();
                        current_entry_links = Vec::new();
                        current_entry_categories = Vec::new();
                        current_entry_summary = None;
                        current_entry_content = None;
                        current_entry_published = None;
                        entry_acc = ItemExtAcc::default();
                    }
                    "author" => {
                        current_author = AtomPerson::new("");
                        if in_entry {
                            in_author = true;
                        } else {
                            in_feed_author = true;
                        }
                    }
                    "link" => {
                        let href = attr_value(&e, b"href").unwrap_or_default();
                        let rel = attr_value(&e, b"rel");
                        let type_ = attr_value(&e, b"type");
                        let length = attr_value(&e, b"length").and_then(|v| v.parse().ok());
                        let link = AtomLink {
                            href,
                            rel,
                            type_,
                            hreflang: None,
                            title: None,
                            length,
                        };
                        if in_entry {
                            current_entry_links.push(link);
                        } else {
                            feed_links.push(link);
                        }
                    }
                    "category" => {
                        let term = attr_value(&e, b"term").unwrap_or_default();
                        let scheme = attr_value(&e, b"scheme");
                        let label = attr_value(&e, b"label");
                        let cat = AtomCategory {
                            term,
                            scheme,
                            label,
                        };
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
                    _ => {}
                }
            }
            Ok(Event::Empty(e)) => {
                let full_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();

                let consumed = if in_entry {
                    entry_acc.on_empty(&full_tag, &e)
                } else {
                    feed_acc.on_empty(&full_tag, &e)
                };
                if consumed {
                    continue;
                }

                match full_tag.as_str() {
                    "link" => {
                        let href = attr_value(&e, b"href").unwrap_or_default();
                        let rel = attr_value(&e, b"rel");
                        let type_ = attr_value(&e, b"type");
                        let length = attr_value(&e, b"length").and_then(|v| v.parse().ok());
                        let link = AtomLink {
                            href,
                            rel,
                            type_,
                            hreflang: None,
                            title: None,
                            length,
                        };
                        if in_entry {
                            current_entry_links.push(link);
                        } else {
                            feed_links.push(link);
                        }
                    }
                    "category" => {
                        let term = attr_value(&e, b"term").unwrap_or_default();
                        let scheme = attr_value(&e, b"scheme");
                        let label = attr_value(&e, b"label");
                        let cat = AtomCategory {
                            term,
                            scheme,
                            label,
                        };
                        if in_entry {
                            current_entry_categories.push(cat);
                        } else {
                            feed_categories.push(cat);
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(e)) => {
                if let Ok(t) = e.unescape() {
                    text_buf.push_str(&t);
                }
            }
            Ok(Event::CData(e)) => {
                if let Ok(t) = std::str::from_utf8(e.as_ref()) {
                    text_buf.push_str(t);
                }
            }
            Ok(Event::End(e)) => {
                let full_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let text = std::mem::take(&mut text_buf);

                if in_author {
                    match full_tag.as_str() {
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
                } else if in_feed_author {
                    match full_tag.as_str() {
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
                } else if in_entry {
                    let Some(text) = entry_acc.on_end(&full_tag, text) else {
                        continue;
                    };
                    match full_tag.as_str() {
                        "id" => current_entry_id = text,
                        "title" => {
                            current_entry_title = make_atom_text(&current_title_type, text);
                        }
                        "updated" => {
                            current_entry_updated =
                                parse_rfc3339_lax(&text).unwrap_or(Timestamp::UNIX_EPOCH);
                        }
                        "published" => {
                            current_entry_published = parse_rfc3339_lax(&text);
                        }
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
                        "entry" => {
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
                                contributors: Vec::new(),
                                published: current_entry_published,
                                rights: None,
                                source: None,
                                extensions: std::mem::take(&mut entry_acc).finish(),
                            };
                            entries.push(entry);
                            in_entry = false;
                        }
                        _ => {}
                    }
                } else {
                    let Some(text) = feed_acc.on_end(&full_tag, text) else {
                        continue;
                    };
                    match full_tag.as_str() {
                        "id" => feed_id = text,
                        "title" => {
                            feed_title = make_atom_text(&current_title_type, text);
                        }
                        "updated" => {
                            feed_updated =
                                parse_rfc3339_lax(&text).unwrap_or(Timestamp::UNIX_EPOCH);
                            feed_updated_set = true;
                        }
                        "subtitle" => feed_subtitle = Some(AtomText::text(text)),
                        "rights" => feed_rights = Some(AtomText::text(text)),
                        "logo" => feed_logo = Some(text),
                        _ => {}
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                if strict {
                    return Err(FeedParseError::new(format!("xml error: {e}")));
                }
                tracing::debug!("atom parse xml error (lenient): {e}");
                break;
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
        if !feed_updated_set {
            return Err(FeedParseError::new("Atom feed missing required <updated>"));
        }
    }

    Ok(AtomFeed {
        id: feed_id,
        title: feed_title,
        updated: feed_updated,
        authors: feed_authors,
        links: feed_links,
        categories: feed_categories,
        contributors: Vec::new(),
        generator: None,
        icon: None,
        logo: feed_logo,
        rights: feed_rights,
        subtitle: feed_subtitle,
        entries,
        extensions: feed_acc.finish(),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(super) fn attr_value(e: &quick_xml::events::BytesStart<'_>, name: &[u8]) -> Option<String> {
    e.attributes()
        .filter_map(|a| a.ok())
        .find(|a| a.key.as_ref() == name)
        .and_then(|a| {
            std::str::from_utf8(a.value.as_ref())
                .ok()
                .map(str::to_owned)
        })
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
}
