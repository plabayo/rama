//! Lenient (default) and strict RSS 2.0 / Atom 1.0 parsing.
//!
//! The entry points are [`Feed::from_str`] (lenient) and
//! [`Feed::from_str_strict`] (strict).  Lenient parsing silently skips
//! elements it cannot understand; strict parsing returns an error for any
//! structural violation.

use jiff::Timestamp;
use quick_xml::{Reader, events::Event};
use rama_core::telemetry::tracing;

use super::atom::{AtomCategory, AtomContent, AtomEntry, AtomFeed, AtomLink, AtomPerson, AtomText};
use super::feed::Feed;
use super::feed_ext::{
    Content, FeedExtensions, ITunes, ITunesFeed, ItemExtensions,
};
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
            .or_else(|_| parse_atom(input, false).map(Feed::Atom))
            .map_err(|_| FeedParseError::new("unrecognized feed format"))
    }
}

fn detect_atom(s: &str) -> bool {
    // Look for `<feed` with the Atom namespace within the first few KB.
    let probe = &s[..s.len().min(2048)];
    probe.contains("<feed") && (probe.contains("w3.org/2005/Atom") || probe.contains("<feed>"))
}

fn detect_rss(s: &str) -> bool {
    let probe = &s[..s.len().min(1024)];
    probe.contains("<rss") || probe.contains("<channel")
}

// ---------------------------------------------------------------------------
// RSS 2.0 parser
// ---------------------------------------------------------------------------

fn parse_rss2(input: &str, strict: bool) -> Result<Rss2Feed, FeedParseError> {
    let mut reader = Reader::from_str(input);
    reader.config_mut().trim_text(true);

    // Working state
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
    let mut ttl: Option<u32> = None;
    let image: Option<Rss2Image> = None;
    let mut items: Vec<Rss2Item> = Vec::new();
    let mut feed_ext = FeedExtensions::default();
    let mut itunes_feed = ITunesFeed::default();
    let mut has_itunes = false;

    // Item working state
    let mut in_item = false;
    let mut in_image_block = false;
    let mut current_item = Rss2Item::default();
    let mut current_item_itunes = ITunes::default();
    let mut current_item_has_itunes = false;
    let mut current_item_content: Option<Content> = None;

    let mut stack: Vec<String> = Vec::new();
    let mut text_buf = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let tag = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                let full_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                stack.push(full_tag.clone());
                text_buf.clear();

                match full_tag.as_str() {
                    "item" => {
                        in_item = true;
                        current_item = Rss2Item::default();
                        current_item_itunes = ITunes::default();
                        current_item_has_itunes = false;
                        current_item_content = None;
                    }
                    "image" if !in_item => {
                        in_image_block = true;
                    }
                    "enclosure" => {
                        // enclosure is an empty element with attributes
                        let url = attr_value(&e, b"url");
                        let length = attr_value(&e, b"length")
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or_default();
                        let type_ = attr_value(&e, b"type").unwrap_or_default();
                        if in_item {
                            current_item.enclosure = Some(Rss2Enclosure { url: url.unwrap_or_default(), length, type_ });
                        }
                    }
                    "guid" => {
                        if in_item {
                            let permalink = attr_value(&e, b"isPermaLink")
                                .map(|v| v != "false")
                                .unwrap_or(true);
                            // value captured on text event
                            current_item.guid = Some(Rss2Guid { value: String::new(), permalink });
                        }
                    }
                    "itunes:image" => {
                        let href = attr_value(&e, b"href");
                        if in_item {
                            if let Some(v) = href { current_item_itunes.image = Some(v); current_item_has_itunes = true; }
                        } else {
                            if let Some(v) = href { itunes_feed.image = Some(v); has_itunes = true; }
                        }
                    }
                    _ => {}
                }
                let _ = tag;
            }
            Ok(Event::Empty(e)) => {
                let full_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match full_tag.as_str() {
                    "enclosure" => {
                        let url = attr_value(&e, b"url");
                        let length = attr_value(&e, b"length")
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or_default();
                        let type_ = attr_value(&e, b"type").unwrap_or_default();
                        if in_item {
                            current_item.enclosure = Some(Rss2Enclosure { url: url.unwrap_or_default(), length, type_ });
                        }
                    }
                    "itunes:image" => {
                        let href = attr_value(&e, b"href");
                        if in_item {
                            if let Some(v) = href { current_item_itunes.image = Some(v); current_item_has_itunes = true; }
                        } else {
                            if let Some(v) = href { itunes_feed.image = Some(v); has_itunes = true; }
                        }
                    }
                    "itunes:category" => {
                        if let Some(v) = attr_value(&e, b"text") {
                            itunes_feed.categories.push(v);
                            has_itunes = true;
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
                stack.pop();

                let text = std::mem::take(&mut text_buf);

                if in_item {
                    match full_tag.as_str() {
                        "title" => current_item.title = Some(text),
                        "link" => current_item.link = Some(text),
                        "description" => current_item.description = Some(text),
                        "author" => current_item.author = Some(text),
                        "comments" => current_item.comments = Some(text),
                        "pubDate" => {
                            current_item.pub_date = parse_rss2_date(&text);
                        }
                        "guid" => {
                            if let Some(guid) = &mut current_item.guid {
                                guid.value = text;
                            }
                        }
                        "category" => {
                            current_item.categories.push(Rss2Category::new(text));
                        }
                        "itunes:title" => { current_item_itunes.title = Some(text); current_item_has_itunes = true; }
                        "itunes:author" => { current_item_itunes.author = Some(text); current_item_has_itunes = true; }
                        "itunes:subtitle" => { current_item_itunes.subtitle = Some(text); current_item_has_itunes = true; }
                        "itunes:summary" => { current_item_itunes.summary = Some(text); current_item_has_itunes = true; }
                        "itunes:duration" => { current_item_itunes.duration = Some(text); current_item_has_itunes = true; }
                        "itunes:explicit" => {
                            current_item_itunes.explicit = Some(text == "true" || text == "yes");
                            current_item_has_itunes = true;
                        }
                        "itunes:episode" => {
                            current_item_itunes.episode = text.parse().ok();
                            current_item_has_itunes = true;
                        }
                        "itunes:season" => {
                            current_item_itunes.season = text.parse().ok();
                            current_item_has_itunes = true;
                        }
                        "itunes:episodeType" => {
                            current_item_itunes.episode_type = Some(text);
                            current_item_has_itunes = true;
                        }
                        "content:encoded" => {
                            current_item_content = Some(Content { encoded: Some(text) });
                        }
                        "item" => {
                            if current_item_has_itunes {
                                current_item.extensions.itunes = Some(current_item_itunes.clone());
                            }
                            if let Some(c) = current_item_content.take() {
                                current_item.extensions.content = Some(c);
                            }
                            items.push(std::mem::take(&mut current_item));
                            in_item = false;
                        }
                        _ => {}
                    }
                } else if in_image_block {
                    if full_tag.as_str() == "image" {
                        in_image_block = false;
                    }
                } else {
                    // Channel-level
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
                        "itunes:author" => { itunes_feed.author = Some(text); has_itunes = true; }
                        "itunes:title" => { itunes_feed.title = Some(text); has_itunes = true; }
                        "itunes:subtitle" => { itunes_feed.subtitle = Some(text); has_itunes = true; }
                        "itunes:summary" => { itunes_feed.summary = Some(text); has_itunes = true; }
                        "itunes:type" => { itunes_feed.type_ = Some(text); has_itunes = true; }
                        "itunes:explicit" => {
                            itunes_feed.explicit = Some(text == "true" || text == "yes");
                            has_itunes = true;
                        }
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
        return Err(FeedParseError::new("RSS 2.0 channel missing required <title>"));
    }
    if strict && link.is_empty() {
        return Err(FeedParseError::new("RSS 2.0 channel missing required <link>"));
    }

    if has_itunes {
        feed_ext.itunes = Some(itunes_feed);
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
        categories: Vec::new(),
        generator,
        docs: None,
        ttl,
        image,
        items,
        extensions: feed_ext,
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
    let mut feed_authors: Vec<AtomPerson> = Vec::new();
    let mut feed_links: Vec<AtomLink> = Vec::new();
    let mut feed_categories: Vec<AtomCategory> = Vec::new();
    let mut feed_subtitle: Option<AtomText> = None;
    let mut feed_rights: Option<AtomText> = None;
    let mut feed_logo: Option<String> = None;
    let mut entries: Vec<AtomEntry> = Vec::new();

    let mut in_entry = false;
    let mut in_author = false;
    let mut in_feed_author = false;
    let mut current_entry_id = String::new();
    let mut current_entry_title = AtomText::text("");
    let mut current_entry_updated = Timestamp::UNIX_EPOCH;
    let mut current_entry_authors: Vec<AtomPerson> = Vec::new();
    let mut current_entry_links: Vec<AtomLink> = Vec::new();
    let mut current_entry_summary: Option<AtomText> = None;
    let mut current_entry_content: Option<AtomContent> = None;
    let mut current_entry_published: Option<Timestamp> = None;
    let mut current_entry_ext = ItemExtensions::default();
    let mut current_author = AtomPerson::new("");
    let mut current_content_type = String::from("text");
    let mut current_title_type = String::from("text");

    let mut text_buf = String::new();
    let mut _stack: Vec<String> = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let full_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                _stack.push(full_tag.clone());
                text_buf.clear();

                match full_tag.as_str() {
                    "entry" => {
                        in_entry = true;
                        current_entry_id = String::new();
                        current_entry_title = AtomText::text("");
                        current_entry_updated = Timestamp::UNIX_EPOCH;
                        current_entry_authors = Vec::new();
                        current_entry_links = Vec::new();
                        current_entry_summary = None;
                        current_entry_content = None;
                        current_entry_published = None;
                        current_entry_ext = ItemExtensions::default();
                    }
                    "author" => {
                        current_author = AtomPerson::new("");
                        if in_entry { in_author = true; } else { in_feed_author = true; }
                    }
                    "link" => {
                        let href = attr_value(&e, b"href").unwrap_or_default();
                        let rel = attr_value(&e, b"rel");
                        let type_ = attr_value(&e, b"type");
                        let length = attr_value(&e, b"length").and_then(|v| v.parse().ok());
                        let link = AtomLink { href, rel, type_, hreflang: None, title: None, length };
                        if in_entry { current_entry_links.push(link); } else { feed_links.push(link); }
                    }
                    "category" => {
                        let term = attr_value(&e, b"term").unwrap_or_default();
                        let scheme = attr_value(&e, b"scheme");
                        let label = attr_value(&e, b"label");
                        let cat = AtomCategory { term, scheme, label };
                        if !in_entry { feed_categories.push(cat); }
                    }
                    "title" => {
                        current_title_type = attr_value(&e, b"type").unwrap_or_else(|| "text".into());
                    }
                    "content" => {
                        current_content_type = attr_value(&e, b"type").unwrap_or_else(|| "text".into());
                    }
                    _ => {}
                }
            }
            Ok(Event::Empty(e)) => {
                let full_tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match full_tag.as_str() {
                    "link" => {
                        let href = attr_value(&e, b"href").unwrap_or_default();
                        let rel = attr_value(&e, b"rel");
                        let type_ = attr_value(&e, b"type");
                        let length = attr_value(&e, b"length").and_then(|v| v.parse().ok());
                        let link = AtomLink { href, rel, type_, hreflang: None, title: None, length };
                        if in_entry { current_entry_links.push(link); } else { feed_links.push(link); }
                    }
                    "category" => {
                        let term = attr_value(&e, b"term").unwrap_or_default();
                        let scheme = attr_value(&e, b"scheme");
                        let label = attr_value(&e, b"label");
                        let cat = AtomCategory { term, scheme, label };
                        if !in_entry { feed_categories.push(cat); }
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
                _stack.pop();
                let text = std::mem::take(&mut text_buf);

                if in_author {
                    match full_tag.as_str() {
                        "name" => current_author.name = text,
                        "email" => current_author.email = Some(text),
                        "uri" => current_author.uri = Some(text),
                        "author" => {
                            current_entry_authors.push(std::mem::replace(&mut current_author, AtomPerson::new("")));
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
                            feed_authors.push(std::mem::replace(&mut current_author, AtomPerson::new("")));
                            in_feed_author = false;
                        }
                        _ => {}
                    }
                } else if in_entry {
                    match full_tag.as_str() {
                        "id" => current_entry_id = text,
                        "title" => {
                            current_entry_title = make_atom_text(&current_title_type, text);
                        }
                        "updated" => {
                            current_entry_updated = parse_rfc3339_lax(&text)
                                .unwrap_or(Timestamp::UNIX_EPOCH);
                        }
                        "published" => {
                            current_entry_published = parse_rfc3339_lax(&text);
                        }
                        "summary" => {
                            current_entry_summary = Some(AtomText::text(text));
                        }
                        "content" => {
                            let at = make_atom_text(&current_content_type, text);
                            current_entry_content = Some(AtomContent { value: at, src: None });
                        }
                        "entry" => {
                            let entry = AtomEntry {
                                id: std::mem::take(&mut current_entry_id),
                                title: std::mem::replace(&mut current_entry_title, AtomText::text("")),
                                updated: current_entry_updated,
                                authors: std::mem::take(&mut current_entry_authors),
                                content: current_entry_content.take(),
                                links: std::mem::take(&mut current_entry_links),
                                summary: current_entry_summary.take(),
                                categories: Vec::new(),
                                contributors: Vec::new(),
                                published: current_entry_published,
                                rights: None,
                                source: None,
                                extensions: std::mem::take(&mut current_entry_ext),
                            };
                            entries.push(entry);
                            in_entry = false;
                        }
                        _ => {}
                    }
                } else {
                    match full_tag.as_str() {
                        "id" => feed_id = text,
                        "title" => {
                            feed_title = make_atom_text(&current_title_type, text);
                        }
                        "updated" => {
                            feed_updated = parse_rfc3339_lax(&text)
                                .unwrap_or(Timestamp::UNIX_EPOCH);
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

    if strict && feed_id.is_empty() {
        return Err(FeedParseError::new("Atom feed missing required <id>"));
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
        extensions: FeedExtensions::default(),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn attr_value(
    e: &quick_xml::events::BytesStart<'_>,
    name: &[u8],
) -> Option<String> {
    e.attributes()
        .filter_map(|a| a.ok())
        .find(|a| a.key.as_ref() == name)
        .and_then(|a| std::str::from_utf8(a.value.as_ref()).ok().map(str::to_owned))
}

fn parse_rss2_date(s: &str) -> Option<Timestamp> {
    use jiff::fmt::rfc2822;
    let s = s.trim();
    rfc2822::parse(s)
        .ok()
        .map(|zdt| zdt.timestamp())
        .or_else(|| parse_rfc3339_lax(s))
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
        let Feed::Rss2(rss) = feed else { panic!("expected RSS 2.0") };
        assert_eq!(rss.title, "My Blog");
        assert_eq!(rss.link, "https://example.com");
        assert_eq!(rss.items.len(), 1);
        assert_eq!(rss.items[0].title.as_deref(), Some("First Post"));
    }

    #[test]
    fn detects_and_parses_atom() {
        let feed = parse_feed(SAMPLE_ATOM, false).unwrap();
        let Feed::Atom(atom) = feed else { panic!("expected Atom") };
        assert_eq!(atom.id, "https://example.com/feed");
        assert_eq!(atom.entries.len(), 1);
        assert_eq!(atom.entries[0].id, "https://example.com/1");
    }

    #[test]
    fn strict_errors_on_missing_rss2_required_fields() {
        let result = parse_feed("<rss><channel><description>x</description></channel></rss>", true);
        assert!(result.is_err());
    }
}
