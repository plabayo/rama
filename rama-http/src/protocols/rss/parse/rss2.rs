//! RSS 2.0 event-loop parser.
//!
//! `parse_rss2` returns `(Rss2Feed, saw_root)` so the caller in
//! [`super`] can decide whether a document without a `<rss>`/`<channel>` root
//! should be rejected.

use jiff::Timestamp;
use quick_xml::{NsReader, events::Event};
use rama_core::telemetry::tracing;

use super::super::atom::AtomLink;
use super::super::ext_parse::{FeedExtAcc, ItemExtAcc, Ns, classify_ns};
use super::super::rss2::{Rss2Category, Rss2Feed, Rss2Guid, Rss2Image, Rss2Item, Rss2Source};
use super::FeedParseError;
use super::helpers::{atom_link_from_attrs, attr_value, enclosure_from_attrs, parse_rss2_date};

pub(crate) fn parse_rss2(input: &str, strict: bool) -> Result<(Rss2Feed, bool), FeedParseError> {
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
