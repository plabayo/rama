//! Async streaming RSS 2.0 reader.
//!
//! [`rss2_event_stream`] consumes an [`AsyncBufRead`] of RSS 2.0 bytes and
//! yields a [`Rss2ReadEvent::Channel`] with the channel-level metadata gathered
//! up to (and excluding) the first `<item>`, then one [`Rss2ReadEvent::Item`]
//! per channel item, then [`Rss2ReadEvent::Eof`]. The state-machine mirrors
//! the sync [`super::super::parse`] event loop but never holds more than one
//! item in memory.
//!
//! [`collect_rss2`] is the in-memory adapter: it drains a stream into an
//! [`Rss2Feed`].

use jiff::Timestamp;
use quick_xml::NsReader;
use quick_xml::events::Event;
use rama_core::futures::Stream;
use rama_core::futures::async_stream::stream_fn;
use rama_core::telemetry::tracing;
use tokio::io::AsyncBufRead;

use super::super::atom::AtomLink;
use super::super::ext_parse::{FeedExtAcc, ItemExtAcc, Ns, classify_ns};
use super::super::feed_ext::FeedExtensions;
use super::super::parse::{Attrs, FeedParseError, attr_value, parse_rss2_date};
use super::super::rss2::{
    Rss2Category, Rss2Enclosure, Rss2Feed, Rss2Guid, Rss2Image, Rss2Item, Rss2Source,
};

/// Channel-level metadata of an RSS 2.0 feed — everything an [`Rss2Feed`]
/// carries *except* its `items`. Re-combine with item events via
/// [`Rss2Channel::into_feed_with_items`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Rss2Channel {
    pub title: String,
    pub link: String,
    pub description: String,
    pub language: Option<String>,
    pub copyright: Option<String>,
    pub managing_editor: Option<String>,
    pub web_master: Option<String>,
    pub pub_date: Option<Timestamp>,
    pub last_build_date: Option<Timestamp>,
    pub categories: Vec<Rss2Category>,
    pub generator: Option<String>,
    pub docs: Option<String>,
    pub ttl: Option<u32>,
    pub image: Option<Rss2Image>,
    pub atom_links: Vec<AtomLink>,
    pub extensions: FeedExtensions,
}

impl Rss2Channel {
    /// Combine this channel header with an iterator of items into a full feed.
    #[must_use]
    pub fn into_feed_with_items<I>(self, items: I) -> Rss2Feed
    where
        I: IntoIterator<Item = Rss2Item>,
    {
        Rss2Feed {
            title: self.title,
            link: self.link,
            description: self.description,
            language: self.language,
            copyright: self.copyright,
            managing_editor: self.managing_editor,
            web_master: self.web_master,
            pub_date: self.pub_date,
            last_build_date: self.last_build_date,
            categories: self.categories,
            generator: self.generator,
            docs: self.docs,
            ttl: self.ttl,
            image: self.image,
            atom_links: self.atom_links,
            items: items.into_iter().collect(),
            extensions: self.extensions,
        }
    }
}

/// One step of an RSS 2.0 streaming parse.
#[derive(Debug, Clone, PartialEq)]
#[expect(
    clippy::large_enum_variant,
    reason = "internal event type: the size disparity (Channel vs. boxed Item) only \
              lives across one yield boundary inside the stream, not in user-visible APIs"
)]
pub(super) enum Rss2ReadEvent {
    /// The channel-level metadata, emitted exactly once before any
    /// [`Item`](Self::Item) event.
    Channel(Rss2Channel),
    /// One fully-parsed `<item>`.
    Item(Box<Rss2Item>),
    /// End of feed (the matching `</rss>` end or EOF in lenient mode).
    Eof,
}

/// Construct an async stream that yields RSS 2.0 events from `reader`.
///
/// `strict = true` propagates structural violations (missing required fields,
/// unparseable entities, …) as `Err`. `strict = false` is lenient: unknown
/// elements are skipped and recoverable text is preserved.
pub(super) fn rss2_event_stream<R>(
    reader: R,
    strict: bool,
) -> impl Stream<Item = Result<Rss2ReadEvent, FeedParseError>> + Send
where
    R: AsyncBufRead + Unpin + Send + 'static,
{
    stream_fn(move |mut yielder| async move {
        let mut nsr = NsReader::from_reader(reader);
        nsr.config_mut().trim_text(true);
        let mut buf: Vec<u8> = Vec::with_capacity(4096);

        // Channel state — yielded as `Rss2ReadEvent::Channel(...)` once we
        // first cross into item territory (or at EOF for an item-less feed).
        let mut channel = Rss2Channel::default();
        let mut feed_acc = FeedExtAcc::default();
        let mut channel_yielded = false;
        let mut saw_root = false;

        // <image> sub-state.
        let mut in_image_block = false;
        let mut image_url = String::new();
        let mut image_title = String::new();
        let mut image_link = String::new();
        let mut image_width: Option<u32> = None;
        let mut image_height: Option<u32> = None;
        let mut image_description: Option<String> = None;

        // Per-item state.
        let mut in_item = false;
        let mut current_item = Rss2Item::default();
        let mut item_acc = ItemExtAcc::default();

        // Pending attributes for elements whose text arrives later.
        let mut pending_category_domain: Option<String> = None;
        let mut pending_source_url: Option<String> = None;

        let mut text_buf = String::new();
        let mut depth: i32 = 0;

        macro_rules! yield_err {
            ($expr:expr) => {{
                yielder.yield_item(Err($expr)).await;
                return;
            }};
        }

        // Flush channel metadata gathered so far as the first event. Called on
        // first `<item>` Start (or on EOF for an item-less feed).
        macro_rules! flush_channel {
            ($channel:expr, $feed_acc:expr, $channel_yielded:expr) => {{
                if !$channel_yielded {
                    let mut chan = std::mem::take($channel);
                    chan.extensions = std::mem::take($feed_acc).finish();
                    $channel_yielded = true;
                    yielder.yield_item(Ok(Rss2ReadEvent::Channel(chan))).await;
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
                    tracing::debug!("rss2 stream xml error (lenient): {e}");
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

                    let consumed = if in_item {
                        item_acc.on_start(ns, local, &e)
                    } else {
                        feed_acc.on_start(ns, local, &e)
                    };
                    if !consumed && !in_item && ns == Ns::Atom && local == "link" {
                        channel.atom_links.push(atom_link_from_attrs(&e));
                        continue;
                    }
                    if consumed || ns != Ns::None {
                        continue;
                    }

                    match local {
                        "rss" | "channel" => saw_root = true,
                        "item" => {
                            flush_channel!(&mut channel, &mut feed_acc, channel_yielded);
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
                            current_item.guid = Some(Rss2Guid {
                                value: String::new(),
                                permalink,
                            });
                        }
                        "source" if in_item => {
                            pending_source_url = attr_value(&e, b"url");
                        }
                        "category" => pending_category_domain = attr_value(&e, b"domain"),
                        _ => {}
                    }
                }
                Event::Empty(e) => {
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
                        channel.atom_links.push(atom_link_from_attrs(&e));
                        continue;
                    }
                    if ns == Ns::None && in_item && local == "enclosure" {
                        current_item.enclosures.push(enclosure_from_attrs(&e));
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
                        tracing::debug!("rss2 stream unescape error (lenient): {err}");
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
                        tracing::debug!("rss2 stream CDATA utf8 error (lenient): {err}");
                        text_buf.push_str(&String::from_utf8_lossy(e.as_ref()));
                    }
                },
                Event::End(e) => {
                    depth -= 1;
                    let ns = classify_ns(&rr);
                    let local_name = e.local_name();
                    let local = std::str::from_utf8(local_name.as_ref()).unwrap_or("");
                    let text = std::mem::take(&mut text_buf);

                    if in_item {
                        let Some(text) = item_acc.on_end(ns, local, text) else {
                            continue;
                        };
                        if ns != Ns::None {
                            continue;
                        }
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
                                let item = std::mem::take(&mut current_item);
                                in_item = false;
                                yielder
                                    .yield_item(Ok(Rss2ReadEvent::Item(Box::new(item))))
                                    .await;
                            }
                            _ => {}
                        }
                    } else if in_image_block {
                        match local {
                            "url" => image_url = text,
                            "title" => image_title = text,
                            "link" => image_link = text,
                            "width" => image_width = text.parse().ok(),
                            "height" => image_height = text.parse().ok(),
                            "description" => image_description = Some(text),
                            "image" => {
                                in_image_block = false;
                                channel.image = Some(Rss2Image {
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
                        let Some(text) = feed_acc.on_end(ns, local, text) else {
                            continue;
                        };
                        if ns != Ns::None {
                            continue;
                        }
                        match local {
                            "title" => channel.title = text,
                            "link" => channel.link = text,
                            "description" => channel.description = text,
                            "language" => channel.language = Some(text),
                            "copyright" => channel.copyright = Some(text),
                            "managingEditor" => channel.managing_editor = Some(text),
                            "webMaster" => channel.web_master = Some(text),
                            "pubDate" => channel.pub_date = parse_rss2_date(&text),
                            "lastBuildDate" => channel.last_build_date = parse_rss2_date(&text),
                            "generator" => channel.generator = Some(text),
                            "ttl" => channel.ttl = text.parse().ok(),
                            "docs" => channel.docs = Some(text),
                            "category" => channel.categories.push(Rss2Category {
                                name: text,
                                domain: pending_category_domain.take(),
                            }),
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
                message: format!("truncated RSS 2.0 document ({depth} unclosed elements at EOF)"),
            });
        }
        if strict && channel.title.is_empty() {
            yield_err!(FeedParseError {
                message: "RSS 2.0 channel missing required <title>".to_owned(),
            });
        }
        if strict && channel.link.is_empty() {
            yield_err!(FeedParseError {
                message: "RSS 2.0 channel missing required <link>".to_owned(),
            });
        }
        if !saw_root {
            // Lenient mode reaching EOF without ever seeing <rss>/<channel> —
            // not an RSS document. Collect adapters surface this as Err.
            return;
        }

        // Item-less feed: still emit the channel header so collect() sees it.
        if !channel_yielded {
            let mut chan = std::mem::take(&mut channel);
            chan.extensions = std::mem::take(&mut feed_acc).finish();
            yielder.yield_item(Ok(Rss2ReadEvent::Channel(chan))).await;
        }
        yielder.yield_item(Ok(Rss2ReadEvent::Eof)).await;
    })
}

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
