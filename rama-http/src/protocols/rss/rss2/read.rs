//! Async streaming RSS 2.0 reader.
//!
//! [`Rss2FeedStream`] is the public type: its async constructor reads the
//! channel header up front and exposes the rest of the document as a stream
//! of [`Rss2Item`]s over the underlying [`AsyncBufRead`].

use std::pin::Pin;
use std::task::{Context, Poll};

use jiff::Timestamp;
use quick_xml::NsReader;
use quick_xml::events::Event;
use rama_core::futures::Stream;
use rama_core::futures::StreamExt as _;
use rama_core::futures::async_stream::stream_fn;
use rama_core::futures::stream::BoxStream;
use rama_core::telemetry::tracing;
use tokio::io::AsyncBufRead;

use super::super::atom::AtomLink;
use super::super::error::{CollectError, FeedParseError, Rss2CollectError};
use super::super::feed_ext::FeedExtensions;
use super::super::feed_ext::names::attr;
use super::super::feed_ext::parse::{FeedExtAcc, ItemExtAcc, Ns, classify_ns};
use super::super::parse_util::{attr_value, enclosure_from_attrs, parse_rss2_date};
use super::names::elem;
use super::{Rss2Category, Rss2Feed, Rss2Guid, Rss2Image, Rss2Item, Rss2Source};

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

/// Async streaming reader for an RSS 2.0 feed.
///
/// Construction reads the document up to (but not including) the first
/// `<item>`, so the parsed [`Rss2Channel`] is available immediately via
/// [`channel`](Self::channel). The stream then yields one [`Rss2Item`] per
/// channel item until the document ends.
///
/// The stream itself implements [`Stream<Item = Result<Rss2Item, _>>`], so
/// the usual combinators work; or you can split with [`drain`](Self::drain),
/// collect with [`collect`](Self::collect) / [`collect_lossy`](Self::collect_lossy),
/// or filter while collecting via [`collect_filtered`](Self::collect_filtered).
pub struct Rss2FeedStream {
    channel: Rss2Channel,
    items: BoxStream<'static, Result<Rss2Item, FeedParseError>>,
}

impl Rss2FeedStream {
    /// Build the stream over `reader` in lenient mode (unknown elements
    /// skipped, recoverable text issues tolerated).
    pub async fn new<R>(reader: R) -> Result<Self, FeedParseError>
    where
        R: AsyncBufRead + Unpin + Send + 'static,
    {
        Self::new_with_mode(reader, false).await
    }

    /// Strict variant — structural violations propagate as `Err`.
    pub async fn new_strict<R>(reader: R) -> Result<Self, FeedParseError>
    where
        R: AsyncBufRead + Unpin + Send + 'static,
    {
        Self::new_with_mode(reader, true).await
    }

    pub(in super::super) async fn new_with_mode<R>(
        reader: R,
        strict: bool,
    ) -> Result<Self, FeedParseError>
    where
        R: AsyncBufRead + Unpin + Send + 'static,
    {
        let mut state = Rss2Reader::new(reader, strict);
        let channel = state.read_channel().await?;
        let items: BoxStream<'static, Result<Rss2Item, FeedParseError>> =
            Box::pin(stream_fn(move |mut yielder| async move {
                let mut state = state;
                loop {
                    match state.read_next_item().await {
                        Ok(Some(item)) => yielder.yield_item(Ok(item)).await,
                        Ok(None) => return,
                        Err(e) => {
                            yielder.yield_item(Err(e)).await;
                            return;
                        }
                    }
                }
            }));
        Ok(Self { channel, items })
    }

    /// Borrow the channel-level metadata parsed at construction time.
    #[must_use]
    pub fn channel(&self) -> &Rss2Channel {
        &self.channel
    }

    /// Split into `(channel, items)` so the caller can map/filter/fold over
    /// the items without giving up the channel.
    #[must_use]
    pub fn drain(
        self,
    ) -> (
        Rss2Channel,
        BoxStream<'static, Result<Rss2Item, FeedParseError>>,
    ) {
        (self.channel, self.items)
    }

    /// Drain the stream into a complete in-memory [`Rss2Feed`]. On a per-item
    /// parse error, the returned [`Rss2CollectError`] carries every item
    /// successfully parsed so far together with the channel header.
    pub async fn collect(mut self) -> Result<Rss2Feed, Rss2CollectError> {
        let mut items = Vec::new();
        while let Some(item) = self.items.next().await {
            match item {
                Ok(it) => items.push(it),
                Err(error) => {
                    return Err(CollectError {
                        error,
                        partial: self.channel.into_feed_with_items(items),
                    });
                }
            }
        }
        Ok(self.channel.into_feed_with_items(items))
    }

    /// Drain the stream, dropping individual items that fail to parse and
    /// returning only the successful ones. Errors are logged at
    /// `tracing::debug!`; the function itself is infallible because the
    /// header was already parsed at construction time.
    pub async fn collect_lossy(mut self) -> Rss2Feed {
        let mut items = Vec::new();
        while let Some(item) = self.items.next().await {
            match item {
                Ok(it) => items.push(it),
                Err(err) => tracing::debug!(error = %err, "rss item dropped by collect_lossy"),
            }
        }
        self.channel.into_feed_with_items(items)
    }

    /// Drain the stream into a feed, retaining only items for which the
    /// predicate returns `true`. Per-item parse errors short-circuit with a
    /// partial feed, identical to [`collect`](Self::collect).
    pub async fn collect_filtered<F>(
        mut self,
        mut predicate: F,
    ) -> Result<Rss2Feed, Rss2CollectError>
    where
        F: FnMut(&Rss2Item) -> bool + Send,
    {
        let mut items = Vec::new();
        while let Some(item) = self.items.next().await {
            match item {
                Ok(it) => {
                    if predicate(&it) {
                        items.push(it);
                    }
                }
                Err(error) => {
                    return Err(CollectError {
                        error,
                        partial: self.channel.into_feed_with_items(items),
                    });
                }
            }
        }
        Ok(self.channel.into_feed_with_items(items))
    }
}

impl Stream for Rss2FeedStream {
    type Item = Result<Rss2Item, FeedParseError>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = Pin::into_inner(self);
        this.items.poll_next_unpin(cx)
    }
}

// ---------------------------------------------------------------------------
// Rss2Reader: the actual XML state machine. Private.
// ---------------------------------------------------------------------------

/// What [`Rss2Reader::step`] did with the event it just consumed.
enum Action {
    /// Keep reading; no observable result yet.
    Continue,
    /// First `<item>` Start was just consumed. Only meaningful in channel
    /// phase; signals the caller to return the channel.
    FirstItemStarted,
    /// `</item>` End was just consumed. Only meaningful in item phase.
    /// Boxed so the enum stays small (a finished `Rss2Item` is ~1.3 KB).
    ItemFinished(Box<Rss2Item>),
    /// `Event::Eof` was just consumed or an XML error broke the lenient loop.
    Eof,
}

struct Rss2Reader<R: AsyncBufRead + Unpin + Send> {
    nsr: NsReader<R>,
    buf: Vec<u8>,
    strict: bool,

    // Cross-event state.
    text_buf: String,
    depth: i32,
    saw_root: bool,

    // Channel accumulator (drained on `read_channel` return).
    channel: Rss2Channel,
    feed_acc: FeedExtAcc,

    // `<image>` sub-state — collected into `channel.image` on `</image>`.
    in_image_block: bool,
    image_url: String,
    image_title: String,
    image_link: String,
    image_width: Option<u32>,
    image_height: Option<u32>,
    image_description: Option<String>,

    // Item accumulator (drained on `</item>`).
    in_item: bool,
    current_item: Rss2Item,
    item_acc: ItemExtAcc,

    // Pending attributes carried from a Start until the matching End/text.
    pending_category_domain: Option<String>,
    pending_source_url: Option<String>,
}

impl<R: AsyncBufRead + Unpin + Send> Rss2Reader<R> {
    fn new(reader: R, strict: bool) -> Self {
        let mut nsr = NsReader::from_reader(reader);
        nsr.config_mut().trim_text(true);
        Self {
            nsr,
            buf: Vec::with_capacity(4096),
            strict,
            text_buf: String::new(),
            depth: 0,
            saw_root: false,
            channel: Rss2Channel::default(),
            feed_acc: FeedExtAcc::default(),
            in_image_block: false,
            image_url: String::new(),
            image_title: String::new(),
            image_link: String::new(),
            image_width: None,
            image_height: None,
            image_description: None,
            in_item: false,
            current_item: Rss2Item::default(),
            item_acc: ItemExtAcc::default(),
            pending_category_domain: None,
            pending_source_url: None,
        }
    }

    /// Read events until the first `<item>` opens (returns the channel as it
    /// stood just before), or until the document ends with no items at all
    /// (returns the channel anyway).
    async fn read_channel(&mut self) -> Result<Rss2Channel, FeedParseError> {
        loop {
            match self.step().await? {
                Action::Continue => {}
                Action::FirstItemStarted | Action::Eof => {
                    return self.take_channel();
                }
                Action::ItemFinished(_) => {
                    // Can't happen here: we haven't entered any item yet.
                    return Err(FeedParseError::new(
                        "internal: item finished during channel phase",
                    ));
                }
            }
        }
    }

    /// Read events until the next `</item>` finalises an item, or until EOF.
    async fn read_next_item(&mut self) -> Result<Option<Rss2Item>, FeedParseError> {
        loop {
            match self.step().await? {
                // FirstItemStarted falls in here too: the first `<item>` is
                // opened at channel-phase return, and any *subsequent* `<item>`
                // Start while we're already in_item is malformed input. We've
                // already absorbed it as a new item context (flushing whatever
                // the outer item had); keep reading.
                Action::Continue | Action::FirstItemStarted => {}
                Action::ItemFinished(item) => return Ok(Some(*item)),
                Action::Eof => return Ok(None),
            }
        }
    }

    /// Move the channel header out (consuming the accumulated extensions) and
    /// validate strict-mode requirements.
    fn take_channel(&mut self) -> Result<Rss2Channel, FeedParseError> {
        if !self.saw_root {
            return Err(FeedParseError::new("no <rss>/<channel> root encountered"));
        }
        let mut channel = std::mem::take(&mut self.channel);
        channel.extensions = std::mem::take(&mut self.feed_acc).finish();
        if self.strict {
            if channel.title.is_empty() {
                return Err(FeedParseError::new(
                    "RSS 2.0 channel missing required <title>",
                ));
            }
            if channel.link.is_empty() {
                return Err(FeedParseError::new(
                    "RSS 2.0 channel missing required <link>",
                ));
            }
        }
        Ok(channel)
    }

    /// Read one XML event, mutate state, and report what happened.
    async fn step(&mut self) -> Result<Action, FeedParseError> {
        self.buf.clear();
        let (rr, ev) = match self.nsr.read_resolved_event_into_async(&mut self.buf).await {
            Ok(p) => p,
            Err(e) => {
                if self.strict {
                    return Err(FeedParseError::new(format!("xml error: {e}")));
                }
                tracing::debug!("rss2 stream xml error (lenient): {e}");
                return Ok(Action::Eof);
            }
        };

        match ev {
            Event::Start(e) => {
                self.depth += 1;
                let ns = classify_ns(&rr);
                let local_name = e.local_name();
                let local = std::str::from_utf8(local_name.as_ref()).unwrap_or("");
                self.text_buf.clear();

                let consumed = if self.in_item {
                    self.item_acc.on_start(ns, local, &e)
                } else {
                    self.feed_acc.on_start(ns, local, &e)
                };
                if !consumed && !self.in_item && ns == Ns::Atom && local == "link" {
                    self.channel
                        .atom_links
                        .push(super::super::parse_util::atom_link_from_attrs(&e));
                    return Ok(Action::Continue);
                }
                if consumed || ns != Ns::None {
                    return Ok(Action::Continue);
                }

                match local {
                    elem::RSS | elem::CHANNEL => {
                        self.saw_root = true;
                        Ok(Action::Continue)
                    }
                    elem::ITEM => {
                        // Entering a new item context: finalise the channel
                        // header (if not yet flushed) and reset per-item state.
                        let first_item = !self.in_item;
                        self.in_item = true;
                        self.current_item = Rss2Item::default();
                        self.item_acc = ItemExtAcc::default();
                        if first_item {
                            Ok(Action::FirstItemStarted)
                        } else {
                            // Nested / re-opened <item> in malformed input;
                            // we silently reset and keep going.
                            Ok(Action::Continue)
                        }
                    }
                    elem::IMAGE if !self.in_item => {
                        self.in_image_block = true;
                        Ok(Action::Continue)
                    }
                    elem::ENCLOSURE if self.in_item => {
                        self.current_item.enclosures.push(enclosure_from_attrs(&e));
                        Ok(Action::Continue)
                    }
                    elem::GUID if self.in_item => {
                        let permalink = attr_value(&e, attr::IS_PERMALINK)
                            .map(|v| v != "false")
                            .unwrap_or(true);
                        self.current_item.guid = Some(Rss2Guid {
                            value: String::new(),
                            permalink,
                        });
                        Ok(Action::Continue)
                    }
                    elem::SOURCE if self.in_item => {
                        self.pending_source_url = attr_value(&e, attr::URL);
                        Ok(Action::Continue)
                    }
                    elem::CATEGORY => {
                        self.pending_category_domain = attr_value(&e, attr::DOMAIN);
                        Ok(Action::Continue)
                    }
                    _ => Ok(Action::Continue),
                }
            }
            Event::Empty(e) => {
                let ns = classify_ns(&rr);
                let local_name = e.local_name();
                let local = std::str::from_utf8(local_name.as_ref()).unwrap_or("");

                let consumed = if self.in_item {
                    self.item_acc.on_empty(ns, local, &e)
                } else {
                    self.feed_acc.on_empty(ns, local, &e)
                };
                if consumed {
                    return Ok(Action::Continue);
                }
                if !self.in_item && ns == Ns::Atom && local == "link" {
                    self.channel
                        .atom_links
                        .push(super::super::parse_util::atom_link_from_attrs(&e));
                    return Ok(Action::Continue);
                }
                if ns == Ns::None && self.in_item && local == "enclosure" {
                    self.current_item.enclosures.push(enclosure_from_attrs(&e));
                }
                Ok(Action::Continue)
            }
            Event::Text(e) => {
                match e.unescape() {
                    Ok(t) => self.text_buf.push_str(&t),
                    Err(err) => {
                        if self.strict {
                            return Err(FeedParseError::new(format!(
                                "invalid text content: {err}"
                            )));
                        }
                        tracing::debug!("rss2 stream unescape error (lenient): {err}");
                        self.text_buf.push_str(&String::from_utf8_lossy(e.as_ref()));
                    }
                }
                Ok(Action::Continue)
            }
            Event::CData(e) => {
                match std::str::from_utf8(e.as_ref()) {
                    Ok(t) => self.text_buf.push_str(t),
                    Err(err) => {
                        if self.strict {
                            return Err(FeedParseError::new(format!("invalid CDATA: {err}")));
                        }
                        tracing::debug!("rss2 stream CDATA utf8 error (lenient): {err}");
                        self.text_buf.push_str(&String::from_utf8_lossy(e.as_ref()));
                    }
                }
                Ok(Action::Continue)
            }
            Event::End(e) => {
                self.depth -= 1;
                let ns = classify_ns(&rr);
                let local = std::str::from_utf8(e.local_name().as_ref())
                    .map(str::to_owned)
                    .unwrap_or_default();
                let text = std::mem::take(&mut self.text_buf);
                drop(e);
                self.handle_end(ns, &local, text)
            }
            Event::Eof => {
                if self.strict && self.depth > 0 {
                    return Err(FeedParseError::new(format!(
                        "truncated RSS 2.0 document ({} unclosed elements at EOF)",
                        self.depth
                    )));
                }
                Ok(Action::Eof)
            }
            _ => Ok(Action::Continue),
        }
    }

    fn handle_end(&mut self, ns: Ns, local: &str, text: String) -> Result<Action, FeedParseError> {
        if self.in_item {
            let Some(text) = self.item_acc.on_end(ns, local, text) else {
                return Ok(Action::Continue);
            };
            if ns != Ns::None {
                return Ok(Action::Continue);
            }
            match local {
                elem::TITLE => self.current_item.title = Some(text),
                elem::LINK => self.current_item.link = Some(text),
                elem::DESCRIPTION => self.current_item.description = Some(text),
                elem::AUTHOR => self.current_item.author = Some(text),
                elem::COMMENTS => self.current_item.comments = Some(text),
                elem::PUB_DATE => self.current_item.pub_date = parse_rss2_date(&text),
                elem::GUID => {
                    if let Some(guid) = &mut self.current_item.guid {
                        guid.value = text;
                    }
                }
                elem::CATEGORY => self.current_item.categories.push(Rss2Category {
                    name: text,
                    domain: self.pending_category_domain.take(),
                }),
                elem::SOURCE => {
                    self.current_item.source = Some(Rss2Source {
                        title: text,
                        url: self.pending_source_url.take().unwrap_or_default(),
                    });
                }
                elem::ITEM => {
                    self.current_item.extensions = std::mem::take(&mut self.item_acc).finish();
                    let item = std::mem::take(&mut self.current_item);
                    self.in_item = false;
                    return Ok(Action::ItemFinished(Box::new(item)));
                }
                _ => {}
            }
        } else if self.in_image_block {
            match local {
                elem::URL => self.image_url = text,
                elem::TITLE => self.image_title = text,
                elem::LINK => self.image_link = text,
                elem::WIDTH => self.image_width = text.parse().ok(),
                elem::HEIGHT => self.image_height = text.parse().ok(),
                elem::DESCRIPTION => self.image_description = Some(text),
                elem::IMAGE => {
                    self.in_image_block = false;
                    self.channel.image = Some(Rss2Image {
                        url: std::mem::take(&mut self.image_url),
                        title: std::mem::take(&mut self.image_title),
                        link: std::mem::take(&mut self.image_link),
                        width: self.image_width.take(),
                        height: self.image_height.take(),
                        description: self.image_description.take(),
                    });
                }
                _ => {}
            }
        } else {
            let Some(text) = self.feed_acc.on_end(ns, local, text) else {
                return Ok(Action::Continue);
            };
            if ns != Ns::None {
                return Ok(Action::Continue);
            }
            match local {
                elem::TITLE => self.channel.title = text,
                elem::LINK => self.channel.link = text,
                elem::DESCRIPTION => self.channel.description = text,
                elem::LANGUAGE => self.channel.language = Some(text),
                elem::COPYRIGHT => self.channel.copyright = Some(text),
                elem::MANAGING_EDITOR => self.channel.managing_editor = Some(text),
                elem::WEB_MASTER => self.channel.web_master = Some(text),
                elem::PUB_DATE => self.channel.pub_date = parse_rss2_date(&text),
                elem::LAST_BUILD_DATE => self.channel.last_build_date = parse_rss2_date(&text),
                elem::GENERATOR => self.channel.generator = Some(text),
                elem::TTL => self.channel.ttl = text.parse().ok(),
                elem::DOCS => self.channel.docs = Some(text),
                elem::CATEGORY => self.channel.categories.push(Rss2Category {
                    name: text,
                    domain: self.pending_category_domain.take(),
                }),
                _ => {}
            }
        }
        Ok(Action::Continue)
    }
}
