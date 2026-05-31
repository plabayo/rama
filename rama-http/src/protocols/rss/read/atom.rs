//! Async streaming Atom 1.0 reader.
//!
//! Same shape as the RSS 2.0 reader: header is read at construction time,
//! [`AtomEntry`]s stream after.

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

use super::super::atom::{
    AtomCategory, AtomContent, AtomEntry, AtomFeed, AtomGenerator, AtomLink, AtomPerson,
    AtomSource, AtomText,
};
use super::super::error::{AtomCollectError, CollectError, FeedParseError};
use super::super::ext_names::attr;
use super::super::ext_parse::{FeedExtAcc, ItemExtAcc, Ns, classify_ns};
use super::super::feed_ext::FeedExtensions;
use super::super::parse_util::{
    atom_category_from_attrs, atom_link_from_attrs, attr_value, make_atom_text, parse_rfc3339_lax,
};

/// Feed-level metadata of an Atom 1.0 document — everything an [`AtomFeed`]
/// carries except its `entries`.
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
    /// Combine this feed header with an iterator of entries into a full
    /// [`AtomFeed`].
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

/// Async streaming reader for an Atom 1.0 feed.
pub struct AtomFeedStream {
    header: AtomHeader,
    entries: BoxStream<'static, Result<AtomEntry, FeedParseError>>,
}

impl AtomFeedStream {
    pub async fn new<R>(reader: R) -> Result<Self, FeedParseError>
    where
        R: AsyncBufRead + Unpin + Send + 'static,
    {
        Self::new_with_mode(reader, false).await
    }

    pub async fn new_strict<R>(reader: R) -> Result<Self, FeedParseError>
    where
        R: AsyncBufRead + Unpin + Send + 'static,
    {
        Self::new_with_mode(reader, true).await
    }

    pub(super) async fn new_with_mode<R>(reader: R, strict: bool) -> Result<Self, FeedParseError>
    where
        R: AsyncBufRead + Unpin + Send + 'static,
    {
        let mut state = AtomReader::new(reader, strict);
        let header = state.read_header().await?;
        let entries: BoxStream<'static, Result<AtomEntry, FeedParseError>> =
            Box::pin(stream_fn(move |mut yielder| async move {
                let mut state = state;
                loop {
                    match state.read_next_entry().await {
                        Ok(Some(entry)) => yielder.yield_item(Ok(entry)).await,
                        Ok(None) => return,
                        Err(e) => {
                            yielder.yield_item(Err(e)).await;
                            return;
                        }
                    }
                }
            }));
        Ok(Self { header, entries })
    }

    /// Borrow the feed-level metadata parsed at construction time.
    #[must_use]
    pub fn header(&self) -> &AtomHeader {
        &self.header
    }

    /// Split into `(header, entries)`.
    #[must_use]
    pub fn drain(
        self,
    ) -> (
        AtomHeader,
        BoxStream<'static, Result<AtomEntry, FeedParseError>>,
    ) {
        (self.header, self.entries)
    }

    /// Drain into a full [`AtomFeed`]; on per-entry error returns a partial
    /// feed with everything parsed so far.
    pub async fn collect(mut self) -> Result<AtomFeed, AtomCollectError> {
        let mut entries = Vec::new();
        while let Some(entry) = self.entries.next().await {
            match entry {
                Ok(e) => entries.push(e),
                Err(error) => {
                    return Err(CollectError {
                        error,
                        partial: self.header.into_feed_with_entries(entries),
                    });
                }
            }
        }
        Ok(self.header.into_feed_with_entries(entries))
    }

    /// Drain, silently dropping (and `tracing::debug!`-logging) entries that
    /// fail to parse.
    pub async fn collect_lossy(mut self) -> AtomFeed {
        let mut entries = Vec::new();
        while let Some(entry) = self.entries.next().await {
            match entry {
                Ok(e) => entries.push(e),
                Err(err) => tracing::debug!(error = %err, "atom entry dropped by collect_lossy"),
            }
        }
        self.header.into_feed_with_entries(entries)
    }

    /// Drain into a feed retaining only entries the predicate accepts.
    pub async fn collect_filtered<F>(
        mut self,
        mut predicate: F,
    ) -> Result<AtomFeed, AtomCollectError>
    where
        F: FnMut(&AtomEntry) -> bool + Send,
    {
        let mut entries = Vec::new();
        while let Some(entry) = self.entries.next().await {
            match entry {
                Ok(e) => {
                    if predicate(&e) {
                        entries.push(e);
                    }
                }
                Err(error) => {
                    return Err(CollectError {
                        error,
                        partial: self.header.into_feed_with_entries(entries),
                    });
                }
            }
        }
        Ok(self.header.into_feed_with_entries(entries))
    }
}

impl Stream for AtomFeedStream {
    type Item = Result<AtomEntry, FeedParseError>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = Pin::into_inner(self);
        this.entries.poll_next_unpin(cx)
    }
}

// ---------------------------------------------------------------------------
// AtomReader: state machine. Private.
// ---------------------------------------------------------------------------

enum Action {
    Continue,
    FirstEntryStarted,
    /// Boxed so the enum stays small (a finished `AtomEntry` is ~1.3 KB).
    EntryFinished(Box<AtomEntry>),
    Eof,
}

struct AtomReader<R: AsyncBufRead + Unpin + Send> {
    nsr: NsReader<R>,
    buf: Vec<u8>,
    strict: bool,

    text_buf: String,
    depth: i32,
    saw_root: bool,
    feed_updated_parsed: bool,

    // Feed-level header accumulator.
    header: AtomHeader,
    feed_acc: FeedExtAcc,
    pending_generator: Option<AtomGenerator>,

    // Entry / sub-element state.
    in_entry: bool,
    current_entry: AtomEntry,
    current_entry_id_set: bool,
    current_entry_title_set: bool,
    current_entry_updated_parsed: bool,
    entry_acc: ItemExtAcc,
    in_author: bool,
    in_feed_author: bool,
    in_contributor: bool,
    in_feed_contributor: bool,
    current_author: AtomPerson,
    current_contributor: AtomPerson,
    in_source: bool,
    current_source: AtomSource,

    current_title_type: String,
    current_summary_type: String,
    current_content_type: String,
    current_rights_type: String,
    current_subtitle_type: String,
}

impl<R: AsyncBufRead + Unpin + Send> AtomReader<R> {
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
            feed_updated_parsed: false,
            header: AtomHeader::default(),
            feed_acc: FeedExtAcc::default(),
            pending_generator: None,
            in_entry: false,
            current_entry: AtomEntry::new("", AtomText::text(""), Timestamp::UNIX_EPOCH),
            current_entry_id_set: false,
            current_entry_title_set: false,
            current_entry_updated_parsed: false,
            entry_acc: ItemExtAcc::default(),
            in_author: false,
            in_feed_author: false,
            in_contributor: false,
            in_feed_contributor: false,
            current_author: AtomPerson::new(""),
            current_contributor: AtomPerson::new(""),
            in_source: false,
            current_source: AtomSource {
                id: None,
                title: None,
                updated: None,
            },
            current_title_type: String::from("text"),
            current_summary_type: String::from("text"),
            current_content_type: String::from("text"),
            current_rights_type: String::from("text"),
            current_subtitle_type: String::from("text"),
        }
    }

    async fn read_header(&mut self) -> Result<AtomHeader, FeedParseError> {
        loop {
            match self.step().await? {
                Action::Continue => {}
                Action::FirstEntryStarted | Action::Eof => return self.take_header(),
                Action::EntryFinished(_) => {
                    return Err(FeedParseError::new(
                        "internal: entry finished during header phase",
                    ));
                }
            }
        }
    }

    async fn read_next_entry(&mut self) -> Result<Option<AtomEntry>, FeedParseError> {
        loop {
            match self.step().await? {
                Action::Continue | Action::FirstEntryStarted => {}
                Action::EntryFinished(entry) => return Ok(Some(*entry)),
                Action::Eof => return Ok(None),
            }
        }
    }

    fn take_header(&mut self) -> Result<AtomHeader, FeedParseError> {
        if !self.saw_root {
            return Err(FeedParseError::new("no <feed> root encountered"));
        }
        let mut header = std::mem::take(&mut self.header);
        header.extensions = std::mem::take(&mut self.feed_acc).finish();
        if self.strict {
            if header.id.is_empty() {
                return Err(FeedParseError::new("Atom feed missing required <id>"));
            }
            if header.title.value.is_empty() {
                return Err(FeedParseError::new("Atom feed missing required <title>"));
            }
            if !self.feed_updated_parsed {
                return Err(FeedParseError::new("Atom feed missing required <updated>"));
            }
        }
        Ok(header)
    }

    async fn step(&mut self) -> Result<Action, FeedParseError> {
        self.buf.clear();
        let (rr, ev) = match self.nsr.read_resolved_event_into_async(&mut self.buf).await {
            Ok(p) => p,
            Err(e) => {
                if self.strict {
                    return Err(FeedParseError::new(format!("xml error: {e}")));
                }
                tracing::debug!("atom stream xml error (lenient): {e}");
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

                let consumed = if self.in_entry {
                    self.entry_acc.on_start(ns, local, &e)
                } else {
                    self.feed_acc.on_start(ns, local, &e)
                };
                if consumed {
                    return Ok(Action::Continue);
                }
                if ns != Ns::Atom {
                    return Ok(Action::Continue);
                }

                match local {
                    "feed" => {
                        self.saw_root = true;
                        Ok(Action::Continue)
                    }
                    "entry" => {
                        let first_entry = !self.in_entry;
                        self.in_entry = true;
                        self.current_entry =
                            AtomEntry::new("", AtomText::text(""), Timestamp::UNIX_EPOCH);
                        self.current_entry_id_set = false;
                        self.current_entry_title_set = false;
                        self.current_entry_updated_parsed = false;
                        self.entry_acc = ItemExtAcc::default();
                        if first_entry {
                            Ok(Action::FirstEntryStarted)
                        } else {
                            Ok(Action::Continue)
                        }
                    }
                    "author" if !self.in_source => {
                        self.current_author = AtomPerson::new("");
                        if self.in_entry {
                            self.in_author = true;
                        } else {
                            self.in_feed_author = true;
                        }
                        Ok(Action::Continue)
                    }
                    "contributor" if !self.in_source => {
                        self.current_contributor = AtomPerson::new("");
                        if self.in_entry {
                            self.in_contributor = true;
                        } else {
                            self.in_feed_contributor = true;
                        }
                        Ok(Action::Continue)
                    }
                    "source" if self.in_entry && !self.in_source => {
                        self.in_source = true;
                        self.current_source = AtomSource {
                            id: None,
                            title: None,
                            updated: None,
                        };
                        Ok(Action::Continue)
                    }
                    "link" if !self.in_source => {
                        let link = atom_link_from_attrs(&e);
                        if self.in_entry {
                            self.current_entry.links.push(link);
                        } else {
                            self.header.links.push(link);
                        }
                        Ok(Action::Continue)
                    }
                    "category" if !self.in_source => {
                        let cat = atom_category_from_attrs(&e);
                        if self.in_entry {
                            self.current_entry.categories.push(cat);
                        } else {
                            self.header.categories.push(cat);
                        }
                        Ok(Action::Continue)
                    }
                    "title" => {
                        let t = attr_value(&e, attr::TYPE).unwrap_or_else(|| "text".into());
                        drop(e);
                        self.start_typed_text("title", t).await
                    }
                    "summary" if self.in_entry => {
                        let t = attr_value(&e, attr::TYPE).unwrap_or_else(|| "text".into());
                        drop(e);
                        self.start_typed_text("summary", t).await
                    }
                    "content" if self.in_entry && !self.in_source => {
                        let t = attr_value(&e, attr::TYPE).unwrap_or_else(|| "text".into());
                        drop(e);
                        self.start_typed_text("content", t).await
                    }
                    "rights" => {
                        let t = attr_value(&e, attr::TYPE).unwrap_or_else(|| "text".into());
                        drop(e);
                        self.start_typed_text("rights", t).await
                    }
                    "subtitle" if !self.in_entry => {
                        let t = attr_value(&e, attr::TYPE).unwrap_or_else(|| "text".into());
                        drop(e);
                        self.start_typed_text("subtitle", t).await
                    }
                    "generator" if !self.in_source => {
                        self.pending_generator = Some(AtomGenerator {
                            value: String::new(),
                            uri: attr_value(&e, attr::URI),
                            version: attr_value(&e, attr::VERSION),
                        });
                        Ok(Action::Continue)
                    }
                    _ => Ok(Action::Continue),
                }
            }
            Event::Empty(e) => {
                let ns = classify_ns(&rr);
                let local_name = e.local_name();
                let local = std::str::from_utf8(local_name.as_ref()).unwrap_or("");

                let consumed = if self.in_entry {
                    self.entry_acc.on_empty(ns, local, &e)
                } else {
                    self.feed_acc.on_empty(ns, local, &e)
                };
                if consumed || ns != Ns::Atom {
                    return Ok(Action::Continue);
                }
                match local {
                    "link" if !self.in_source => {
                        let link = atom_link_from_attrs(&e);
                        if self.in_entry {
                            self.current_entry.links.push(link);
                        } else {
                            self.header.links.push(link);
                        }
                    }
                    "category" if !self.in_source => {
                        let cat = atom_category_from_attrs(&e);
                        if self.in_entry {
                            self.current_entry.categories.push(cat);
                        } else {
                            self.header.categories.push(cat);
                        }
                    }
                    "content" if self.in_entry && !self.in_source => {
                        // Out-of-line <content src=".." type=".."/>
                        if let Some(src) = attr_value(&e, attr::SRC) {
                            let type_ = attr_value(&e, attr::TYPE).unwrap_or_else(|| "text".into());
                            self.current_entry.content = Some(AtomContent {
                                value: AtomText::text(type_),
                                src: Some(src),
                            });
                        }
                    }
                    _ => {}
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
                        tracing::debug!("atom stream unescape error (lenient): {err}");
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
                        tracing::debug!("atom stream CDATA utf8 error (lenient): {err}");
                        self.text_buf.push_str(&String::from_utf8_lossy(e.as_ref()));
                    }
                }
                Ok(Action::Continue)
            }
            Event::End(e) => {
                self.depth -= 1;
                let local = std::str::from_utf8(e.local_name().as_ref())
                    .map(str::to_owned)
                    .unwrap_or_default();
                let ns = classify_ns(&rr);
                let text = std::mem::take(&mut self.text_buf);
                drop(e);
                self.handle_end(ns, &local, text)
            }
            Event::Eof => {
                if self.strict && self.depth > 0 {
                    return Err(FeedParseError::new(format!(
                        "truncated Atom document ({} unclosed elements at EOF)",
                        self.depth
                    )));
                }
                Ok(Action::Eof)
            }
            _ => Ok(Action::Continue),
        }
    }

    /// Common entry point for the typed text constructs (title/summary/
    /// content/rights/subtitle). If type is `xhtml`, captures the inner
    /// subtree directly; otherwise records the type and lets the End handler
    /// finalise it from `text_buf`.
    async fn start_typed_text(
        &mut self,
        which: &'static str,
        t: String,
    ) -> Result<Action, FeedParseError> {
        if t == "xhtml" {
            let xml = capture_xhtml_subtree_async(&mut self.nsr, &mut self.buf).await?;
            self.depth -= 1;
            match which {
                "title" => {
                    if self.in_entry {
                        self.current_entry.title = AtomText::xhtml(xml);
                        self.current_entry_title_set = true;
                    } else {
                        self.header.title = AtomText::xhtml(xml);
                    }
                }
                "summary" => {
                    self.current_entry.summary = Some(AtomText::xhtml(xml));
                }
                "content" => {
                    self.current_entry.content = Some(AtomContent {
                        value: AtomText::xhtml(xml),
                        src: None,
                    });
                }
                "rights" => {
                    if self.in_entry {
                        self.current_entry.rights = Some(AtomText::xhtml(xml));
                    } else {
                        self.header.rights = Some(AtomText::xhtml(xml));
                    }
                }
                "subtitle" => {
                    self.header.subtitle = Some(AtomText::xhtml(xml));
                }
                _ => {}
            }
            return Ok(Action::Continue);
        }
        match which {
            "title" => self.current_title_type = t,
            "summary" => self.current_summary_type = t,
            "content" => self.current_content_type = t,
            "rights" => self.current_rights_type = t,
            "subtitle" => self.current_subtitle_type = t,
            _ => {}
        }
        Ok(Action::Continue)
    }

    fn handle_end(&mut self, ns: Ns, local: &str, text: String) -> Result<Action, FeedParseError> {
        // Author / contributor sub-elements: shallow finalisation.
        if self.in_author && ns == Ns::Atom {
            return Ok(self.handle_person_end(local, text, &PersonKind::EntryAuthor));
        }
        if self.in_feed_author && ns == Ns::Atom {
            return Ok(self.handle_person_end(local, text, &PersonKind::FeedAuthor));
        }
        if self.in_contributor && ns == Ns::Atom {
            return Ok(self.handle_person_end(local, text, &PersonKind::EntryContributor));
        }
        if self.in_feed_contributor && ns == Ns::Atom {
            return Ok(self.handle_person_end(local, text, &PersonKind::FeedContributor));
        }
        // Source sub-elements: route into current_source, then close on </source>.
        if self.in_source && ns == Ns::Atom {
            match local {
                "id" => self.current_source.id = Some(text),
                "title" => {
                    self.current_source.title =
                        Some(make_atom_text(&self.current_title_type, text));
                }
                "updated" => self.current_source.updated = parse_rfc3339_lax(&text),
                "source" => {
                    self.in_source = false;
                    let source = std::mem::replace(
                        &mut self.current_source,
                        AtomSource {
                            id: None,
                            title: None,
                            updated: None,
                        },
                    );
                    self.current_entry.source = Some(source);
                }
                _ => {}
            }
            return Ok(Action::Continue);
        }
        // Entry-level core elements.
        if self.in_entry {
            let Some(text) = self.entry_acc.on_end(ns, local, text) else {
                return Ok(Action::Continue);
            };
            if ns != Ns::Atom {
                return Ok(Action::Continue);
            }
            match local {
                "id" => {
                    self.current_entry.id = text;
                    self.current_entry_id_set = true;
                }
                "title" => {
                    self.current_entry.title = make_atom_text(&self.current_title_type, text);
                    self.current_entry_title_set = true;
                }
                "updated" => {
                    if let Some(ts) = parse_rfc3339_lax(&text) {
                        self.current_entry.updated = ts;
                        self.current_entry_updated_parsed = true;
                    }
                }
                "published" => self.current_entry.published = parse_rfc3339_lax(&text),
                "summary" => {
                    self.current_entry.summary =
                        Some(make_atom_text(&self.current_summary_type, text));
                }
                "content" => {
                    self.current_entry.content = Some(AtomContent {
                        value: make_atom_text(&self.current_content_type, text),
                        src: None,
                    });
                }
                "rights" => {
                    self.current_entry.rights =
                        Some(make_atom_text(&self.current_rights_type, text));
                }
                "entry" => {
                    if self.strict {
                        if !self.current_entry_id_set {
                            return Err(FeedParseError::new("Atom entry missing required <id>"));
                        }
                        if !self.current_entry_title_set {
                            return Err(FeedParseError::new("Atom entry missing required <title>"));
                        }
                        if !self.current_entry_updated_parsed {
                            return Err(FeedParseError::new(
                                "Atom entry missing required <updated>",
                            ));
                        }
                    }
                    self.current_entry.extensions = std::mem::take(&mut self.entry_acc).finish();
                    let entry = std::mem::replace(
                        &mut self.current_entry,
                        AtomEntry::new("", AtomText::text(""), Timestamp::UNIX_EPOCH),
                    );
                    self.in_entry = false;
                    return Ok(Action::EntryFinished(Box::new(entry)));
                }
                _ => {}
            }
            return Ok(Action::Continue);
        }
        // Feed-level core elements.
        let Some(text) = self.feed_acc.on_end(ns, local, text) else {
            return Ok(Action::Continue);
        };
        if ns != Ns::Atom {
            return Ok(Action::Continue);
        }
        match local {
            "id" => self.header.id = text,
            "title" => self.header.title = make_atom_text(&self.current_title_type, text),
            "updated" => {
                if let Some(ts) = parse_rfc3339_lax(&text) {
                    self.header.updated = ts;
                    self.feed_updated_parsed = true;
                }
            }
            "subtitle" => {
                self.header.subtitle = Some(make_atom_text(&self.current_subtitle_type, text));
            }
            "rights" => {
                self.header.rights = Some(make_atom_text(&self.current_rights_type, text));
            }
            "logo" => self.header.logo = Some(text),
            "icon" => self.header.icon = Some(text),
            "generator" => {
                if let Some(mut g) = self.pending_generator.take() {
                    g.value = text;
                    self.header.generator = Some(g);
                }
            }
            _ => {}
        }
        Ok(Action::Continue)
    }

    fn handle_person_end(&mut self, local: &str, text: String, kind: &PersonKind) -> Action {
        let person = match kind {
            PersonKind::EntryAuthor | PersonKind::FeedAuthor => &mut self.current_author,
            PersonKind::EntryContributor | PersonKind::FeedContributor => {
                &mut self.current_contributor
            }
        };
        match local {
            "name" => person.name = text,
            "email" => person.email = Some(text),
            "uri" => person.uri = Some(text),
            "author" | "contributor" => {
                let finalised = std::mem::replace(person, AtomPerson::new(""));
                match kind {
                    PersonKind::EntryAuthor => {
                        self.current_entry.authors.push(finalised);
                        self.in_author = false;
                    }
                    PersonKind::FeedAuthor => {
                        self.header.authors.push(finalised);
                        self.in_feed_author = false;
                    }
                    PersonKind::EntryContributor => {
                        self.current_entry.contributors.push(finalised);
                        self.in_contributor = false;
                    }
                    PersonKind::FeedContributor => {
                        self.header.contributors.push(finalised);
                        self.in_feed_contributor = false;
                    }
                }
            }
            _ => {}
        }
        Action::Continue
    }
}

enum PersonKind {
    EntryAuthor,
    FeedAuthor,
    EntryContributor,
    FeedContributor,
}

// ---------------------------------------------------------------------------
// XHTML subtree capture (preserved from the previous implementation).
// ---------------------------------------------------------------------------

/// Consume events from `nsr` until the matching End closes the enclosing
/// `type="xhtml"` element, re-emitting child events into a string buffer.
/// The single wrapping `<div xmlns="...xhtml">` and its closing End are
/// stripped so the captured string is the raw inner markup the writer expects.
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
        let (_, ev) = nsr
            .read_resolved_event_into_async(buf)
            .await
            .map_err(|e| FeedParseError::new(format!("xhtml capture: {e}")))?;
        match ev {
            Event::Start(e) => {
                if depth == 0 && !saw_wrapper && e.local_name().as_ref() == b"div" {
                    saw_wrapper = true;
                    depth += 1;
                } else {
                    depth += 1;
                    writer
                        .write_event(Event::Start(e))
                        .map_err(|err| FeedParseError::new(format!("xhtml write: {err}")))?;
                }
            }
            Event::End(e) => {
                if depth == 0 {
                    drop(writer);
                    return String::from_utf8(captured).map_err(|err| {
                        FeedParseError::new(format!("xhtml inner is not utf-8: {err}"))
                    });
                }
                depth -= 1;
                if depth == 0 && saw_wrapper {
                    // closing the wrapper <div> — drop it
                } else {
                    writer
                        .write_event(Event::End(e))
                        .map_err(|err| FeedParseError::new(format!("xhtml write: {err}")))?;
                }
            }
            Event::Empty(e) => writer
                .write_event(Event::Empty(e))
                .map_err(|err| FeedParseError::new(format!("xhtml write: {err}")))?,
            Event::Text(e) => writer
                .write_event(Event::Text(e))
                .map_err(|err| FeedParseError::new(format!("xhtml write: {err}")))?,
            Event::CData(e) => writer
                .write_event(Event::CData(e))
                .map_err(|err| FeedParseError::new(format!("xhtml write: {err}")))?,
            Event::Comment(e) => writer
                .write_event(Event::Comment(e))
                .map_err(|err| FeedParseError::new(format!("xhtml write: {err}")))?,
            Event::Eof => {
                return Err(FeedParseError::new("unexpected EOF in xhtml content"));
            }
            // DocType / PI / Decl are not legal inside Atom xhtml content; drop.
            _ => {}
        }
    }
}
