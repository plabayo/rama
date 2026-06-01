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

use super::names::elem;
use crate::protocols::rss::atom::{
    AtomCategory, AtomContent, AtomEntry, AtomFeed, AtomGenerator, AtomLink, AtomPerson,
    AtomSource, AtomText,
};
use crate::protocols::rss::error::{AtomCollectError, CollectError, FeedParseError};
use crate::protocols::rss::feed_ext::FeedExtensions;
use crate::protocols::rss::feed_ext::names::attr;
use crate::protocols::rss::feed_ext::parse::{FeedExtAcc, ItemExtAcc, Ns, classify_ns};
use crate::protocols::rss::parse_util::{
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

    pub(in crate::protocols::rss) async fn new_with_mode<R>(
        reader: R,
        strict: bool,
    ) -> Result<Self, FeedParseError>
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
    /// Nesting depth of open `<atom:source>` elements. Zero means we are
    /// not currently inside a source. The outermost source is depth 1; a
    /// (malformed) nested `<source>` inside another bumps to 2, 3, … so the
    /// inner `</source>` does not prematurely finalise the outer one.
    /// Only depth-1 children mutate [`Self::current_source`]; deeper ones
    /// are silently dropped (or in strict mode rejected at the Start).
    source_depth: u32,
    current_source: AtomSource,
    /// Type attribute of the source's `<title>` — kept separate from the
    /// outer entry's `current_title_type` so a `<source><title type="html">`
    /// can't leak its type back to a still-open outer `<title>`.
    current_source_title_type: String,

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
            source_depth: 0,
            current_source: AtomSource {
                id: None,
                title: None,
                updated: None,
            },
            current_source_title_type: String::from("text"),
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

    /// RFC 4287 §3.2: an Atom Person construct contains exactly `<name>`,
    /// optionally `<uri>` and `<email>`. Anything else is malformed and must
    /// NOT leak side effects into the enclosing entry/feed. Used by both the
    /// Start and Empty arms of [`Self::step`]; the `in_person` boolean is
    /// inlined at the call sites (a method call would borrow `self` as a
    /// unit and clash with the `self.buf` borrow held by the current event).
    fn person_child_is_valid(local: &str) -> bool {
        matches!(local, elem::NAME | elem::URI | elem::EMAIL)
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

                // Person-construct containment: any non-{name,uri,email}
                // child of an <author>/<contributor> must not mutate the
                // enclosing entry/feed state (link/category/content/typed
                // text/etc.) Strict mode rejects; lenient mode swallows.
                // For type="xhtml" typed-text we still consume the inner
                // subtree so the parser depth stays in sync.
                // (Inline the four-bool check rather than calling
                // `self.in_person()` — the latter would borrow `self` as
                // a unit and clash with the `self.buf` borrow held by `ev`.
                // Reading individual bool fields is a split borrow.)
                let in_person = self.in_author
                    || self.in_feed_author
                    || self.in_contributor
                    || self.in_feed_contributor;
                if in_person && !Self::person_child_is_valid(local) {
                    if self.strict {
                        return Err(FeedParseError::new(format!(
                            "Atom person element may only contain <name>/<uri>/<email>, \
                             found <{local}>"
                        )));
                    }
                    if matches!(
                        local,
                        elem::TITLE | elem::SUMMARY | elem::CONTENT | elem::RIGHTS | elem::SUBTITLE
                    ) && attr_value(&e, attr::TYPE).as_deref() == Some("xhtml")
                    {
                        drop(e);
                        let _ =
                            capture_xhtml_subtree_async(&mut self.nsr, &mut self.buf, self.strict)
                                .await?;
                        self.depth -= 1;
                    }
                    return Ok(Action::Continue);
                }

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
                    elem::FEED => {
                        self.saw_root = true;
                        Ok(Action::Continue)
                    }
                    elem::ENTRY => {
                        let first_entry = !self.in_entry;
                        if !first_entry {
                            // Nested / re-opened <entry> in malformed input.
                            // Strict rejects (matches RSS behaviour). Lenient
                            // resets and keeps going; the outer partial entry
                            // is discarded — trace so operators can spot it.
                            if self.strict {
                                return Err(FeedParseError::new(format!(
                                    "Atom: nested or re-opened <entry> at depth {}",
                                    self.depth,
                                )));
                            }
                            tracing::debug!(
                                "atom: nested or re-opened <entry> at depth {} — \
                                 partial outer entry discarded",
                                self.depth,
                            );
                        }
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
                    elem::AUTHOR if self.source_depth == 0 => {
                        self.current_author = AtomPerson::new("");
                        if self.in_entry {
                            self.in_author = true;
                        } else {
                            self.in_feed_author = true;
                        }
                        Ok(Action::Continue)
                    }
                    elem::CONTRIBUTOR if self.source_depth == 0 => {
                        self.current_contributor = AtomPerson::new("");
                        if self.in_entry {
                            self.in_contributor = true;
                        } else {
                            self.in_feed_contributor = true;
                        }
                        Ok(Action::Continue)
                    }
                    elem::SOURCE if self.in_entry => {
                        self.source_depth += 1;
                        if self.source_depth == 1 {
                            self.current_source = AtomSource {
                                id: None,
                                title: None,
                                updated: None,
                            };
                            self.current_source_title_type = String::from("text");
                        } else if self.strict {
                            return Err(FeedParseError::new(
                                "Atom <source> may not be nested inside another <source>",
                            ));
                        }
                        Ok(Action::Continue)
                    }
                    elem::LINK if self.source_depth == 0 => {
                        let link = atom_link_from_attrs(&e);
                        if self.in_entry {
                            self.current_entry.links.push(link);
                        } else {
                            self.header.links.push(link);
                        }
                        Ok(Action::Continue)
                    }
                    elem::CATEGORY if self.source_depth == 0 => {
                        let cat = atom_category_from_attrs(&e);
                        if self.in_entry {
                            self.current_entry.categories.push(cat);
                        } else {
                            self.header.categories.push(cat);
                        }
                        Ok(Action::Continue)
                    }
                    elem::TITLE => {
                        let t = attr_value(&e, attr::TYPE).unwrap_or_else(|| "text".into());
                        drop(e);
                        self.start_typed_text(elem::TITLE, t).await
                    }
                    elem::SUMMARY if self.in_entry => {
                        let t = attr_value(&e, attr::TYPE).unwrap_or_else(|| "text".into());
                        drop(e);
                        self.start_typed_text(elem::SUMMARY, t).await
                    }
                    elem::CONTENT if self.in_entry && self.source_depth == 0 => {
                        let t = attr_value(&e, attr::TYPE).unwrap_or_else(|| "text".into());
                        drop(e);
                        self.start_typed_text(elem::CONTENT, t).await
                    }
                    elem::RIGHTS => {
                        let t = attr_value(&e, attr::TYPE).unwrap_or_else(|| "text".into());
                        drop(e);
                        self.start_typed_text(elem::RIGHTS, t).await
                    }
                    elem::SUBTITLE if !self.in_entry => {
                        let t = attr_value(&e, attr::TYPE).unwrap_or_else(|| "text".into());
                        drop(e);
                        self.start_typed_text(elem::SUBTITLE, t).await
                    }
                    elem::GENERATOR if self.source_depth == 0 => {
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

                // Same person-construct containment as for Start events.
                let in_person = self.in_author
                    || self.in_feed_author
                    || self.in_contributor
                    || self.in_feed_contributor;
                if in_person && !Self::person_child_is_valid(local) {
                    if self.strict {
                        return Err(FeedParseError::new(format!(
                            "Atom person element may only contain <name>/<uri>/<email>, \
                             found <{local}/>"
                        )));
                    }
                    return Ok(Action::Continue);
                }

                let consumed = if self.in_entry {
                    self.entry_acc.on_empty(ns, local, &e)
                } else {
                    self.feed_acc.on_empty(ns, local, &e)
                };
                if consumed || ns != Ns::Atom {
                    return Ok(Action::Continue);
                }
                match local {
                    elem::LINK if self.source_depth == 0 => {
                        let link = atom_link_from_attrs(&e);
                        if self.in_entry {
                            self.current_entry.links.push(link);
                        } else {
                            self.header.links.push(link);
                        }
                    }
                    elem::CATEGORY if self.source_depth == 0 => {
                        let cat = atom_category_from_attrs(&e);
                        if self.in_entry {
                            self.current_entry.categories.push(cat);
                        } else {
                            self.header.categories.push(cat);
                        }
                    }
                    elem::CONTENT if self.in_entry && self.source_depth == 0 => {
                        // Out-of-line <content src=".." type=".."/>
                        if let Some(src) = attr_value(&e, attr::SRC) {
                            let type_ = attr_value(&e, attr::TYPE).unwrap_or_else(|| "text".into());
                            self.current_entry.content = Some(AtomContent::out_of_line(src, type_));
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
                let ns = classify_ns(&rr);
                // Copy the local name into a stack buffer so we can release
                // the borrow on `self.buf` (held by `e`) before calling
                // `handle_end`, which mutably borrows `&mut self`. Avoids
                // the per-event String allocation that the borrow-checker
                // would otherwise force on this hot path.
                //
                // 64 bytes covers every Atom/RSS/extension element name in
                // our vocabulary; longer or non-UTF-8 names fall through
                // to "" (which matches nothing) — same outcome as before.
                let mut stack = [0u8; 64];
                let local_bytes = e.local_name();
                let n = local_bytes.as_ref().len().min(stack.len());
                stack[..n].copy_from_slice(&local_bytes.as_ref()[..n]);
                drop(e);
                let local = std::str::from_utf8(&stack[..n]).unwrap_or("");
                let text = std::mem::take(&mut self.text_buf);
                self.handle_end(ns, local, text)
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
            let xml =
                capture_xhtml_subtree_async(&mut self.nsr, &mut self.buf, self.strict).await?;
            self.depth -= 1;
            // Children of `<atom:source>` belong to the source, not the
            // enclosing entry. The text/html path is intercepted by the
            // source branch in `handle_end`, but the xhtml path bypasses
            // that (it consumes events inline and never returns an
            // `Event::End` to `handle_end`) so we route here explicitly.
            // AtomSource only carries id/title/updated, so any xhtml-typed
            // source child other than `<title>` has nowhere to land and
            // is intentionally dropped. Only the OUTERMOST source's title
            // is captured — inner (malformed nested) sources' xhtml is
            // discarded entirely.
            if self.source_depth > 0 {
                if self.source_depth == 1 && which == elem::TITLE {
                    self.current_source.title = Some(AtomText::xhtml(xml));
                }
                return Ok(Action::Continue);
            }
            match which {
                elem::TITLE => {
                    if self.in_entry {
                        self.current_entry.title = AtomText::xhtml(xml);
                        self.current_entry_title_set = true;
                    } else {
                        self.header.title = AtomText::xhtml(xml);
                    }
                }
                elem::SUMMARY => {
                    self.current_entry.summary = Some(AtomText::xhtml(xml));
                }
                elem::CONTENT => {
                    self.current_entry.content = Some(AtomContent {
                        value: AtomText::xhtml(xml),
                        src: None,
                        out_of_line_type: None,
                    });
                }
                elem::RIGHTS => {
                    if self.in_entry {
                        self.current_entry.rights = Some(AtomText::xhtml(xml));
                    } else {
                        self.header.rights = Some(AtomText::xhtml(xml));
                    }
                }
                elem::SUBTITLE => {
                    self.header.subtitle = Some(AtomText::xhtml(xml));
                }
                _ => {}
            }
            return Ok(Action::Continue);
        }
        // Inside a `<source>` only `<title>` is meaningful (id and updated
        // carry no type); writing into the outer entry's `current_*_type`
        // would leak the source's typing back to the entry. Keep the
        // source's title type isolated and ignore the rest. Inside a
        // nested (malformed) source the typing is discarded entirely.
        if self.source_depth > 0 {
            if self.source_depth == 1 && which == elem::TITLE {
                self.current_source_title_type = t;
            }
            return Ok(Action::Continue);
        }
        match which {
            elem::TITLE => self.current_title_type = t,
            elem::SUMMARY => self.current_summary_type = t,
            elem::CONTENT => self.current_content_type = t,
            elem::RIGHTS => self.current_rights_type = t,
            elem::SUBTITLE => self.current_subtitle_type = t,
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
        // Source sub-elements: route into current_source, then close on the
        // outermost </source>. Inner sources (malformed nesting) just
        // decrement the depth — neither their children nor their close
        // touch the outer source's accumulated state.
        if self.source_depth > 0 && ns == Ns::Atom {
            if local == elem::SOURCE {
                self.source_depth -= 1;
                if self.source_depth == 0 {
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
                return Ok(Action::Continue);
            }
            // Only the outermost source's children mutate current_source.
            if self.source_depth == 1 {
                match local {
                    elem::ID => self.current_source.id = Some(text),
                    elem::TITLE => {
                        self.current_source.title =
                            Some(make_atom_text(&self.current_source_title_type, text));
                    }
                    elem::UPDATED => self.current_source.updated = parse_rfc3339_lax(&text),
                    _ => {}
                }
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
                elem::ID => {
                    self.current_entry.id = text;
                    self.current_entry_id_set = true;
                }
                elem::TITLE => {
                    self.current_entry.title = make_atom_text(&self.current_title_type, text);
                    self.current_entry_title_set = true;
                }
                elem::UPDATED => {
                    if let Some(ts) = parse_rfc3339_lax(&text) {
                        self.current_entry.updated = ts;
                        self.current_entry_updated_parsed = true;
                    } else if self.strict {
                        return Err(FeedParseError::new(format!(
                            "Atom entry <updated> could not be parsed as RFC 3339: {text:?}"
                        )));
                    }
                }
                elem::PUBLISHED => self.current_entry.published = parse_rfc3339_lax(&text),
                elem::SUMMARY => {
                    self.current_entry.summary =
                        Some(make_atom_text(&self.current_summary_type, text));
                }
                elem::CONTENT => {
                    self.current_entry.content = Some(AtomContent {
                        value: make_atom_text(&self.current_content_type, text),
                        src: None,
                        out_of_line_type: None,
                    });
                }
                elem::RIGHTS => {
                    self.current_entry.rights =
                        Some(make_atom_text(&self.current_rights_type, text));
                }
                elem::ENTRY => {
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
            elem::ID => self.header.id = text,
            elem::TITLE => self.header.title = make_atom_text(&self.current_title_type, text),
            elem::UPDATED => {
                if let Some(ts) = parse_rfc3339_lax(&text) {
                    self.header.updated = ts;
                    self.feed_updated_parsed = true;
                } else if self.strict {
                    return Err(FeedParseError::new(format!(
                        "Atom feed <updated> could not be parsed as RFC 3339: {text:?}"
                    )));
                }
            }
            elem::SUBTITLE => {
                self.header.subtitle = Some(make_atom_text(&self.current_subtitle_type, text));
            }
            elem::RIGHTS => {
                self.header.rights = Some(make_atom_text(&self.current_rights_type, text));
            }
            elem::LOGO => self.header.logo = Some(text),
            elem::ICON => self.header.icon = Some(text),
            elem::GENERATOR => {
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
            elem::NAME => person.name = text,
            elem::EMAIL => person.email = Some(text),
            elem::URI => person.uri = Some(text),
            elem::AUTHOR | elem::CONTRIBUTOR => {
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
///
/// RFC 4287 §3.1.1.3 requires the content of an xhtml text construct to be
/// **exactly one** XHTML-namespaced `<div>` element wrapping the real
/// markup. In `strict` mode this is enforced (missing wrapper, wrong
/// namespace, or non-`<div>` first element all fail). In lenient mode we
/// keep absorbing whatever the publisher emitted: a first `<div>` (any
/// namespace, or none) is treated as the wrapper; otherwise the inner
/// content is captured verbatim.
///
/// On the wire the writer always emits a correctly-namespaced wrapper, so
/// a round-tripped feed is always strict-clean.
async fn capture_xhtml_subtree_async<R>(
    nsr: &mut NsReader<R>,
    buf: &mut Vec<u8>,
    strict: bool,
) -> Result<String, FeedParseError>
where
    R: AsyncBufRead + Unpin,
{
    const XHTML_NS_BYTES: &[u8] = crate::protocols::rss::ns::XHTML_NS.as_bytes();

    // The outer reader runs with `trim_text(true)` so core-Atom text fields
    // come back without surrounding whitespace. Inside an xhtml subtree
    // every space matters — `<p>foo</p> <p>bar</p>` and
    // `<p>Hello <em>world</em> there</p>` both lose meaning if the inter-
    // element whitespace is trimmed. Disable trimming for the capture and
    // restore it before returning (errors included).
    nsr.config_mut().trim_text(false);
    let result = capture_xhtml_subtree_inner(nsr, buf, strict, XHTML_NS_BYTES).await;
    nsr.config_mut().trim_text(true);
    result
}

async fn capture_xhtml_subtree_inner<R>(
    nsr: &mut NsReader<R>,
    buf: &mut Vec<u8>,
    strict: bool,
    xhtml_ns_bytes: &[u8],
) -> Result<String, FeedParseError>
where
    R: AsyncBufRead + Unpin,
{
    use quick_xml::Writer;
    use quick_xml::name::ResolveResult;

    let mut captured = Vec::<u8>::new();
    let mut depth: i32 = 0;
    let mut saw_wrapper = false;
    let mut writer = Writer::new(&mut captured);
    loop {
        buf.clear();
        let (rr, ev) = nsr
            .read_resolved_event_into_async(buf)
            .await
            .map_err(|e| FeedParseError::new(format!("xhtml capture: {e}")))?;
        match ev {
            Event::Start(e) => {
                if depth == 0 && !saw_wrapper {
                    let is_div = e.local_name().as_ref() == elem::DIV.as_bytes();
                    let in_xhtml_ns =
                        matches!(rr, ResolveResult::Bound(n) if n.0 == xhtml_ns_bytes);
                    if strict && !(is_div && in_xhtml_ns) {
                        return Err(FeedParseError::new(
                            "Atom xhtml content must be wrapped in a single \
                             XHTML-namespaced <div> (RFC 4287 §3.1.1.3)",
                        ));
                    }
                    if is_div {
                        saw_wrapper = true;
                        depth += 1;
                        continue;
                    }
                }
                depth += 1;
                writer
                    .write_event(Event::Start(e))
                    .map_err(|err| FeedParseError::new(format!("xhtml write: {err}")))?;
            }
            Event::End(e) => {
                if depth == 0 {
                    if strict && !saw_wrapper {
                        return Err(FeedParseError::new(
                            "Atom xhtml content must be wrapped in a single \
                             XHTML-namespaced <div> (RFC 4287 §3.1.1.3)",
                        ));
                    }
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
            Event::Empty(e) => {
                if depth == 0 && !saw_wrapper && strict {
                    return Err(FeedParseError::new(
                        "Atom xhtml content must be wrapped in a single \
                         XHTML-namespaced <div> (RFC 4287 §3.1.1.3)",
                    ));
                }
                writer
                    .write_event(Event::Empty(e))
                    .map_err(|err| FeedParseError::new(format!("xhtml write: {err}")))?;
            }
            Event::Text(e) => {
                // Non-whitespace text outside the wrapper violates the spec.
                if depth == 0 && !saw_wrapper && strict {
                    let s = e.unescape().map(|c| c.into_owned()).unwrap_or_default();
                    if !s.trim().is_empty() {
                        return Err(FeedParseError::new(
                            "Atom xhtml content must be wrapped in a single \
                             XHTML-namespaced <div> (RFC 4287 §3.1.1.3)",
                        ));
                    }
                }
                writer
                    .write_event(Event::Text(e))
                    .map_err(|err| FeedParseError::new(format!("xhtml write: {err}")))?;
            }
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
