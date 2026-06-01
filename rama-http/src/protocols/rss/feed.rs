//! [`Feed`] / [`FeedItem`] umbrella types, [`IntoResponse`] impls, the
//! `from_body` convenience that drains [`FeedStream`] into an in-memory feed,
//! and the format-agnostic aggregator-style accessors on the two enums.
//!
//! There is **no synchronous high-level parser** — everything goes through
//! the async streaming reader. Callers who need item-by-item processing use
//! [`super::FeedStream`] directly; callers who just want the whole document
//! call [`Feed::from_body`] (which is the "collect" adapter on top).
//!
//! The cross-format accessors on `Feed` / `FeedItem` (and the parallel ones
//! on [`super::FeedStream`]) are for callers who don't know the upstream
//! format ahead of time and just want title / link / author / etc. The
//! per-format types ([`Rss2Feed`], [`AtomFeed`], …) keep their public fields
//! and aren't decorated with these — direct field access is the obvious move
//! when you already know the format.

use jiff::Timestamp;

use crate::headers::ContentType;
use crate::service::web::response::{Headers, IntoResponse};
use crate::{Body, Response};

use super::atom::{AtomEntry, AtomFeed, AtomLink};
use super::error::FeedParseError;
use super::rss2::{Rss2Enclosure, Rss2Feed, Rss2Item};
use super::stream::FeedStream;

/// A feed in either RSS 2.0 or Atom 1.0 format.
#[derive(Debug, Clone, PartialEq)]
pub enum Feed {
    Rss2(Rss2Feed),
    Atom(AtomFeed),
}

/// One item or entry, regardless of the originating feed format. Yielded by
/// [`FeedStream`] when iterated as a [`Stream`]; convert into a strongly-typed
/// `Rss2Item` / `AtomEntry` with the obvious `match`, or use the
/// cross-format accessors directly on this enum.
///
/// [`Stream`]: rama_core::futures::Stream
#[derive(Debug, Clone, PartialEq)]
pub enum FeedItem {
    Rss2(Rss2Item),
    Atom(AtomEntry),
}

impl From<Rss2Item> for FeedItem {
    fn from(i: Rss2Item) -> Self {
        Self::Rss2(i)
    }
}

impl From<AtomEntry> for FeedItem {
    fn from(e: AtomEntry) -> Self {
        Self::Atom(e)
    }
}

impl FeedItem {
    /// Atom requires a title; RSS makes it optional. Caller should be ready
    /// for `None` on an RSS item that only carries `<description>`.
    #[must_use]
    pub fn title(&self) -> Option<&str> {
        match self {
            Self::Rss2(i) => i.title.as_deref(),
            Self::Atom(e) => Some(e.title.value.as_str()),
        }
    }

    /// RSS `<guid>` (optional) | Atom `<id>` (required).
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        match self {
            Self::Rss2(i) => i.guid.as_ref().map(|g| g.value.as_str()),
            Self::Atom(e) => Some(&e.id),
        }
    }

    /// RSS `<link>` | Atom `<link rel="alternate">` (or first link without
    /// `rel`, since Atom defaults `rel` to `"alternate"`).
    #[must_use]
    pub fn link(&self) -> Option<&str> {
        match self {
            Self::Rss2(i) => i.link.as_deref(),
            Self::Atom(e) => pick_alternate(&e.links).map(|l| l.href.as_str()),
        }
    }

    /// Short excerpt. RSS `<description>` | Atom `<summary>`.
    #[must_use]
    pub fn summary(&self) -> Option<&str> {
        match self {
            Self::Rss2(i) => i.description.as_deref(),
            Self::Atom(e) => e.summary.as_ref().map(|t| t.value.as_str()),
        }
    }

    /// Long-form body. Atom `<content>` (any of text/html/xhtml). For RSS,
    /// returns `<content:encoded>` if present, otherwise falls back to
    /// `<description>` — many publishers put the full body there. The fallback
    /// means `summary()` and `content()` may return the same string on RSS
    /// items without `content:encoded`.
    ///
    /// For Atom out-of-line content (`<content src="..." type="..."/>`)
    /// returns `None`: the body lives at the remote URL, not in the feed.
    /// Use the per-format types directly if you need the `src` / `type`
    /// pair.
    #[must_use]
    pub fn content(&self) -> Option<&str> {
        match self {
            Self::Rss2(i) => i
                .extensions
                .content
                .as_ref()
                .and_then(|c| c.encoded.as_deref())
                .or(i.description.as_deref()),
            Self::Atom(e) => e
                .content
                .as_ref()
                .filter(|c| c.src.is_none())
                .map(|c| c.value.value.as_str()),
        }
    }

    /// Item-level authors. RSS yields `<author>` (if any) plus the
    /// `dc:creator` extension (if set); Atom yields the `<author>` Person
    /// names. Duplicates and empty strings are dropped.
    #[must_use]
    pub fn authors(&self) -> Vec<&str> {
        match self {
            Self::Rss2(i) => {
                let primary = i.author.as_deref();
                let dc_creator = i
                    .extensions
                    .dublin_core
                    .as_ref()
                    .and_then(|d| d.creator.as_deref());
                let mut out = Vec::with_capacity(2);
                for s in [primary, dc_creator].into_iter().flatten() {
                    if !s.is_empty() && !out.contains(&s) {
                        out.push(s);
                    }
                }
                out
            }
            Self::Atom(e) => e.authors.iter().map(|p| p.name.as_str()).collect(),
        }
    }

    /// RSS `<pubDate>` | Atom `<published>`.
    #[must_use]
    pub fn published(&self) -> Option<Timestamp> {
        match self {
            Self::Rss2(i) => i.pub_date,
            Self::Atom(e) => e.published,
        }
    }

    /// Atom `<updated>` (required) | RSS has no per-item updated — `None`.
    #[must_use]
    pub fn updated(&self) -> Option<Timestamp> {
        match self {
            Self::Rss2(_) => None,
            Self::Atom(e) => Some(e.updated),
        }
    }

    /// Item-level category names / terms.
    #[must_use]
    pub fn categories(&self) -> Vec<&str> {
        match self {
            Self::Rss2(i) => i.categories.iter().map(|c| c.name.as_str()).collect(),
            Self::Atom(e) => e.categories.iter().map(|c| c.term.as_str()).collect(),
        }
    }

    /// Attached binaries (podcast audio etc.). RSS `<enclosure>` | Atom
    /// `<link rel="enclosure">`. The two encodings normalise to the same
    /// `(url, length, mime)` triple via [`EnclosureView`].
    #[must_use]
    pub fn enclosures(&self) -> Vec<EnclosureView<'_>> {
        match self {
            Self::Rss2(i) => i.enclosures.iter().map(EnclosureView::from).collect(),
            Self::Atom(e) => e
                .links
                .iter()
                .filter(|l| l.rel.as_deref() == Some("enclosure"))
                .map(EnclosureView::from)
                .collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// EnclosureView
// ---------------------------------------------------------------------------

/// Normalised view over an enclosure: RSS `<enclosure>` and Atom
/// `<link rel="enclosure">` collapse to the same `(url, length, mime)` shape.
/// `length` and `mime` are required by RSS but optional in Atom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnclosureView<'a> {
    pub url: &'a str,
    pub length: Option<u64>,
    pub mime: Option<&'a str>,
}

impl<'a> From<&'a Rss2Enclosure> for EnclosureView<'a> {
    fn from(e: &'a Rss2Enclosure) -> Self {
        Self {
            url: &e.url,
            length: Some(e.length),
            mime: Some(&e.type_),
        }
    }
}

impl<'a> From<&'a AtomLink> for EnclosureView<'a> {
    fn from(l: &'a AtomLink) -> Self {
        Self {
            url: &l.href,
            length: l.length,
            mime: l.type_.as_deref(),
        }
    }
}

// ---------------------------------------------------------------------------
// Small helpers used by both Feed and FeedItem accessors.
// ---------------------------------------------------------------------------

/// Pick the `alternate` link from a slice of Atom-style links, falling back
/// to a link with no `rel` (Atom defaults `rel` to `"alternate"`). Shared
/// with [`super::FeedStream`].
pub(super) fn pick_alternate(links: &[AtomLink]) -> Option<&AtomLink> {
    links
        .iter()
        .find(|l| l.rel.as_deref() == Some("alternate"))
        .or_else(|| links.iter().find(|l| l.rel.is_none()))
}

pub(super) fn pick_rel<'a>(links: &'a [AtomLink], rel: &str) -> Option<&'a AtomLink> {
    links.iter().find(|l| l.rel.as_deref() == Some(rel))
}

impl Feed {
    /// Parse a feed from a [`Body`] by draining a [`FeedStream`]. This is the
    /// convenience "collect" adapter — fine for the typical "give me the
    /// whole document" client / proxy case, but it does buffer every item /
    /// entry into memory.
    ///
    /// Use [`FeedStream::from_body`] directly if you want to process items
    /// incrementally (e.g. filter podcast episodes as they stream in, or stop
    /// after the first N items).
    ///
    /// For defence-in-depth on untrusted feeds, apply a `BodyLimit` layer
    /// upstream — the streaming reader is bounded-memory per item but does
    /// not cap the total document size on its own.
    pub async fn from_body(body: Body) -> Result<Self, FeedParseError> {
        match FeedStream::from_body(body).await?.collect().await {
            Ok(feed) => Ok(feed),
            Err(err) => Err(err.error),
        }
    }

    /// Strict variant of [`Self::from_body`]. Collapses the
    /// [`super::FeedCollectError`] from the underlying [`FeedStream::collect`]
    /// into just its [`FeedParseError`]; if you need the partial feed on a
    /// mid-stream error, drain a [`FeedStream`] yourself.
    pub async fn from_body_strict(body: Body) -> Result<Self, FeedParseError> {
        match FeedStream::from_body_strict(body).await?.collect().await {
            Ok(feed) => Ok(feed),
            Err(err) => Err(err.error),
        }
    }

    /// Returns `true` if this is an RSS 2.0 feed.
    #[must_use]
    pub fn is_rss2(&self) -> bool {
        matches!(self, Self::Rss2(_))
    }

    /// Returns `true` if this is an Atom feed.
    #[must_use]
    pub fn is_atom(&self) -> bool {
        matches!(self, Self::Atom(_))
    }

    /// Returns the inner RSS 2.0 feed, if this is one.
    #[must_use]
    pub fn as_rss2(&self) -> Option<&Rss2Feed> {
        match self {
            Self::Rss2(f) => Some(f),
            Self::Atom(_) => None,
        }
    }

    /// Returns the inner Atom feed, if this is one.
    #[must_use]
    pub fn as_atom(&self) -> Option<&AtomFeed> {
        match self {
            Self::Atom(f) => Some(f),
            Self::Rss2(_) => None,
        }
    }

    // -----------------------------------------------------------------
    // Cross-format accessors.
    //
    // The two specs use different vocabularies for the same concepts
    // (RSS pubDate ↔ Atom published, RSS description ↔ Atom subtitle /
    // summary / content, RSS <author> string ↔ Atom Person, …). These
    // accessors return the obvious mapping; per-spec divergences are
    // documented on each method. Per-format fields that have no
    // counterpart in the other spec (Atom <id>, RSS <ttl>, iTunes /
    // Podcasting 2.0 extensions, …) stay behind the per-format types
    // and the Self::Rss2(_) / Self::Atom(_) discrimination.
    // -----------------------------------------------------------------

    /// Feed title (Atom requires; RSS technically requires too — empty if a
    /// malformed feed lacks it).
    #[must_use]
    pub fn title(&self) -> &str {
        match self {
            Self::Rss2(f) => &f.title,
            Self::Atom(f) => f.title.value.as_str(),
        }
    }

    /// RSS `<description>` (required) | Atom `<subtitle>` (optional).
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        match self {
            Self::Rss2(f) => Some(&f.description),
            Self::Atom(f) => f.subtitle.as_ref().map(|t| t.value.as_str()),
        }
    }

    /// Human-readable home URL of the feed. RSS `<link>` | Atom
    /// `<link rel="alternate">` (or first link without `rel`, since Atom
    /// defaults `rel` to `"alternate"`).
    #[must_use]
    pub fn link(&self) -> Option<&str> {
        match self {
            Self::Rss2(f) => Some(&f.link),
            Self::Atom(f) => pick_alternate(&f.links).map(|l| l.href.as_str()),
        }
    }

    /// Canonical URL of the feed document itself. RSS
    /// `<atom:link rel="self">` | Atom `<link rel="self">`.
    #[must_use]
    pub fn self_link(&self) -> Option<&str> {
        match self {
            Self::Rss2(f) => pick_rel(&f.atom_links, "self").map(|l| l.href.as_str()),
            Self::Atom(f) => pick_rel(&f.links, "self").map(|l| l.href.as_str()),
        }
    }

    /// Atom `<id>` (required). RSS has no equivalent — always `None` for RSS.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        match self {
            Self::Rss2(_) => None,
            Self::Atom(f) => Some(&f.id),
        }
    }

    /// RSS `<language>` | Atom currently `None` (xml:lang on the root isn't
    /// captured yet).
    #[must_use]
    pub fn language(&self) -> Option<&str> {
        match self {
            Self::Rss2(f) => f.language.as_deref(),
            Self::Atom(_) => None,
        }
    }

    /// RSS `<copyright>` | Atom `<rights>`.
    #[must_use]
    pub fn copyright(&self) -> Option<&str> {
        match self {
            Self::Rss2(f) => f.copyright.as_deref(),
            Self::Atom(f) => f.rights.as_ref().map(|t| t.value.as_str()),
        }
    }

    /// Generator string. RSS `<generator>` | Atom `<generator>` value (the
    /// uri/version attributes are dropped — use the per-format type to keep
    /// them).
    #[must_use]
    pub fn generator(&self) -> Option<&str> {
        match self {
            Self::Rss2(f) => f.generator.as_deref(),
            Self::Atom(f) => f.generator.as_ref().map(|g| g.value.as_str()),
        }
    }

    /// RSS `<image><url>` | Atom `<logo>`.
    #[must_use]
    pub fn image_url(&self) -> Option<&str> {
        match self {
            Self::Rss2(f) => f.image.as_ref().map(|i| i.url.as_str()),
            Self::Atom(f) => f.logo.as_deref(),
        }
    }

    /// Atom `<icon>` | RSS has no equivalent.
    #[must_use]
    pub fn icon_url(&self) -> Option<&str> {
        match self {
            Self::Rss2(_) => None,
            Self::Atom(f) => f.icon.as_deref(),
        }
    }

    /// RSS `<pubDate>` | Atom has no feed-level "first published" — `None`.
    #[must_use]
    pub fn published(&self) -> Option<Timestamp> {
        match self {
            Self::Rss2(f) => f.pub_date,
            Self::Atom(_) => None,
        }
    }

    /// RSS `<lastBuildDate>` | Atom `<updated>` (required).
    #[must_use]
    pub fn updated(&self) -> Option<Timestamp> {
        match self {
            Self::Rss2(f) => f.last_build_date,
            Self::Atom(f) => Some(f.updated),
        }
    }

    /// Feed-level authors. RSS yields `[managingEditor, webMaster]` (filtered,
    /// in declaration order). Atom yields the `<author>` Person list (names).
    #[must_use]
    pub fn authors(&self) -> Vec<&str> {
        match self {
            Self::Rss2(f) => [f.managing_editor.as_deref(), f.web_master.as_deref()]
                .into_iter()
                .flatten()
                .filter(|s| !s.is_empty())
                .collect(),
            Self::Atom(f) => f.authors.iter().map(|p| p.name.as_str()).collect(),
        }
    }

    /// Feed-level category names (RSS `<category>` names / Atom `<category>`
    /// terms).
    #[must_use]
    pub fn categories(&self) -> Vec<&str> {
        match self {
            Self::Rss2(f) => f.categories.iter().map(|c| c.name.as_str()).collect(),
            Self::Atom(f) => f.categories.iter().map(|c| c.term.as_str()).collect(),
        }
    }
}

impl From<Rss2Feed> for Feed {
    fn from(f: Rss2Feed) -> Self {
        Self::Rss2(f)
    }
}

impl From<AtomFeed> for Feed {
    fn from(f: AtomFeed) -> Self {
        Self::Atom(f)
    }
}

// ---------------------------------------------------------------------------
// IntoResponse
// ---------------------------------------------------------------------------

impl IntoResponse for Rss2Feed {
    fn into_response(self) -> Response {
        (
            Headers::single(ContentType::rss()),
            Body::from_stream(self.into_stream_writer()),
        )
            .into_response()
    }
}

impl IntoResponse for AtomFeed {
    fn into_response(self) -> Response {
        (
            Headers::single(ContentType::atom()),
            Body::from_stream(self.into_stream_writer()),
        )
            .into_response()
    }
}

impl IntoResponse for Feed {
    fn into_response(self) -> Response {
        match self {
            Self::Rss2(f) => f.into_response(),
            Self::Atom(f) => f.into_response(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{StatusCode, header};

    #[test]
    fn rss2_into_response_sets_content_type() {
        let feed = Rss2Feed::builder()
            .title("T")
            .link("https://example.com")
            .description("D")
            .build();
        let resp = feed.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get(header::CONTENT_TYPE).unwrap();
        assert!(ct.to_str().unwrap().contains("rss+xml"));
    }

    #[test]
    fn atom_into_response_sets_content_type() {
        use crate::protocols::rss::atom::{AtomFeed, AtomText};
        use jiff::Timestamp;
        let feed = AtomFeed::builder()
            .id("urn:x:1")
            .title(AtomText::text("T"))
            .updated(Timestamp::UNIX_EPOCH)
            .build();
        let resp = feed.into_response();
        let ct = resp.headers().get(header::CONTENT_TYPE).unwrap();
        assert!(ct.to_str().unwrap().contains("atom+xml"));
    }

    #[test]
    fn feed_umbrella_round_trips() {
        let rss = Rss2Feed::builder()
            .title("Blog")
            .link("https://blog.example.com")
            .description("A blog")
            .build();
        let feed: Feed = rss.into();
        assert!(feed.is_rss2());
        assert_eq!(feed.title(), "Blog");
        assert!(feed.as_rss2().is_some());
        assert!(feed.as_atom().is_none());
    }
}
