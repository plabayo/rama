//! [`Feed`] umbrella type, [`IntoResponse`] impls, and the `from_body`
//! convenience that drains [`FeedStream`] into an in-memory feed.
//!
//! There is **no synchronous high-level parser** — everything goes through
//! the async streaming reader. Callers who need item-by-item processing use
//! [`super::FeedStream`] directly; callers who just want the whole document
//! call [`Feed::from_body`] (which is the "collect" adapter on top).

use crate::headers::ContentType;
use crate::service::web::response::{Headers, IntoResponse};
use crate::{Body, Response};

use super::atom::AtomFeed;
use super::error::FeedParseError;
use super::read::FeedStream;
use super::rss2::Rss2Feed;

/// A feed in either RSS 2.0 or Atom 1.0 format.
#[derive(Debug, Clone, PartialEq)]
pub enum Feed {
    Rss2(Rss2Feed),
    Atom(AtomFeed),
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

    /// The feed title regardless of format.
    #[must_use]
    pub fn title(&self) -> &str {
        match self {
            Self::Rss2(f) => &f.title,
            Self::Atom(f) => f.title.value(),
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
        use super::super::atom::{AtomFeed, AtomText};
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
