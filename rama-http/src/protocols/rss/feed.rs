//! [`Feed`] umbrella type, [`IntoResponse`] impls, and client-side parse entry
//! points (`Feed::from_body`, `Feed::from_str`).

use std::str::FromStr;

use crate::{Body, Response, StatusCode};
use crate::headers::ContentType;
use crate::service::web::response::{Headers, IntoResponse};

use super::atom::AtomFeed;
use super::parse::{FeedParseError, parse_feed};
use super::rss2::Rss2Feed;

// ---------------------------------------------------------------------------
// Feed umbrella
// ---------------------------------------------------------------------------

/// A feed in either RSS 2.0 or Atom 1.0 format.
#[derive(Debug, Clone, PartialEq)]
pub enum Feed {
    Rss2(Rss2Feed),
    Atom(AtomFeed),
}

impl Feed {
    /// Parse a feed document, detecting the format automatically.
    ///
    /// Unrecognized elements are silently ignored.
    pub fn parse(input: &str) -> Result<Self, FeedParseError> {
        parse_feed(input, false)
    }

    /// Parse a feed document strictly; any structural violation returns an
    /// error.
    pub fn parse_strict(input: &str) -> Result<Self, FeedParseError> {
        parse_feed(input, true)
    }

    /// Parse a feed from a [`Body`], consuming it entirely.
    pub async fn from_body(body: Body) -> Result<Self, FeedParseError> {
        use crate::BodyExtractExt as _;
        let text = body
            .try_into_string()
            .await
            .map_err(|e| FeedParseError { message: e.to_string() })?;
        Self::parse(&text)
    }

    /// Parse a feed from a [`Body`] in strict mode.
    pub async fn from_body_strict(body: Body) -> Result<Self, FeedParseError> {
        use crate::BodyExtractExt as _;
        let text = body
            .try_into_string()
            .await
            .map_err(|e| FeedParseError { message: e.to_string() })?;
        Self::parse_strict(&text)
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

impl FromStr for Feed {
    type Err = FeedParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
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
        match self.to_xml() {
            Ok(xml) => (Headers::single(ContentType::rss()), Body::from(xml)).into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

impl IntoResponse for AtomFeed {
    fn into_response(self) -> Response {
        match self.to_xml() {
            Ok(xml) => (Headers::single(ContentType::atom()), Body::from(xml)).into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
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
    use crate::header;

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
