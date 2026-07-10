//! Error types returned by the RSS / Atom streaming readers.

use std::fmt;

use super::Feed;
use super::atom::AtomFeed;
use super::rss2::Rss2Feed;

/// Returned when the document cannot be turned into a feed at all — either
/// nothing recognisable as an RSS 2.0 / Atom 1.0 root was seen, or strict
/// mode rejected a structural violation in the header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedParseError {
    pub message: String,
}

impl FeedParseError {
    pub(super) fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }
}

impl fmt::Display for FeedParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "feed parse error: {}", self.message)
    }
}

impl std::error::Error for FeedParseError {}

/// Returned by [`Rss2FeedStream::collect`], [`AtomFeedStream::collect`] and
/// [`FeedStream::collect`] when an item / entry fails to parse partway
/// through the stream. The `partial` feed holds the header that was parsed
/// at stream construction *and* every item / entry that succeeded before
/// the failure, so callers can keep what's salvageable.
///
/// Use [`Rss2FeedStream::collect_lossy`] / [`AtomFeedStream::collect_lossy`]
/// /[`FeedStream::collect_lossy`] when per-item errors should be skipped
/// silently instead of short-circuiting.
///
/// [`Rss2FeedStream::collect`]: super::Rss2FeedStream::collect
/// [`AtomFeedStream::collect`]: super::AtomFeedStream::collect
/// [`FeedStream::collect`]: super::FeedStream::collect
/// [`Rss2FeedStream::collect_lossy`]: super::Rss2FeedStream::collect_lossy
/// [`AtomFeedStream::collect_lossy`]: super::AtomFeedStream::collect_lossy
/// [`FeedStream::collect_lossy`]: super::FeedStream::collect_lossy
#[derive(Debug, Clone, PartialEq)]
pub struct CollectError<F> {
    /// The underlying per-item parse error.
    pub error: FeedParseError,
    /// The header plus every item / entry that was parsed before the error.
    /// The header is always populated; the items list may be empty if the
    /// failure happened on the very first item.
    pub partial: Box<F>,
}

impl<F: fmt::Debug> fmt::Display for CollectError<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "collect failed: {} (partial feed retained)", self.error)
    }
}

impl<F: fmt::Debug> std::error::Error for CollectError<F> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Per-format convenience alias.
pub type Rss2CollectError = CollectError<Rss2Feed>;
/// Per-format convenience alias.
pub type AtomCollectError = CollectError<AtomFeed>;
/// Format-agnostic alias.
pub type FeedCollectError = CollectError<Feed>;
