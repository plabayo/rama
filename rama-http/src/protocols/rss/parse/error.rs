//! [`FeedParseError`] — returned by both lenient and strict parsing paths when
//! the document cannot be turned into a [`Feed`](super::super::Feed).

/// Returned by parsing when the document is not a recognised feed (lenient) or
/// when the document is structurally invalid (strict).
#[derive(Debug, Clone, PartialEq)]
pub struct FeedParseError {
    pub message: String,
}

impl FeedParseError {
    pub(crate) fn new(msg: impl Into<String>) -> Self {
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
