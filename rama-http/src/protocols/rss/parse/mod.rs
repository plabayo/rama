//! Lenient (default) and strict RSS 2.0 / Atom 1.0 parsing.
//!
//! The entry points are [`Feed::parse`](super::Feed::parse) (lenient) and
//! [`Feed::parse_strict`](super::Feed::parse_strict) (strict). Lenient parsing
//! silently skips elements it cannot understand; strict parsing returns an
//! error for any structural violation.
//!
//! The module is split for readability:
//! * `error` — [`FeedParseError`] type.
//! * `rss2` — the RSS 2.0 event-loop parser.
//! * `atom1` — the Atom 1.0 event-loop parser (and xhtml subtree capture).
//! * `helpers` — `attr_value`, date parsing, the `Attrs` alias and other small
//!   utilities shared with the writers.
//! * `tests` — all parser unit tests.

mod atom1;
mod error;
mod helpers;
mod rss2;

#[cfg(test)]
mod tests;

use super::feed::Feed;

pub use error::FeedParseError;
pub(super) use helpers::{Attrs, attr_value, parse_rss2_date};

pub(super) fn parse_feed(input: &str, strict: bool) -> Result<Feed, FeedParseError> {
    // Quick sniff for format detection before full parse.
    let trimmed = input.trim_start();
    let is_atom = detect_atom(trimmed);
    let is_rss = !is_atom && detect_rss(trimmed);

    // Each parser reports whether it actually saw a recognized root element
    // (`<rss>`/`<channel>` or `<feed>`); without one the input is not a feed,
    // so even lenient parsing returns an error rather than an empty feed.
    if is_atom {
        let (feed, saw_root) = atom1::parse_atom(input, strict)?;
        if saw_root {
            return Ok(Feed::Atom(feed));
        }
    } else if is_rss {
        let (feed, saw_root) = rss2::parse_rss2(input, strict)?;
        if saw_root {
            return Ok(Feed::Rss2(feed));
        }
    }

    if strict {
        return Err(FeedParseError::new(
            "document is neither RSS 2.0 nor Atom 1.0",
        ));
    }

    // Lenient fallback: accept only if a recognized feed root is present.
    if let Ok((feed, true)) = rss2::parse_rss2(input, false) {
        return Ok(Feed::Rss2(feed));
    }
    if let Ok((feed, true)) = atom1::parse_atom(input, false) {
        return Ok(Feed::Atom(feed));
    }
    Err(FeedParseError::new("unrecognized feed format"))
}

fn detect_atom(s: &str) -> bool {
    // Either the Atom namespace URI is declared (any prefix), or a bare
    // `<feed>` element is present. Looking for the URI alone catches prefixed
    // roots like `<a:feed xmlns:a="http://www.w3.org/2005/Atom">`.
    let probe = probe_prefix(s, 2048);
    probe.contains("w3.org/2005/Atom") || probe.contains("<feed>") || probe.contains("<feed ")
}

fn detect_rss(s: &str) -> bool {
    let probe = probe_prefix(s, 1024);
    probe.contains("<rss") || probe.contains("<channel")
}

/// Largest prefix of `s` no longer than `max` bytes, never splitting a
/// multi-byte UTF-8 char (plain byte slicing would panic on a non-boundary).
fn probe_prefix(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}
