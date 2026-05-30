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
    // Quick sniff for format detection before full parse. RSS is checked
    // first: RSS feeds routinely declare `xmlns:atom="…"` for `<atom:link>`,
    // which would false-positive an Atom-first probe.
    let trimmed = input.trim_start();
    let is_rss = detect_rss(trimmed);
    let is_atom = !is_rss && detect_atom(trimmed);

    // Each parser reports whether it actually saw a recognized root element
    // (`<rss>`/`<channel>` or `<feed>`); without one the input is not a feed,
    // so even lenient parsing returns an error rather than an empty feed.
    if is_rss {
        let (feed, saw_root) = rss2::parse_rss2(input, strict)?;
        if saw_root {
            return Ok(Feed::Rss2(feed));
        }
    } else if is_atom {
        let (feed, saw_root) = atom1::parse_atom(input, strict)?;
        if saw_root {
            return Ok(Feed::Atom(feed));
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

/// Sniff whether `s` looks like an Atom 1.0 document. We look at the *first
/// real element* (skipping `<?xml…?>`, comments and DOCTYPE) and check that
/// its local name is `feed`. This catches both plain `<feed xmlns=…>` and a
/// prefix-bound root like `<a:feed xmlns:a="http://www.w3.org/2005/Atom">`
/// without false-positiving on an RSS feed that merely *declares* the Atom
/// namespace prefix (e.g. for `<atom:link rel="self"/>`).
pub(super) fn detect_atom(s: &str) -> bool {
    first_element_local_name(probe_prefix(s, 2048)) == Some("feed")
}

/// Sniff whether `s` looks like an RSS 2.0 document — first element is `rss`
/// (or `channel`, if some upstream stripped the wrapping `<rss>` shell).
pub(super) fn detect_rss(s: &str) -> bool {
    matches!(
        first_element_local_name(probe_prefix(s, 1024)),
        Some("rss" | "channel")
    )
}

/// Find the local name of the first real element in `s`, skipping the XML
/// declaration, comments and DOCTYPE. Returns `None` if no element is found
/// inside the probed window.
fn first_element_local_name(s: &str) -> Option<&str> {
    let mut rest = s;
    loop {
        // Find the next `<`.
        let lt = rest.find('<')?;
        rest = &rest[lt + 1..];
        if let Some(after) = rest.strip_prefix("?xml") {
            // XML declaration: skip to `?>`.
            let end = after.find("?>")?;
            rest = &after[end + 2..];
            continue;
        }
        if let Some(after) = rest.strip_prefix("!--") {
            // Comment: skip to `-->`.
            let end = after.find("-->")?;
            rest = &after[end + 3..];
            continue;
        }
        if let Some(after) = rest.strip_prefix("!DOCTYPE") {
            // DOCTYPE: skip to the matching `>` at depth 0 (no internal subset
            // support — good enough for sniffing).
            let end = after.find('>')?;
            rest = &after[end + 1..];
            continue;
        }
        if rest.starts_with('!') || rest.starts_with('?') {
            // Some other declaration/PI we don't care about; skip to `>`.
            let end = rest.find('>')?;
            rest = &rest[end + 1..];
            continue;
        }
        // Real element name; ends at whitespace, `/`, or `>`.
        let qname_end = rest
            .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
            .unwrap_or(rest.len());
        let qname = &rest[..qname_end];
        // Strip any namespace prefix (`a:feed` -> `feed`).
        return Some(qname.rsplit(':').next().unwrap_or(qname));
    }
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
