//! RSS / Atom feed reader TUI for the web client.
//!
//! When the web client receives a feed response and the output is an
//! interactive terminal — i.e. stdout/stdin are a TTY, `-o`/`--output` is not
//! set and this isn't a `--curl` dry-run — the body is rendered in a
//! scrollable reader instead of being dumped to stdout. Detection is fully
//! automatic: it keys off the response `Content-Type` (`application/rss+xml`
//! and `application/atom+xml` always; generic `*/xml` is parsed and only shown
//! as a feed if it actually is one, otherwise the raw bytes are written as
//! before).

use rama::{
    error::{BoxError, ErrorContext as _},
    extensions::{Extension, ExtensionsRef as _},
    http::{
        Body, HeaderMap, Response,
        body::util::BodyExt as _,
        headers::{ContentType, HeaderMapExt as _},
        mime,
        protocols::rss::{Feed, FeedStream},
    },
    telemetry::tracing,
};
use tokio::io::AsyncWriteExt as _;

use super::super::SendCommand;

mod tui;

/// Marker the response body logger inserts when it decides a response is a
/// feed-reader candidate and therefore must NOT be written to stdout. It is
/// read back in [`super::run_inner`] to launch the reader. `generic` records
/// whether the content-type was a canonical feed type or a generic XML type
/// that still needs to be parsed to confirm it is a feed.
#[derive(Debug, Clone, Copy, Extension)]
pub(super) struct FeedTuiCandidate {
    pub(super) generic: bool,
}

/// How feed-like a response content-type is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FeedKind {
    /// `application/rss+xml` / `application/atom+xml` — definitely a feed.
    Canonical,
    /// `application/xml` / `text/xml` — maybe a feed; the body must be parsed
    /// to be sure.
    GenericXml,
}

/// Classify a response by its typed [`ContentType`] header. Returns `None` for
/// any content-type that is not a feed candidate. Comparisons go through the
/// parsed [`mime`] parts, so charset (and other) parameters are ignored and the
/// type/subtype/suffix matching is case-insensitive.
pub(super) fn feed_kind(headers: &HeaderMap) -> Option<FeedKind> {
    let ct = headers.typed_get::<ContentType>()?.into_mime();
    let (ty, sub, suffix) = (ct.type_(), ct.subtype(), ct.suffix());

    // application/rss+xml | application/atom+xml
    if ty == mime::APPLICATION && suffix == Some(mime::XML) && (sub == "rss" || sub == "atom") {
        return Some(FeedKind::Canonical);
    }
    // application/xml | text/xml — could be a feed; confirmed by parsing.
    if sub == mime::XML && suffix.is_none() && (ty == mime::APPLICATION || ty == mime::TEXT) {
        return Some(FeedKind::GenericXml);
    }
    None
}

/// Whether the web client may launch the feed reader for this invocation:
/// interactive shell (stdout and stdin are both a TTY), output not redirected
/// to a file, and not a `--curl` dry-run.
pub(super) fn tui_gate_open(cfg: &SendCommand) -> bool {
    use std::io::IsTerminal as _;
    cfg.output.is_none()
        && !cfg.curl
        && std::io::stdout().is_terminal()
        && std::io::stdin().is_terminal()
}

/// Render the feed response in the reader. For canonical feed content-types the
/// body is streamed and entries appear as they parse. For generic XML the body
/// is parsed first; if it turns out not to be a feed the raw bytes are written
/// to stdout, preserving the non-feed behavior.
pub(super) async fn run(resp: Response, candidate: FeedTuiCandidate) -> Result<(), BoxError> {
    let (_parts, body) = resp.into_parts();

    if candidate.generic {
        let bytes = body
            .collect()
            .await
            .context("collect feed response body")?
            .to_bytes();
        match Feed::from_body(Body::from(bytes.clone())).await {
            Ok(feed) => tui::run_buffered(feed).await,
            Err(err) => {
                tracing::debug!(
                    "generic xml response is not a parseable feed ({err}); writing raw bytes"
                );
                write_stdout(&bytes).await
            }
        }
    } else {
        let stream = FeedStream::from_body(body)
            .await
            .context("parse feed response header")?;
        tui::run_streaming(stream).await
    }
}

async fn write_stdout(bytes: &[u8]) -> Result<(), BoxError> {
    let mut out = tokio::io::stdout();
    out.write_all(bytes)
        .await
        .context("write response bytes to stdout")?;
    out.flush().await.context("flush stdout")?;
    Ok(())
}

/// Convenience used by [`super::run_inner`]: pull the candidate marker (if any)
/// off a response.
pub(super) fn candidate_of(resp: &Response) -> Option<FeedTuiCandidate> {
    resp.extensions().get_ref::<FeedTuiCandidate>().copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::http::{HeaderMap, header};

    fn headers_with_ct(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::CONTENT_TYPE, value.parse().unwrap());
        h
    }

    #[test]
    fn feed_kind_canonical_types() {
        assert_eq!(
            feed_kind(&headers_with_ct("application/rss+xml")),
            Some(FeedKind::Canonical)
        );
        assert_eq!(
            feed_kind(&headers_with_ct("application/atom+xml")),
            Some(FeedKind::Canonical)
        );
        // case-insensitive + parameters are tolerated
        assert_eq!(
            feed_kind(&headers_with_ct("Application/RSS+XML; charset=utf-8")),
            Some(FeedKind::Canonical)
        );
    }

    #[test]
    fn feed_kind_generic_xml() {
        assert_eq!(
            feed_kind(&headers_with_ct("application/xml")),
            Some(FeedKind::GenericXml)
        );
        assert_eq!(
            feed_kind(&headers_with_ct("text/xml; charset=utf-8")),
            Some(FeedKind::GenericXml)
        );
    }

    #[test]
    fn feed_kind_non_feed() {
        assert_eq!(feed_kind(&headers_with_ct("text/html")), None);
        assert_eq!(feed_kind(&headers_with_ct("application/json")), None);
        assert_eq!(feed_kind(&headers_with_ct("text/plain")), None);
        assert_eq!(feed_kind(&HeaderMap::new()), None);
    }
}
