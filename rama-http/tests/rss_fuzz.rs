//! Property-based fuzzing for the RSS / Atom parser surface.
//!
//! The parser is fed arbitrary attacker-controlled input in the proxy and
//! client use cases. The properties exercised here are:
//!
//! * `Feed::parse` (lenient) **must never panic** on any byte string.
//! * `Feed::parse_strict` must never panic either — it may return `Err`, but
//!   must not unwind through arbitrary input.
//! * The same input fed through both modes must agree on the obvious fact that
//!   anything strict accepts, lenient must also accept.
//!
//! `quickcheck` generates strings biased toward `ASCII` plus some specific
//! shapes (XML-ish, with stray tags and entities) so the test runs fast yet
//! still exercises the interesting edges.

#![cfg(feature = "rss")]
#![expect(
    clippy::needless_pass_by_value,
    reason = "quickcheck requires by-value Arbitrary arguments for shrinking"
)]
#![expect(
    clippy::let_underscore_must_use,
    reason = "the property under test is that parse does not panic; the value itself doesn't matter"
)]

use quickcheck::{Arbitrary, Gen, TestResult};
use quickcheck_macros::quickcheck;

use rama_http::protocols::rss::Feed;

/// Bytes biased toward XML-ish shapes so the parser is exercised on interesting
/// inputs more often than purely random `String::arbitrary` would.
#[derive(Debug, Clone)]
struct FeedLikeBytes(Vec<u8>);

impl Arbitrary for FeedLikeBytes {
    fn arbitrary(g: &mut Gen) -> Self {
        // Tokens worth interleaving:
        //   `<rss>` / `<channel>` / `<feed>` to trip detection,
        //   `<item>` / `<entry>` to enter element states,
        //   `<![CDATA[` / `]]>` for the CDATA path,
        //   `&amp;` / `&` / `&bogus;` for the entity path,
        //   `<` / `>` for tokenizer edges,
        //   plus a few real attribute names and multi-byte chars to keep the
        //   utf-8 boundary code honest.
        let chunks: &[&[u8]] = &[
            b"<rss version=\"2.0\">",
            b"<channel>",
            b"<title>",
            b"</title>",
            b"<item>",
            b"</item>",
            b"<link>",
            b"</link>",
            b"<description>",
            b"</description>",
            b"</channel>",
            b"</rss>",
            b"<feed xmlns=\"http://www.w3.org/2005/Atom\">",
            b"<entry>",
            b"</entry>",
            b"<id>",
            b"</id>",
            b"<updated>2024-01-01T00:00:00Z</updated>",
            b"</feed>",
            b"<source>",
            b"</source>",
            b"<author><name>",
            b"</name></author>",
            b"<![CDATA[",
            b"]]>",
            b"&amp;",
            b"&bogus;",
            b"<>",
            b"<!--",
            b"-->",
            b"<?xml version=\"1.0\"?>",
            b"<!DOCTYPE x>",
            b"\xff\xfe", // would-be UTF-16 BOM
            "🎙".as_bytes(),
            "€".as_bytes(),
            b"a",
            b" ",
            b"\n",
            b"\"",
        ];
        let len = u8::arbitrary(g) % 32;
        let mut out = Vec::with_capacity(64);
        for _ in 0..len {
            let pick = (u8::arbitrary(g) as usize) % chunks.len();
            out.extend_from_slice(chunks[pick]);
        }
        Self(out)
    }
}

#[quickcheck]
fn parse_never_panics(input: FeedLikeBytes) -> TestResult {
    let Ok(s) = std::str::from_utf8(&input.0) else {
        // Public `Feed::parse` takes `&str`; non-utf8 isn't its concern.
        return TestResult::discard();
    };
    let _ = Feed::parse(s);
    let _ = Feed::parse_strict(s);
    TestResult::passed()
}

#[quickcheck]
fn strict_acceptance_implies_lenient_acceptance(input: FeedLikeBytes) -> TestResult {
    let Ok(s) = std::str::from_utf8(&input.0) else {
        return TestResult::discard();
    };
    if Feed::parse_strict(s).is_ok() {
        // If strict accepts it, lenient must too — there is no input that
        // strict accepts but lenient rejects.
        assert!(
            Feed::parse(s).is_ok(),
            "strict accepted but lenient rejected: {s:?}"
        );
    }
    TestResult::passed()
}
