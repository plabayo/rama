//! Property-based fuzzing for the async streaming RSS / Atom reader.
//!
//! The reader is fed attacker-controlled bytes in the proxy and client cases,
//! so the property is: `FeedStream::new` (lenient) and `FeedStream::new_strict`
//! must never panic on any utf-8 input.
//!
//! `quickcheck` generates byte strings biased toward XML-ish shapes so the
//! parser is exercised on interesting inputs more often than purely random
//! `String::arbitrary` would.

#![cfg(feature = "rss")]
#![expect(
    clippy::expect_used,
    reason = "fuzz test: panicking on runtime build failure is the assertion"
)]

use std::sync::OnceLock;

use quickcheck::{Arbitrary, Gen, TestResult};
use quickcheck_macros::quickcheck;

use rama_http::protocols::rss::FeedStream;

/// Bytes biased toward XML-ish shapes so the parser is exercised on
/// interesting inputs more often than purely random `String::arbitrary`.
#[derive(Debug, Clone)]
struct FeedLikeBytes(Vec<u8>);

impl Arbitrary for FeedLikeBytes {
    fn arbitrary(g: &mut Gen) -> Self {
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

fn rt() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime")
    })
}

async fn drive(bytes: Vec<u8>, strict: bool) {
    let cursor = std::io::Cursor::new(bytes);
    let reader = tokio::io::BufReader::new(cursor);
    let result = if strict {
        FeedStream::new_strict(reader).await
    } else {
        FeedStream::new(reader).await
    };
    if let Ok(stream) = result {
        // Drain to completion to exercise the items path too.
        let _ = stream.collect_lossy().await;
    }
}

#[quickcheck]
fn parse_never_panics(input: FeedLikeBytes) -> TestResult {
    // Public surface takes bytes via AsyncBufRead, so non-utf8 is fine — but
    // the parser may reject it. The property is: no panic, regardless.
    rt().block_on(drive(input.0.clone(), false));
    rt().block_on(drive(input.0, true));
    TestResult::passed()
}

#[quickcheck]
fn strict_acceptance_implies_lenient_acceptance(input: FeedLikeBytes) -> TestResult {
    let bytes = input.0;
    let strict_ok = rt().block_on(async {
        let cursor = std::io::Cursor::new(bytes.clone());
        let reader = tokio::io::BufReader::new(cursor);
        FeedStream::new_strict(reader).await.is_ok()
    });
    if strict_ok {
        let lenient_ok = rt().block_on(async {
            let cursor = std::io::Cursor::new(bytes.clone());
            let reader = tokio::io::BufReader::new(cursor);
            FeedStream::new(reader).await.is_ok()
        });
        assert!(
            lenient_ok,
            "strict accepted but lenient rejected: {:?}",
            String::from_utf8_lossy(&bytes)
        );
    }
    TestResult::passed()
}
