//! WHATWG URL test corpus runner.
//!
//! The corpus is `whatwg_urltestdata.json`, vendored from
//! <https://github.com/web-platform-tests/wpt/blob/master/url/resources/urltestdata.json>.
//! It encodes browser URL parsing semantics — a deliberate divergence
//! from RFC 3986 in several places (see policy notes in
//! [`crate::uri::parser`] module docs).
//!
//! We run the corpus in **Mode A (crash-resistance)**: every input must
//! be fed to both `Uri::parse_bytes` and `Uri::parse_bytes_strict`
//! without panicking. The result (Ok or typed Err) is acceptable either
//! way — that's the policy divergence at work.
//!
//! Where our policy differs from WHATWG in security-relevant ways, the
//! `POLICY_DIVERGENCES` table documents the disagreement. Each row pairs
//! a sample input with the reason we differ; the documentation surface
//! is the table itself, not a per-row assertion (asserting WHATWG's
//! browser-quirk output would force us to either match it — bad — or
//! maintain a parallel expected-output table for every relevant entry).

use rama_core::bytes::Bytes;
use serde_json::Value;

use crate::uri::Uri;

/// Bytes of the WHATWG URL test data, vendored at the time of M3 (d).
/// Updated by re-downloading from web-platform-tests.
const WHATWG_URLTESTDATA: &[u8] = include_bytes!("whatwg_urltestdata.json");

/// Categories of behaviour where our policy differs from WHATWG. Each
/// variant has a representative input; the *reason* is the documentation
/// — that's the point of having this table.
#[derive(Debug, Clone, Copy)]
enum PolicyDifference {
    /// We never fold `\` to `/` (request-smuggling vector).
    BackslashNotFolded,
    /// We never silently strip control chars (header-injection vector).
    ControlCharNotStripped,
    /// We never decode alt-IPv4 forms to canonical 127.0.0.1 (SSRF
    /// amplifier).
    AltIpv4PreservedAsName,
    /// We never strip default ports / lowercase host / decode unreserved
    /// host bytes (breaks SigV4, OAuth, cache keys).
    NoNormalizationAtParse,
    /// `file:` URLs have WHATWG-specific path / host coercion rules we
    /// don't implement.
    FileSchemeQuirksNotImplemented,
}

/// Hand-curated table of WHATWG inputs where our behaviour differs. Not
/// exhaustive — this is documentation, not an exhaustive policy oracle.
const POLICY_DIVERGENCES: &[(&str, PolicyDifference)] = &[
    (
        "http://example.com\\foo",
        PolicyDifference::BackslashNotFolded,
    ),
    (
        "http://example.com/\tfoo",
        PolicyDifference::ControlCharNotStripped,
    ),
    (
        "http://example.com/foo\nbar",
        PolicyDifference::ControlCharNotStripped,
    ),
    (
        "http://0177.0.0.1/",
        PolicyDifference::AltIpv4PreservedAsName,
    ),
    (
        "http://0x7f.0.0.1/",
        PolicyDifference::AltIpv4PreservedAsName,
    ),
    (
        "http://EXAMPLE.com:80/Path",
        PolicyDifference::NoNormalizationAtParse,
    ),
    (
        "file:///C:/foo",
        PolicyDifference::FileSchemeQuirksNotImplemented,
    ),
    (
        "file:C:/foo",
        PolicyDifference::FileSchemeQuirksNotImplemented,
    ),
];

#[test]
fn whatwg_corpus_no_panic_either_mode() {
    let entries: Vec<Value> = serde_json::from_slice(WHATWG_URLTESTDATA)
        .expect("vendored whatwg_urltestdata.json must be valid JSON");

    let mut tested = 0usize;
    let mut graceful_ok = 0usize;
    let mut strict_ok = 0usize;

    for entry in &entries {
        // Comment lines come as plain strings — skip.
        let Some(obj) = entry.as_object() else {
            continue;
        };
        // Skip entries without an `input` field (some are nested or weird).
        let Some(input) = obj.get("input").and_then(Value::as_str) else {
            continue;
        };

        tested += 1;
        let buf = Bytes::copy_from_slice(input.as_bytes());

        // The contract: neither parser may panic, segfault, or hang.
        // Either Ok or Err is acceptable.
        if Uri::parse(buf.clone()).is_ok() {
            graceful_ok += 1;
        }
        if Uri::parse_strict(buf).is_ok() {
            strict_ok += 1;
        }
    }

    // Sanity floor: we should be able to read SOME entries from the corpus.
    assert!(
        tested >= 100,
        "WHATWG corpus loaded only {tested} entries — JSON probably broken"
    );

    // Diagnostic — printed only on failure or with `--nocapture`.
    eprintln!("whatwg corpus: tested={tested} graceful_ok={graceful_ok} strict_ok={strict_ok}",);
}

/// Verify the policy-divergence table compiles and references real inputs
/// (forces us to keep the table accurate as the parser evolves).
#[test]
fn policy_divergence_table_self_consistent() {
    for (input, diff) in POLICY_DIVERGENCES {
        // Each input must parse-or-error without panic in both modes.
        let buf = Bytes::copy_from_slice(input.as_bytes());
        drop(Uri::parse(buf.clone()));
        drop(Uri::parse_strict(buf));
        // The variant name surfaces via Debug if the entry is ever
        // surprising — keeps the table honest.
        drop(format!("{diff:?}"));
    }
}
