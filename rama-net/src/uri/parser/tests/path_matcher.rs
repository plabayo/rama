//! `PathPattern` — infallible path-pattern matching + captures.
//!
//! These tests pin the matcher's contract: literal exactness, whole-segment
//! and run captures, anonymous wildcards with literal affixes, catch-all
//! (`**`, incl. mid-pattern), explicit trailing-slash policy, decode-aware
//! comparison, case sensitivity, and the `?` optional element. Each `#[test]`
//! covers one group of the spec matrix.

use crate::uri::{PathMatchOptions, PathPattern, PathRef};

/// Build a [`PathRef`] from a raw on-wire path string.
fn p(s: &str) -> PathRef<'_> {
    PathRef::from_raw_str(s)
}

/// Capture `path` against `pattern`, returning `(name, value)` pairs sorted
/// by name for stable assertions (glob excluded — see [`glob_of`]).
fn caps(pattern: &str, path: &str) -> Option<Vec<(String, String)>> {
    let pat = PathPattern::new(pattern);
    pat.captures(p(path)).map(|c| {
        let mut v: Vec<(String, String)> = c
            .iter()
            .map(|(n, val)| (n.to_owned(), val.to_owned()))
            .collect();
        v.sort();
        v
    })
}

/// The `**` glob value for `path` against `pattern`, if matched.
fn glob_of(pattern: &str, path: &str) -> Option<String> {
    PathPattern::new(pattern)
        .captures(p(path))
        .and_then(|c| c.glob().map(str::to_owned))
}

// ======================================================================
// 1. Literal exact
// ======================================================================

#[test]
fn literal_exact() {
    let pat = PathPattern::new("/backend-api/codex/responses");
    assert!(pat.is_match(p("/backend-api/codex/responses")));
    // No extra trailing segment, no missing segment.
    assert!(!pat.is_match(p("/backend-api/codex/responses/x")));
    assert!(!pat.is_match(p("/backend-api/codex")));
    // Captures present (empty) exactly when is_match is true.
    assert!(pat.captures(p("/backend-api/codex/responses")).is_some());
    assert!(
        pat.captures(p("/backend-api/codex/responses"))
            .unwrap()
            .is_empty()
    );
    assert!(pat.captures(p("/backend-api/codex")).is_none());
}

// ======================================================================
// 2. Whole-segment capture, trailing slash required
// ======================================================================

#[test]
fn whole_segment_capture_trailing_required() {
    // `/simple/:name/` requires the trailing slash.
    assert_eq!(
        caps("/simple/:name/", "/simple/requests/"),
        Some(vec![("name".to_owned(), "requests".to_owned())])
    );
    // Without the trailing slash: no match.
    assert!(caps("/simple/:name/", "/simple/requests").is_none());
}

// ======================================================================
// 3. Optional trailing slash
// ======================================================================

#[test]
fn optional_trailing_slash() {
    // `/simple/:name/?` matches both forms with name=requests.
    let want = Some(vec![("name".to_owned(), "requests".to_owned())]);
    assert_eq!(caps("/simple/:name/?", "/simple/requests"), want);
    assert_eq!(caps("/simple/:name/?", "/simple/requests/"), want);
}

// ======================================================================
// 4. Capture + literal suffix (run capture)
// ======================================================================

#[test]
fn capture_with_suffix() {
    assert_eq!(
        caps("/p2/:vendor/:pkg*.json", "/p2/acme/widget.json"),
        Some(vec![
            ("pkg".to_owned(), "widget".to_owned()),
            ("vendor".to_owned(), "acme".to_owned()),
        ])
    );
    // `~` is inside the captured run.
    assert_eq!(
        caps("/p2/:vendor/:pkg*.json", "/p2/acme/widget~dev.json"),
        Some(vec![
            ("pkg".to_owned(), "widget~dev".to_owned()),
            ("vendor".to_owned(), "acme".to_owned()),
        ])
    );
    // Wrong suffix: no match.
    assert!(caps("/p2/:vendor/:pkg*.json", "/p2/acme/widget.txt").is_none());
}

// ======================================================================
// 5. Anonymous wildcard + literal suffix
// ======================================================================

#[test]
fn anonymous_wildcard_suffix() {
    let pat = PathPattern::new("/files/*.txt");
    assert!(pat.is_match(p("/files/readme.txt")));
    assert!(!pat.is_match(p("/files/readme.md")));
    // No captures recorded for the anonymous `*`.
    assert!(pat.captures(p("/files/readme.txt")).unwrap().is_empty());
}

// ======================================================================
// 6. Catch-all (`**`)
// ======================================================================

#[test]
fn catch_all_tail() {
    assert_eq!(glob_of("/assets/**", "/assets/a"), Some("a".to_owned()));
    assert_eq!(
        glob_of("/assets/**", "/assets/a/b/c"),
        Some("a/b/c".to_owned())
    );
    // `**` requires 1+ segments: `/assets` alone does not match.
    assert!(
        PathPattern::new("/assets/**")
            .captures(p("/assets"))
            .is_none()
    );
    assert!(!PathPattern::new("/assets/**").is_match(p("/assets")));
}

// ======================================================================
// 7. Catch-all in the middle
// ======================================================================

#[test]
fn catch_all_middle() {
    let pat = PathPattern::new("/p2/**/*.txt");
    assert!(pat.is_match(p("/p2/a/b/c.txt")));
    // `**` is 1+, so a single trailing segment leaves nothing for it.
    assert!(!pat.is_match(p("/p2/x.txt")));
    // The glob captures the middle run before the final `*.txt` segment.
    assert_eq!(
        glob_of("/p2/**/*.txt", "/p2/a/b/c.txt"),
        Some("a/b".to_owned())
    );
}

// ======================================================================
// 8. Decode-aware capture
// ======================================================================

#[test]
fn decode_aware_capture() {
    // `%6d` decodes to `m`, so the encoded path still captures vendor=acme.
    assert_eq!(
        caps("/p2/:vendor/:pkg*.json", "/p2/ac%6de/widget.json"),
        Some(vec![
            ("pkg".to_owned(), "widget".to_owned()),
            ("vendor".to_owned(), "acme".to_owned()),
        ])
    );
}

// ======================================================================
// 9. Case sensitivity (default vs ignore_ascii_case)
// ======================================================================

#[test]
fn case_sensitivity() {
    // Default: case-sensitive literal.
    let sensitive = PathPattern::new("/api/v2");
    assert!(sensitive.is_match(p("/api/v2")));
    assert!(!sensitive.is_match(p("/API/v2")));

    // ignore_ascii_case opts into case-insensitive matching.
    let insensitive = PathPattern::new_with_opts(
        "/api/v2",
        PathMatchOptions {
            ignore_ascii_case: true,
            ..Default::default()
        },
    );
    assert!(insensitive.is_match(p("/API/v2")));
    assert!(insensitive.is_match(p("/api/v2")));
}

// ======================================================================
// 10. Char-optional `?`
// ======================================================================

#[test]
fn char_optional() {
    // `ab?c` -> optional `b`.
    let pat = PathPattern::new("/ab?c");
    assert!(pat.is_match(p("/abc")));
    assert!(pat.is_match(p("/ac")));
    assert!(!pat.is_match(p("/abdc")));
}

// ======================================================================
// 11. Empty / root edge cases (no panics)
// ======================================================================

#[test]
fn root_and_empty_edges() {
    // Root pattern matches root path only.
    assert!(PathPattern::new("/").is_match(p("/")));
    assert!(!PathPattern::new("/a").is_match(p("/")));
    assert!(PathPattern::new("/a").is_match(p("/a")));

    // No panics on empty path, bare `*`, or odd inputs (outcomes asserted so
    // the calls aren't dropped, but the point is the absence of a panic).
    assert!(PathPattern::new("").is_match(p("")));
    // `*` is 0+ within a segment, and `/` is a single empty segment, so `/*`
    // matches `/`.
    assert!(PathPattern::new("/*").is_match(p("/")));
    // Odd literal-laden pattern: just must not panic; it shouldn't match `/x`.
    assert!(!PathPattern::new(":weird*?[]").is_match(p("/x")));
    // `/*` (anonymous 0+ within a segment) matches a single non-empty segment.
    assert!(PathPattern::new("/*").is_match(p("/anything")));
    // `**` over a multi-segment path must not panic and joins the glob.
    assert_eq!(glob_of("/**", "/a/b"), Some("a/b".to_owned()));
}

// ======================================================================
// is_match / captures parity + extra no-capture cases
// ======================================================================

#[test]
fn is_match_captures_parity() {
    let cases: &[(&str, &str)] = &[
        (
            "/backend-api/codex/responses",
            "/backend-api/codex/responses",
        ),
        ("/files/*.txt", "/files/a.txt"),
        ("/p2/:vendor/:pkg*.json", "/p2/acme/widget.json"),
        ("/assets/**", "/assets/a/b"),
        ("/simple/:name/?", "/simple/x/"),
        ("/api/v2", "/api/v3"),
        ("/files/*.txt", "/files/a.md"),
        ("/", "/"),
        ("/", "/a"),
    ];
    for (pattern, path) in cases {
        let pat = PathPattern::new(*pattern);
        let m = pat.is_match(p(path));
        let c = pat.captures(p(path));
        assert_eq!(
            m,
            c.is_some(),
            "is_match/captures disagree for pattern {pattern:?} path {path:?}"
        );
    }

    // A pure-literal multi-segment pattern: captures Some+empty when matched.
    let pat = PathPattern::new("/a/b/c");
    assert!(pat.is_match(p("/a/b/c")));
    assert!(pat.captures(p("/a/b/c")).unwrap().is_empty());
    assert!(!pat.is_match(p("/a/b")));
    assert!(pat.captures(p("/a/b")).is_none());
}

// ======================================================================
// get() / is_empty() accessors (direct — the helpers above only read iter/glob)
// ======================================================================

#[test]
fn capture_accessors() {
    let pat = PathPattern::new("/p2/:vendor/:pkg*.json");
    let caps = pat.captures(p("/p2/acme/widget.json")).unwrap();
    assert_eq!(caps.get("vendor"), Some("acme"));
    assert_eq!(caps.get("pkg"), Some("widget"));
    assert_eq!(caps.get("absent"), None);
    assert!(!caps.is_empty());

    let empty_pat = PathPattern::new("/x");
    let empty = empty_pat.captures(p("/x")).unwrap();
    assert!(empty.is_empty());
    assert_eq!(empty.get("anything"), None);
}

// ======================================================================
// Capture directly followed by a literal (no `*`)
// ======================================================================

#[test]
fn capture_then_literal_without_star() {
    // `:pkg.json` (no `*`): the capture is the greedy run before the `.json`
    // literal — same result as `:pkg*.json`. Pins that the literal after the
    // name is matched intact (not having its first byte swallowed).
    let pat = PathPattern::new("/p2/:vendor/:pkg.json");
    let caps = pat.captures(p("/p2/acme/widget.json")).unwrap();
    assert_eq!(caps.get("pkg"), Some("widget"));
    assert_eq!(caps.get("vendor"), Some("acme"));
    assert!(pat.captures(p("/p2/acme/widget.txt")).is_none());
}

// ======================================================================
// Capture names with `_` and `-`
// ======================================================================

#[test]
fn capture_names_with_underscore_and_dash() {
    let pat = PathPattern::new("/:my_name/:other-id");
    let caps = pat.captures(p("/foo/bar")).unwrap();
    assert_eq!(caps.get("my_name"), Some("foo"));
    assert_eq!(caps.get("other-id"), Some("bar"));
}

// ======================================================================
// Capture-free trailing-slash policy (exercises the alloc-free fast path)
// ======================================================================

#[test]
fn capture_free_trailing_slash_fast_path() {
    let required = PathPattern::new("/a/b/");
    assert!(required.is_match(p("/a/b/")));
    assert!(!required.is_match(p("/a/b")));

    let forbidden = PathPattern::new("/a/b");
    assert!(forbidden.is_match(p("/a/b")));
    assert!(!forbidden.is_match(p("/a/b/")));

    let optional = PathPattern::new("/a/b/?");
    assert!(optional.is_match(p("/a/b")));
    assert!(optional.is_match(p("/a/b/")));
}

// ======================================================================
// Backtracking discards tentative bindings before re-binding
// ======================================================================

#[test]
fn backtracking_discards_stale_bindings() {
    // `**` is shortest-first: take=1 ([a]) tentatively binds :x="b" then fails
    // on the leftover [c]; that binding must be discarded before take=2 binds
    // :x="c". A leaked binding would surface as a stale `x` here.
    assert_eq!(
        caps("/**/:x", "/a/b/c"),
        Some(vec![("x".to_owned(), "c".to_owned())])
    );
    assert_eq!(glob_of("/**/:x", "/a/b/c"), Some("a/b".to_owned()));
}

// ======================================================================
// Anonymous (`:` with no name) and glob bindings excluded from get()/iter()
// ======================================================================

#[test]
fn anonymous_and_glob_excluded_from_named() {
    // `:` with no following name is an uncaptured wildcard run.
    let anon_pat = PathPattern::new("/p2/:/:real");
    let caps = anon_pat.captures(p("/p2/foo/bar")).unwrap();
    assert_eq!(caps.get("real"), Some("bar"));
    assert_eq!(caps.iter().collect::<Vec<_>>(), vec![("real", "bar")]);

    // The `**` glob is reachable only via glob(), never get()/iter().
    let glob_pat = PathPattern::new("/files/**/:name");
    let g = glob_pat.captures(p("/files/a/b/x")).unwrap();
    assert_eq!(g.get("name"), Some("x"));
    assert_eq!(g.glob(), Some("a/b"));
    assert_eq!(g.iter().collect::<Vec<_>>(), vec![("name", "x")]);
}

// ======================================================================
// Pathological shapes are polynomial AND still correct
//
// These shapes (many runs / many optionals in one segment, many `**` in a
// pattern) would explode exponentially under naive backtracking; the memo
// keeps them fast. The asserts pin both: a wall-clock budget that a 2^N
// matcher blows through, and the exact match/capture result so the memo can't
// "go fast by being wrong".
// ======================================================================

#[test]
fn pathological_multi_run_segment_is_polynomial_and_correct() {
    use std::time::{Duration, Instant};

    // One segment, two literal-separated captures `[a*][b][b*][b]`: matching
    // "aaa…a" + "bb", greedy-longest binds a="aaa…a" then literal `b`, then
    // b="" before the trailing literal `b`.
    let pat = PathPattern::new("/:a*b:b*b");
    let hay = "/".to_owned() + &"a".repeat(40) + "bb";
    let start = Instant::now();
    let caps = pat.captures(p(&hay)).expect("must match");
    assert_eq!(caps.get("a"), Some("a".repeat(40).as_str()));
    assert_eq!(caps.get("b"), Some(""));

    // A failing match over a long run forces the matcher to prove no split
    // works — the exponential blowup case. Many adjacent captures + literals.
    let fail_pat = PathPattern::new(":x*:y*:z*:w*:v*END");
    let fail_hay = "/".to_owned() + &"q".repeat(60);
    assert!(fail_pat.captures(p(&fail_hay)).is_none());
    assert!(!fail_pat.is_match(p(&fail_hay)));
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "matching must stay polynomial"
    );
}

#[test]
fn pathological_many_optional_literals_is_polynomial() {
    use std::time::{Duration, Instant};

    // Thirty optional `a`s followed by a literal that can't match: the naive
    // matcher forks 2^30 ways before failing.
    let mut raw = String::from("/");
    for _ in 0..30 {
        raw.push_str("a?");
    }
    raw.push('Z');
    let pat = PathPattern::new(raw.as_str());
    let hay = "/".to_owned() + &"a".repeat(30);
    let start = Instant::now();
    assert!(!pat.is_match(p(&hay)));
    assert!(pat.captures(p(&hay)).is_none());
    // All-optional prefix can still match when the literal lands.
    assert!(PathPattern::new(raw.as_str()).is_match(p("/Z")));
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "matching must stay polynomial"
    );
}

#[test]
fn pathological_multi_catchall_is_polynomial_and_correct() {
    use std::time::{Duration, Instant};

    // Eight `**` plus a trailing literal that never appears: naive search is
    // O(segments^8); the cross-segment memo keeps it polynomial. (Two `**`
    // alone are only O(n^2), too cheap to exercise the memo.)
    let pat = PathPattern::new("/**/**/**/**/**/**/**/**/end");
    let hay = "/".to_owned() + &"x/".repeat(30) + "y";
    let start = Instant::now();
    assert!(!pat.is_match(p(&hay)));
    assert!(pat.captures(p(&hay)).is_none());
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "matching must stay polynomial"
    );

    // And it still matches + globs correctly when the tail lines up. `**` is
    // shortest-first, so the first `**` takes one segment and the second the
    // rest before `end`.
    let ok = PathPattern::new("/**/**/end");
    let g = ok.captures(p("/a/b/c/end")).expect("must match");
    assert_eq!(g.glob(), Some("a".to_owned()).as_deref());
}
