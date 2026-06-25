//! `PathPattern` — infallible path-pattern matching and captures.
//!
//! Pins the matcher contract: literal exactness, whole-segment and run
//! captures, anonymous wildcards with literal affixes, catch-all (`{*}`, incl.
//! mid-pattern), explicit trailing-slash policy, decode-aware and case-(in)
//! sensitive comparison, the `?` optional element, polynomial backtracking, and
//! that brace misuse / UTF-8 / percent-encoding never panic. `*`, `:`, `.` etc.
//! are plain literals; only `{`, `}`, `?` are metacharacters.

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

/// The `{*}` glob value for `path` against `pattern`, if matched.
fn glob_of(pattern: &str, path: &str) -> Option<String> {
    PathPattern::new(pattern)
        .captures(p(path))
        .and_then(|c| c.glob().map(str::to_owned))
}

#[test]
fn literal_exact() {
    let pat = PathPattern::new("/backend-api/codex/responses");
    assert!(pat.is_match(p("/backend-api/codex/responses")));
    assert!(!pat.is_match(p("/backend-api/codex/responses/x")));
    assert!(!pat.is_match(p("/backend-api/codex")));
    assert!(
        pat.captures(p("/backend-api/codex/responses"))
            .unwrap()
            .is_empty()
    );
    assert!(pat.captures(p("/backend-api/codex")).is_none());
}

#[test]
fn old_metachars_are_now_literals() {
    // `:` is a plain literal now (Google AIP custom-method style).
    let colon = PathPattern::new("/books:archive");
    assert!(colon.is_match(p("/books:archive")));
    assert!(!colon.is_match(p("/books/archive")));
    assert!(colon.captures(p("/books:archive")).unwrap().is_empty());

    // `*` is a plain literal now, not a wildcard.
    let star = PathPattern::new("/a*b");
    assert!(star.is_match(p("/a*b")));
    assert!(!star.is_match(p("/axb")));
    assert!(!star.is_match(p("/ab")));

    // `**` likewise: a literal segment, no longer a catch-all.
    let dstar = PathPattern::new("/x/**");
    assert!(dstar.is_match(p("/x/**")));
    assert!(!dstar.is_match(p("/x/a/b")));
}

#[test]
fn whole_segment_capture_trailing_required() {
    assert_eq!(
        caps("/simple/{name}/", "/simple/requests/"),
        Some(vec![("name".to_owned(), "requests".to_owned())])
    );
    assert!(caps("/simple/{name}/", "/simple/requests").is_none());
}

#[test]
fn optional_trailing_slash() {
    let want = Some(vec![("name".to_owned(), "requests".to_owned())]);
    assert_eq!(caps("/simple/{name}/?", "/simple/requests"), want);
    assert_eq!(caps("/simple/{name}/?", "/simple/requests/"), want);
}

#[test]
fn capture_with_suffix() {
    assert_eq!(
        caps("/p2/{vendor}/{pkg}.json", "/p2/acme/widget.json"),
        Some(vec![
            ("pkg".to_owned(), "widget".to_owned()),
            ("vendor".to_owned(), "acme".to_owned()),
        ])
    );
    // `~` lands inside the captured run.
    assert_eq!(
        caps("/p2/{vendor}/{pkg}.json", "/p2/acme/widget~dev.json"),
        Some(vec![
            ("pkg".to_owned(), "widget~dev".to_owned()),
            ("vendor".to_owned(), "acme".to_owned()),
        ])
    );
    assert!(caps("/p2/{vendor}/{pkg}.json", "/p2/acme/widget.txt").is_none());
}

#[test]
fn anonymous_wildcard_suffix() {
    let pat = PathPattern::new("/files/{}.txt");
    assert!(pat.is_match(p("/files/readme.txt")));
    assert!(!pat.is_match(p("/files/readme.md")));
    assert!(pat.captures(p("/files/readme.txt")).unwrap().is_empty());
}

#[test]
fn catch_all_tail() {
    assert_eq!(glob_of("/assets/{*}", "/assets/a"), Some("a".to_owned()));
    assert_eq!(
        glob_of("/assets/{*}", "/assets/a/b/c"),
        Some("a/b/c".to_owned())
    );
    // `{*}` requires 1+ segments.
    assert!(
        PathPattern::new("/assets/{*}")
            .captures(p("/assets"))
            .is_none()
    );
    assert!(!PathPattern::new("/assets/{*}").is_match(p("/assets")));
}

#[test]
fn catch_all_middle() {
    let pat = PathPattern::new("/p2/{*}/{}.txt");
    assert!(pat.is_match(p("/p2/a/b/c.txt")));
    // `{*}` is 1+, so a single trailing segment leaves nothing for it.
    assert!(!pat.is_match(p("/p2/x.txt")));
    assert_eq!(
        glob_of("/p2/{*}/{}.txt", "/p2/a/b/c.txt"),
        Some("a/b".to_owned())
    );
}

#[test]
fn decode_aware_capture() {
    // `%6d` decodes to `m`, so the encoded path still captures vendor=acme.
    assert_eq!(
        caps("/p2/{vendor}/{pkg}.json", "/p2/ac%6de/widget.json"),
        Some(vec![
            ("pkg".to_owned(), "widget".to_owned()),
            ("vendor".to_owned(), "acme".to_owned()),
        ])
    );
}

#[test]
fn case_sensitivity() {
    let sensitive = PathPattern::new("/api/v2");
    assert!(sensitive.is_match(p("/api/v2")));
    assert!(!sensitive.is_match(p("/API/v2")));

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

#[test]
fn pattern_identity_honors_match_options_and_capture_names() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn hash(pattern: &PathPattern) -> u64 {
        let mut hasher = DefaultHasher::new();
        pattern.hash(&mut hasher);
        hasher.finish()
    }

    let opts = PathMatchOptions {
        ignore_ascii_case: true,
        ..Default::default()
    };
    let upper = PathPattern::new_with_opts("/API/{id}.JSON", opts);
    let lower = PathPattern::new_with_opts("/api/{id}.json", opts);
    assert_eq!(upper, lower);
    assert_eq!(hash(&upper), hash(&lower));

    let different_capture_name = PathPattern::new_with_opts("/api/{ID}.json", opts);
    assert_ne!(lower, different_capture_name);

    let sensitive = PathPattern::new("/API/{id}.JSON");
    assert_ne!(sensitive, lower);
}

#[test]
fn char_optional() {
    // `ab?c` -> optional `b`.
    let pat = PathPattern::new("/ab?c");
    assert!(pat.is_match(p("/abc")));
    assert!(pat.is_match(p("/ac")));
    assert!(!pat.is_match(p("/abdc")));
}

#[test]
fn root_and_empty_edges() {
    assert!(PathPattern::new("/").is_match(p("/")));
    assert!(!PathPattern::new("/a").is_match(p("/")));
    assert!(PathPattern::new("/a").is_match(p("/a")));

    assert!(PathPattern::new("").is_match(p("")));
    // `{}` is 0+ within a segment and `/` is a single empty segment, so `/{}`
    // matches `/`.
    assert!(PathPattern::new("/{}").is_match(p("/")));
    assert!(!PathPattern::new("{weird}?[]").is_match(p("/x")));
    assert!(PathPattern::new("/{}").is_match(p("/anything")));
    assert_eq!(glob_of("/{*}", "/a/b"), Some("a/b".to_owned()));
}

#[test]
fn is_match_captures_parity() {
    let cases: &[(&str, &str)] = &[
        (
            "/backend-api/codex/responses",
            "/backend-api/codex/responses",
        ),
        ("/files/{}.txt", "/files/a.txt"),
        ("/p2/{vendor}/{pkg}.json", "/p2/acme/widget.json"),
        ("/assets/{*}", "/assets/a/b"),
        ("/simple/{name}/?", "/simple/x/"),
        ("/api/v2", "/api/v3"),
        ("/files/{}.txt", "/files/a.md"),
        ("/", "/"),
        ("/", "/a"),
    ];
    for (pattern, path) in cases {
        let pat = PathPattern::new(*pattern);
        assert_eq!(
            pat.is_match(p(path)),
            pat.captures(p(path)).is_some(),
            "is_match/captures disagree for pattern {pattern:?} path {path:?}"
        );
    }

    let pat = PathPattern::new("/a/b/c");
    assert!(pat.captures(p("/a/b/c")).unwrap().is_empty());
    assert!(pat.captures(p("/a/b")).is_none());
}

#[test]
fn capture_accessors() {
    let pat = PathPattern::new("/p2/{vendor}/{pkg}.json");
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

#[test]
fn capture_then_literal_without_star() {
    // `{pkg}.json` captures the greedy run before the `.json` literal, with the
    // literal matched intact.
    let pat = PathPattern::new("/p2/{vendor}/{pkg}.json");
    let caps = pat.captures(p("/p2/acme/widget.json")).unwrap();
    assert_eq!(caps.get("pkg"), Some("widget"));
    assert_eq!(caps.get("vendor"), Some("acme"));
    assert!(pat.captures(p("/p2/acme/widget.txt")).is_none());
}

#[test]
fn capture_names_with_underscore_and_dash() {
    let pat = PathPattern::new("/{my_name}/{other-id}");
    let caps = pat.captures(p("/foo/bar")).unwrap();
    assert_eq!(caps.get("my_name"), Some("foo"));
    assert_eq!(caps.get("other-id"), Some("bar"));
}

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

#[test]
fn backtracking_discards_stale_bindings() {
    // `{*}` is shortest-first: take=1 ([a]) tentatively binds x="b" then fails
    // on the leftover [c]; that binding must be discarded before take=2 binds
    // x="c". A leaked binding would surface as a stale `x` here.
    assert_eq!(
        caps("/{*}/{x}", "/a/b/c"),
        Some(vec![("x".to_owned(), "c".to_owned())])
    );
    assert_eq!(glob_of("/{*}/{x}", "/a/b/c"), Some("a/b".to_owned()));
}

#[test]
fn anonymous_and_glob_excluded_from_named() {
    // `{}` is an uncaptured wildcard run.
    let anon_pat = PathPattern::new("/p2/{}/{real}");
    let caps = anon_pat.captures(p("/p2/foo/bar")).unwrap();
    assert_eq!(caps.get("real"), Some("bar"));
    assert_eq!(caps.iter().collect::<Vec<_>>(), vec![("real", "bar")]);

    // The `{*}` glob is reachable only via glob(), never get()/iter().
    let glob_pat = PathPattern::new("/files/{*}/{name}");
    let g = glob_pat.captures(p("/files/a/b/x")).unwrap();
    assert_eq!(g.get("name"), Some("x"));
    assert_eq!(g.glob(), Some("a/b"));
    assert_eq!(g.iter().collect::<Vec<_>>(), vec![("name", "x")]);
}

#[test]
fn named_catch_all() {
    // `{*name}` is a named catch-all: 1+ segments, '/'-joined and decoded,
    // read via get()/iter() — not glob().
    assert_eq!(
        caps("/assets/{*path}", "/assets/css/app.css"),
        Some(vec![("path".to_owned(), "css/app.css".to_owned())])
    );
    assert_eq!(
        caps("/assets/{*path}", "/assets/a"),
        Some(vec![("path".to_owned(), "a".to_owned())])
    );
    // It is a named binding, so glob() stays empty.
    let pat = PathPattern::new("/assets/{*path}");
    let c = pat.captures(p("/assets/a/b")).unwrap();
    assert_eq!(c.get("path"), Some("a/b"));
    assert_eq!(c.glob(), None);

    // Like `{*}`, it needs 1+ segments: the bare prefix does not match.
    assert!(
        PathPattern::new("/assets/{*path}")
            .captures(p("/assets"))
            .is_none()
    );

    // Mid-pattern: the run stops before the trailing literal.
    assert_eq!(
        caps("/a/{*mid}/z", "/a/b/c/z"),
        Some(vec![("mid".to_owned(), "b/c".to_owned())])
    );

    // Decoded + joined across segments.
    assert_eq!(
        caps("/d/{*rest}", "/d/a%20b/c"),
        Some(vec![("rest".to_owned(), "a b/c".to_owned())])
    );

    // `{name}` stays within a segment (contrast): it captures one segment
    // only, so a multi-segment path does not match.
    assert!(
        PathPattern::new("/assets/{path}")
            .captures(p("/assets/a/b"))
            .is_none()
    );
    assert_eq!(
        caps("/assets/{path}", "/assets/a"),
        Some(vec![("path".to_owned(), "a".to_owned())])
    );
}

#[test]
fn utf8_literal_and_capture() {
    // Multibyte UTF-8 literal segment.
    assert!(PathPattern::new("/café/menu").is_match(p("/café/menu")));
    assert!(!PathPattern::new("/café/menu").is_match(p("/cafe/menu")));

    // Capture carries a multibyte value through intact.
    assert_eq!(
        caps("/u/{name}", "/u/naïve"),
        Some(vec![("name".to_owned(), "naïve".to_owned())])
    );

    // Percent-encoded UTF-8 decodes to the same value, both in a capture and
    // against a (decoded) literal segment.
    assert_eq!(
        caps("/u/{name}", "/u/caf%C3%A9"),
        Some(vec![("name".to_owned(), "café".to_owned())])
    );
    assert!(PathPattern::new("/café").is_match(p("/caf%C3%A9")));

    // A multibyte run inside an affixed capture splits on the literal byte.
    assert_eq!(
        caps("/d/{name}.md", "/d/naïve.md"),
        Some(vec![("name".to_owned(), "naïve".to_owned())])
    );
}

#[test]
fn pct_encoded_inside_segment_is_not_a_separator() {
    // `%2F` decodes to `/` but stays *within* the captured value — segmentation
    // happens on raw `/`, before decoding, so it must not split the segment.
    assert_eq!(
        caps("/files/{name}", "/files/a%2Fb"),
        Some(vec![("name".to_owned(), "a/b".to_owned())])
    );
    assert_eq!(
        caps("/person/{name}/age", "/person/glen%20dc/age"),
        Some(vec![("name".to_owned(), "glen dc".to_owned())])
    );
    // A percent-encoded brace decodes to a plain literal in the value
    // (`%7B` == `{`); it is never re-interpreted as a token.
    assert_eq!(
        caps("/x/{v}", "/x/%7Babc"),
        Some(vec![("v".to_owned(), "{abc".to_owned())])
    );
}

#[test]
fn invalid_utf8_decodes_lossy_without_panic() {
    // `%ff` decodes to byte 0xFF (not valid UTF-8): the capture is rendered
    // lossily (U+FFFD) rather than panicking or dropping the match.
    let pat = PathPattern::new("/x/{v}");
    let caps = pat.captures(p("/x/%ff")).unwrap();
    assert_eq!(caps.get("v"), Some("\u{FFFD}"));
    // Same for the `{*}` glob join.
    assert_eq!(glob_of("/g/{*}", "/g/a/%ff"), Some("a/\u{FFFD}".to_owned()));
}

#[test]
fn misused_meta_chars_never_panic_and_stay_consistent() {
    // Patterns that abuse the brace metacharacters (`{`, `}`, `?`) or pile up
    // the now-literal `*`/`:` must compile (infallible) and match without
    // panicking, and is_match must always agree with captures().is_some() —
    // including on percent-encoded, empty, and double-slash paths.
    let patterns = [
        "{",
        "}",
        "{}",
        "{{}}",
        "{}}",
        "{{}",
        "{name",
        "name}",
        "{bad name}",
        "{na/me}",
        "{*}",
        "{**}",
        "{*}}",
        "{*bad name}",
        "{*na/me}",
        "a{*}",
        "{*}b",
        "{}?",
        "{name}?",
        "{?}",
        "?{}",
        "??",
        "a?",
        "ab?c",
        "{weird}?[]",
        ":",
        "*",
        "**",
        "***",
        "/",
        "//",
        "///",
        "",
        "/a/{*}/{*}/b",
        "{a}{b}{c}",
        "{*rest}",
        "x{*name}",
        "{*name}}",
        "/a/{*mid}/z",
        "{}.{}",
        "v{ver}-rc",
    ];
    let paths = [
        "", "/", "//", "/abc", "/a/b", "/a/b/c", "/a//b", "/x/", "/*", "/:", "/a?b", "/%2F",
        "/%ff", "/café", "/a%2Fb/c",
    ];
    for pattern in patterns {
        let pat = PathPattern::new(pattern);
        for path in paths {
            let pr = p(path);
            assert_eq!(
                pat.is_match(pr),
                pat.captures(pr).is_some(),
                "is_match/captures disagree: pattern={pattern:?} path={path:?}"
            );
            if let Some(c) = pat.captures(pr) {
                // Accessors must not panic; a name yielded by iter() resolves
                // via get() (duplicate names resolve to the first binding, so
                // only presence is asserted, not value equality).
                for (name, _value) in c.iter() {
                    assert!(c.get(name).is_some());
                }
                std::hint::black_box((c.glob(), c.is_empty()));
            }
        }
    }
}

// The shapes below explode exponentially under naive backtracking; the failure
// memo keeps them polynomial. Each asserts both a wall-clock budget a 2^N
// matcher blows through and the exact result, so the memo can't "go fast by
// being wrong".

#[test]
fn pathological_multi_run_segment_is_polynomial_and_correct() {
    use std::time::{Duration, Instant};

    // One segment, two literal-separated captures `[a][b][b][b]`: matching
    // "aaa…a" + "bb", greedy-longest binds a="aaa…a", literal `b`, then b=""
    // before the trailing literal `b`.
    let pat = PathPattern::new("/{a}b{b}b");
    let hay = "/".to_owned() + &"a".repeat(40) + "bb";
    let start = Instant::now();
    let caps = pat.captures(p(&hay)).expect("must match");
    assert_eq!(caps.get("a"), Some("a".repeat(40).as_str()));
    assert_eq!(caps.get("b"), Some(""));

    // A failing match over a long run forces the matcher to prove no split
    // works — the exponential blowup case.
    let fail_pat = PathPattern::new("{x}{y}{z}{w}{v}END");
    let fail_hay = "/".to_owned() + &"q".repeat(60);
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
    // The all-optional prefix can still match when the literal lands.
    assert!(PathPattern::new(raw.as_str()).is_match(p("/Z")));
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "matching must stay polynomial"
    );
}

#[test]
fn pathological_multi_catchall_is_polynomial_and_correct() {
    use std::time::{Duration, Instant};

    // Eight `{*}` plus a trailing literal that never appears: naive search is
    // O(segments^8); the cross-segment memo keeps it polynomial.
    let pat = PathPattern::new("/{*}/{*}/{*}/{*}/{*}/{*}/{*}/{*}/end");
    let hay = "/".to_owned() + &"x/".repeat(30) + "y";
    let start = Instant::now();
    assert!(!pat.is_match(p(&hay)));
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "matching must stay polynomial"
    );

    // Still matches + globs correctly when the tail lines up. `{*}` is
    // shortest-first, so the first takes one segment and the second the rest.
    let ok = PathPattern::new("/{*}/{*}/end");
    let g = ok.captures(p("/a/b/c/end")).expect("must match");
    assert_eq!(g.glob(), Some("a"));
}

#[test]
fn brace_misuse_falls_back_to_literal() {
    // Mid-segment `{*…}` is not a catch-all; the whole segment is literal.
    let pat = PathPattern::new("/a{*}b");
    assert!(pat.is_match(p("/a{*}b")));
    assert!(!pat.is_match(p("/axb")));

    // `{}}` = anonymous run `{}` then a literal `}`.
    let pat = PathPattern::new("/{}}");
    assert!(pat.is_match(p("/anything}")));
    assert!(!pat.is_match(p("/anything")));

    // Whole-segment `{*}}` has a non-name catch-all body -> literal segment.
    let pat = PathPattern::new("/{*}}");
    assert!(pat.is_match(p("/{*}}")));
    assert!(!pat.is_match(p("/a/b")));
}

#[test]
fn segment_kinds_classify_each_segment() {
    use crate::uri::PathPatternSegmentKind as K;
    let kinds = |pat: &str| PathPattern::new(pat).segment_kinds().collect::<Vec<_>>();

    assert_eq!(kinds("/a/b"), [K::Literal, K::Literal]);
    assert_eq!(kinds("/users/{id}"), [K::Literal, K::Dynamic]);
    assert_eq!(kinds("/files/{}.json"), [K::Literal, K::Dynamic]);
    assert_eq!(kinds("/p/{pkg}.json"), [K::Literal, K::Dynamic]);
    assert_eq!(kinds("/assets/{*}"), [K::Literal, K::CatchAll]);
    assert_eq!(kinds("/assets/{*rest}"), [K::Literal, K::CatchAll]);
    // An optional element makes the segment non-fixed -> dynamic.
    assert_eq!(kinds("/maybe/a?"), [K::Literal, K::Dynamic]);
    // Invalid catch-all / brace junk is a literal, exactly as the matcher
    // treats it (no router-side drift).
    assert_eq!(kinds("/api/{*bad name}"), [K::Literal, K::Literal]);
    assert_eq!(kinds("/x/{na.me}"), [K::Literal, K::Literal]);
    // Bare root has no segments.
    assert_eq!(PathPattern::new("/").segment_kinds().len(), 0);
    assert_eq!(PathPattern::new("").segment_kinds().len(), 0);
}

#[test]
fn segment_specificity_reports_dynamic_tie_breakers() {
    use crate::uri::PathPatternSegmentKind as K;
    let specs: Vec<_> = PathPattern::new("/files/{name}.json")
        .segment_specificity()
        .collect();

    assert_eq!(specs[0].kind, K::Literal);
    assert_eq!(specs[0].literal_bytes, 5);
    assert_eq!(specs[0].dynamic_parts, 0);
    assert_eq!(specs[0].optional_parts, 0);

    assert_eq!(specs[1].kind, K::Dynamic);
    assert_eq!(specs[1].literal_bytes, 5);
    assert_eq!(specs[1].dynamic_parts, 1);
    assert_eq!(specs[1].optional_parts, 0);

    let specs: Vec<_> = PathPattern::new("/maybe/a?")
        .segment_specificity()
        .collect();
    assert_eq!(specs[1].kind, K::Dynamic);
    assert_eq!(specs[1].literal_bytes, 1);
    assert_eq!(specs[1].dynamic_parts, 0);
    assert_eq!(specs[1].optional_parts, 1);
}

#[test]
fn prefix_matching() {
    let api = PathPattern::new_prefix("/api");
    assert!(api.is_match(p("/api"))); // bare prefix
    assert!(api.is_match(p("/api/"))); // trailing slash ignored
    assert!(api.is_match(p("/api/users")));
    assert!(api.is_match(p("/api/users/42")));
    assert!(!api.is_match(p("/apixyz"))); // segment-boundary, not substring
    assert!(!api.is_match(p("/"))); // shorter than the prefix
    assert!(!api.is_match(p("")));

    // Multi-segment prefix.
    let v2 = PathPattern::new_prefix("/api/v2");
    assert!(v2.is_match(p("/api/v2")));
    assert!(v2.is_match(p("/api/v2/users")));
    assert!(!v2.is_match(p("/api"))); // path shorter than prefix
    assert!(!v2.is_match(p("/api/v2x"))); // partial last segment

    // Empty prefix matches everything.
    let any = PathPattern::new_prefix("");
    assert!(any.is_match(p("/anything/at/all")));
    assert!(any.is_match(p("")));

    // Captures still bind in prefix mode; the trailing run is ignored.
    let cap = PathPattern::new_prefix("/users/{id}");
    let caps = cap.captures(p("/users/42/orders/7")).unwrap();
    assert_eq!(caps.get("id"), Some("42"));
}

#[test]
fn path_router_matches_longest_typed_prefix() {
    use crate::uri::PathRouter;

    let mut router = PathRouter::new();
    router.insert_prefix("/api", "api");
    router.insert_prefix("/api/admin", "admin");

    let matched = router.match_prefix(p("/api/admin/users")).unwrap();
    assert_eq!(*matched.value(), "admin");
    assert_eq!(matched.matched_segment_count(), 2);

    let matched = router.match_prefix(p("/api/users")).unwrap();
    assert_eq!(*matched.value(), "api");
    assert_eq!(matched.matched_segment_count(), 1);

    assert!(router.match_prefix(p("/apix/users")).is_none());
}

#[test]
fn path_router_matches_dynamic_prefix_and_captures() {
    use crate::uri::PathRouter;

    let mut router = PathRouter::new();
    router.insert_prefix("/users/{id}", "user");

    let matched = router.match_prefix(p("/users/42/orders")).unwrap();
    assert_eq!(*matched.value(), "user");
    assert_eq!(matched.matched_segment_count(), 2);
    assert_eq!(matched.captures().get("id"), Some("42"));

    assert!(router.match_prefix(p("/users")).is_none());
}

#[test]
fn path_router_drops_trailing_catch_all_from_prefix() {
    use crate::uri::PathRouter;

    let mut router = PathRouter::new();
    router.insert_prefix("/api/{*rest}", "api");

    let matched = router.match_prefix(p("/api")).unwrap();
    assert_eq!(*matched.value(), "api");
    assert_eq!(matched.matched_segment_count(), 1);
    assert!(matched.captures().get("rest").is_none());

    let matched = router.match_prefix(p("/api/users/42")).unwrap();
    assert_eq!(*matched.value(), "api");
    assert_eq!(matched.matched_segment_count(), 1);
}

#[test]
fn path_router_treats_invalid_catch_all_as_literal() {
    use crate::uri::PathRouter;

    let mut router = PathRouter::new();
    router.insert_prefix("/api/{*bad name}", "literal");

    assert!(router.match_prefix(p("/api/users")).is_none());
    let matched = router.match_prefix(p("/api/{*bad%20name}/users")).unwrap();
    assert_eq!(*matched.value(), "literal");
    assert_eq!(matched.matched_segment_count(), 2);
}

#[test]
fn path_router_honors_case_insensitive_options() {
    use crate::uri::PathRouter;

    let mut router = PathRouter::new();
    router.insert_prefix_with_opts(
        "/Api/{id}",
        PathMatchOptions {
            ignore_ascii_case: true,
            ..Default::default()
        },
        "api",
    );

    let matched = router.match_prefix(p("/api/ABC/rest")).unwrap();
    assert_eq!(*matched.value(), "api");
    assert_eq!(matched.matched_segment_count(), 2);
    assert_eq!(matched.captures().get("id"), Some("ABC"));
}

#[test]
fn path_router_empty_prefix_matches_without_consuming_segments() {
    use crate::uri::PathRouter;

    let mut router = PathRouter::new();
    router.insert_prefix("{*rest}", "root");

    let matched = router.match_prefix(p("/api/users")).unwrap();
    assert_eq!(*matched.value(), "root");
    assert_eq!(matched.matched_segment_count(), 0);
    assert!(matched.captures().get("rest").is_none());

    let matched = router.match_prefix(p("/")).unwrap();
    assert_eq!(*matched.value(), "root");
    assert_eq!(matched.matched_segment_count(), 0);
}

#[test]
fn path_router_replaces_equivalent_prefix() {
    use crate::uri::PathRouter;

    let mut router = PathRouter::new();
    let opts = PathMatchOptions {
        ignore_ascii_case: true,
        ..Default::default()
    };

    assert_eq!(router.insert_prefix_with_opts("/Api", opts, "old"), None);
    assert_eq!(
        router.insert_prefix_with_opts("/api", opts, "new"),
        Some("old")
    );
    assert_eq!(router.len(), 1);

    let matched = router.match_prefix(p("/API/users")).unwrap();
    assert_eq!(*matched.value(), "new");
    assert_eq!(matched.matched_segment_count(), 1);
}

#[test]
fn path_router_uses_trie_precedence_without_registration_order_bias() {
    use crate::uri::PathRouter;

    let mut router = PathRouter::new();
    router.insert_prefix("/{tenant}/settings", "dynamic-settings");
    router.insert_prefix("/acme", "literal");
    router.insert_prefix("/acme/settings/security", "literal-security");
    router.insert_prefix("/acme/{section}", "literal-section");

    let matched = router
        .match_prefix(p("/acme/settings/security/mfa"))
        .unwrap();
    assert_eq!(*matched.value(), "literal-security");
    assert_eq!(matched.matched_segment_count(), 3);

    let matched = router.match_prefix(p("/acme/settings/profile")).unwrap();
    assert_eq!(*matched.value(), "literal-section");
    assert_eq!(matched.matched_segment_count(), 2);
    assert_eq!(matched.captures().get("section"), Some("settings"));

    let matched = router.match_prefix(p("/globex/settings/profile")).unwrap();
    assert_eq!(*matched.value(), "dynamic-settings");
    assert_eq!(matched.matched_segment_count(), 2);
    assert_eq!(matched.captures().get("tenant"), Some("globex"));

    let matched = router.match_prefix(p("/acme/billing/cards")).unwrap();
    assert_eq!(*matched.value(), "literal-section");
    assert_eq!(matched.matched_segment_count(), 2);
    assert_eq!(matched.captures().get("section"), Some("billing"));
}

#[test]
fn path_router_middle_catch_all_reports_consumed_path_segments() {
    use crate::uri::PathRouter;

    let mut router = PathRouter::new();
    router.insert_prefix("/files/{*rest}/raw", "raw");

    let matched = router.match_prefix(p("/files/a/b/c/raw/tail")).unwrap();
    assert_eq!(*matched.value(), "raw");
    assert_eq!(matched.matched_segment_count(), 5);
    assert_eq!(matched.captures().get("rest"), Some("a/b/c"));
}

#[tokio::test]
async fn path_router_service_inserts_owned_captures() {
    use crate::uri::{
        PathRef, PathRouteCaptures, PathRouteInput, PathRouter, PathRouterError, Uri,
    };
    use rama_core::{
        Service,
        extensions::{Extensions, ExtensionsRef},
        service::service_fn,
    };

    struct Input {
        uri: Uri,
        extensions: Extensions,
    }

    impl Input {
        fn new(path: &str) -> Self {
            Self {
                uri: path.parse().unwrap(),
                extensions: Extensions::new(),
            }
        }
    }

    impl ExtensionsRef for Input {
        fn extensions(&self) -> &Extensions {
            &self.extensions
        }
    }

    impl PathRouteInput for Input {
        fn path_ref(&self) -> PathRef<'_> {
            self.uri.path_ref_or_root()
        }
    }

    let mut router = PathRouter::new();
    router.insert_prefix(
        "/users/{id}/files/{*rest}",
        service_fn(async |input: Input| {
            let captures = input
                .extensions()
                .get_ref::<PathRouteCaptures>()
                .expect("path captures");
            Ok::<_, std::convert::Infallible>((
                captures.get("id").map(str::to_owned),
                captures.glob().map(str::to_owned),
            ))
        }),
    );

    let output = router
        .serve(Input::new("/users/42/files/a/b/c"))
        .await
        .unwrap();
    assert_eq!(output, (Some("42".to_owned()), None));

    let err = router.serve(Input::new("/teams/42")).await.unwrap_err();
    assert!(matches!(err, PathRouterError::NotFound));
}
