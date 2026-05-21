//! `Uri::resolve` / `Uri::resolve_strict` — RFC 3986 §5.2 reference
//! resolution.
//!
//! Covers the RFC §5.4 example corpus (normal + abnormal cases) plus
//! error surfaces and the graceful-vs-strict divergence.

use super::parse_graceful;
use crate::uri::{ResolveError, Uri};

/// Standard §5.4 base URI used by both example tables.
const BASE: &str = "http://a/b/c/d;p?q";

fn resolve(base: &str, reference: &str) -> String {
    let base: Uri = parse_graceful(base).unwrap();
    let reference: Uri = Uri::parse_reference(reference).unwrap();
    base.resolve(&reference).unwrap().to_string()
}

fn resolve_strict(base: &str, reference: &str) -> Result<String, ResolveError> {
    let base: Uri = parse_graceful(base).unwrap();
    let reference: Uri = Uri::parse_reference(reference).unwrap();
    base.resolve_strict(&reference).map(|u| u.to_string())
}

// ----------------------------------------------------------------------
// RFC 3986 §5.4.1 — Normal examples
// ----------------------------------------------------------------------

#[test]
fn rfc_5_4_1_normal_examples() {
    for (reference, expected) in [
        ("g:h", "g:h"),
        ("g", "http://a/b/c/g"),
        ("./g", "http://a/b/c/g"),
        ("g/", "http://a/b/c/g/"),
        ("/g", "http://a/g"),
        ("//g", "http://g"),
        ("?y", "http://a/b/c/d;p?y"),
        ("g?y", "http://a/b/c/g?y"),
        ("#s", "http://a/b/c/d;p?q#s"),
        ("g#s", "http://a/b/c/g#s"),
        ("g?y#s", "http://a/b/c/g?y#s"),
        (";x", "http://a/b/c/;x"),
        ("g;x", "http://a/b/c/g;x"),
        ("g;x?y#s", "http://a/b/c/g;x?y#s"),
        ("", "http://a/b/c/d;p?q"),
        (".", "http://a/b/c/"),
        ("./", "http://a/b/c/"),
        ("..", "http://a/b/"),
        ("../", "http://a/b/"),
        ("../g", "http://a/b/g"),
        ("../..", "http://a/"),
        ("../../", "http://a/"),
        ("../../g", "http://a/g"),
    ] {
        assert_eq!(
            resolve(BASE, reference),
            expected,
            "reference: {reference:?}"
        );
    }
}

// ----------------------------------------------------------------------
// RFC 3986 §5.4.2 — Abnormal examples
// ----------------------------------------------------------------------

#[test]
fn rfc_5_4_2_abnormal_examples() {
    for (reference, expected) in [
        // Excess `..` clamps at root (graceful).
        ("../../../g", "http://a/g"),
        ("../../../../g", "http://a/g"),
        // `.` / `..` inside path segments.
        ("/./g", "http://a/g"),
        ("/../g", "http://a/g"),
        // Trailing `.` / `..` in segment names are NOT special.
        ("g.", "http://a/b/c/g."),
        (".g", "http://a/b/c/.g"),
        ("g..", "http://a/b/c/g.."),
        ("..g", "http://a/b/c/..g"),
        // Compound dots.
        ("./../g", "http://a/b/g"),
        ("./g/.", "http://a/b/c/g/"),
        ("g/./h", "http://a/b/c/g/h"),
        ("g/../h", "http://a/b/c/h"),
        ("g;x=1/./y", "http://a/b/c/g;x=1/y"),
        ("g;x=1/../y", "http://a/b/c/y"),
        // Query/fragment portions are NOT dot-normalized — they stop the path.
        ("g?y/./x", "http://a/b/c/g?y/./x"),
        ("g?y/../x", "http://a/b/c/g?y/../x"),
        ("g#s/./x", "http://a/b/c/g#s/./x"),
        ("g#s/../x", "http://a/b/c/g#s/../x"),
    ] {
        assert_eq!(
            resolve(BASE, reference),
            expected,
            "reference: {reference:?}"
        );
    }
}

// ----------------------------------------------------------------------
// Scheme-matching loophole (graceful vs strict)
// ----------------------------------------------------------------------

#[test]
fn graceful_applies_scheme_matching_loophole() {
    // `http:g` against `http://a/b/c/d;p?q`:
    //  - graceful: scheme matches, treat R as if no scheme → branch 4
    //    → resolves to `http://a/b/c/g`
    //  - strict: keep R verbatim → `http:g`
    let base: Uri = parse_graceful(BASE).unwrap();
    let reference: Uri = Uri::parse_reference("http:g").unwrap();
    assert_eq!(
        base.resolve(&reference).unwrap().to_string(),
        "http://a/b/c/g"
    );
    assert_eq!(
        base.resolve_strict(&reference).unwrap().to_string(),
        "http:g",
    );
}

#[test]
fn loophole_does_not_apply_when_schemes_differ() {
    // `mailto:g` against `http://a/b/c/` — schemes don't match.
    // Both modes treat R as scheme-bearing → branch 1 → `mailto:g`.
    assert_eq!(resolve(BASE, "mailto:g"), "mailto:g");
    assert_eq!(resolve_strict(BASE, "mailto:g").unwrap(), "mailto:g",);
}

// ----------------------------------------------------------------------
// Traversal past root (graceful vs strict)
// ----------------------------------------------------------------------

#[test]
fn graceful_clamps_dot_dot_at_root() {
    assert_eq!(resolve(BASE, "../../../g"), "http://a/g");
    assert_eq!(resolve(BASE, "../../../../../../g"), "http://a/g");
}

#[test]
fn strict_rejects_dot_dot_traversal_past_root() {
    let base: Uri = parse_graceful(BASE).unwrap();
    let reference: Uri = Uri::parse_reference("../../../g").unwrap();
    let err = base.resolve_strict(&reference).unwrap_err();
    assert_eq!(err, ResolveError::DotSegmentTraversalPastRoot);
}

#[test]
fn strict_allows_exact_root_traversal() {
    // `../..` against `http://a/b/c/d;p?q` pops down to root → "http://a/"
    // — reaches root but doesn't traverse past it. Strict allows.
    assert_eq!(resolve_strict(BASE, "../..").unwrap(), "http://a/");
    // One more `..` would error.
    let base: Uri = parse_graceful(BASE).unwrap();
    let reference: Uri = Uri::parse_reference("../../..").unwrap();
    assert!(matches!(
        base.resolve_strict(&reference),
        Err(ResolveError::DotSegmentTraversalPastRoot),
    ));
}

// ----------------------------------------------------------------------
// Error surfaces
// ----------------------------------------------------------------------

#[test]
fn base_without_scheme_errors() {
    let base: Uri = parse_graceful("/p").unwrap();
    let reference: Uri = Uri::parse_reference("foo").unwrap();
    assert_eq!(
        base.resolve(&reference).unwrap_err(),
        ResolveError::BaseHasNoScheme,
    );
}

#[test]
fn asterisk_as_base_or_reference_errors() {
    let star: Uri = parse_graceful("*").unwrap();
    let normal: Uri = parse_graceful("http://a/b").unwrap();
    assert_eq!(
        star.resolve(&normal).unwrap_err(),
        ResolveError::AsteriskNotResolvable,
    );
    assert_eq!(
        normal.resolve(&star).unwrap_err(),
        ResolveError::AsteriskNotResolvable,
    );
}

// ----------------------------------------------------------------------
// Empty base path with authority (the §5.2.3 merge edge case)
// ----------------------------------------------------------------------

#[test]
fn merge_empty_base_path_with_authority() {
    // Base `http://a` has empty path with authority — relative ref `g`
    // should produce `http://a/g` per §5.2.3 special case.
    let base: Uri = parse_graceful("http://a").unwrap();
    let reference: Uri = Uri::parse_reference("g").unwrap();
    assert_eq!(base.resolve(&reference).unwrap().to_string(), "http://a/g");
}

// ----------------------------------------------------------------------
// Fragment is always from the reference
// ----------------------------------------------------------------------

#[test]
fn fragment_taken_from_reference_unconditionally() {
    // Same-document ref with no path/query/scheme/authority — pure fragment.
    assert_eq!(resolve("http://a/b?q", "#frag"), "http://a/b?q#frag");
    // Base has fragment, reference doesn't → result has none.
    assert_eq!(resolve("http://a/b#oldfrag", "g"), "http://a/g");
    // Base + reference both have fragment → reference's wins.
    assert_eq!(resolve("http://a/b#old", "g#new"), "http://a/g#new");
}

// ----------------------------------------------------------------------
// Same-document references (Branch 3 — query inheritance)
// ----------------------------------------------------------------------

#[test]
fn branch_3_empty_ref_inherits_query() {
    // R has nothing → result == B (modulo fragment, which is None here).
    assert_eq!(resolve("http://a/b?q", ""), "http://a/b?q");
}

#[test]
fn branch_3_fragment_only_ref_inherits_query() {
    // `#s` against `?q` → keep B's query.
    assert_eq!(resolve("http://a/b?q", "#s"), "http://a/b?q#s");
}

#[test]
fn branch_3_query_only_ref_overrides_query() {
    // `?y` against `?q` → R's query wins, B.path inherited.
    assert_eq!(resolve("http://a/b?q", "?y"), "http://a/b?y");
}

// ----------------------------------------------------------------------
// Opaque-path base (mailto, urn, data, …)
// ----------------------------------------------------------------------

#[test]
fn opaque_base_resolution() {
    // Reference `bar` against `mailto:foo` — merge rule with no authority
    // and opaque base path "foo": "up to last /" of "foo" is "" → result
    // path is just "bar". Scheme inherited.
    assert_eq!(resolve("mailto:foo", "bar"), "mailto:bar");
}

// ----------------------------------------------------------------------
// Tree of base/reference scheme presence
// ----------------------------------------------------------------------

#[test]
fn reference_with_different_scheme_passes_through() {
    // Branch 1 — R has scheme that differs from B. Use R as-is (with
    // dot-removal on the path).
    assert_eq!(
        resolve("http://a/b/", "ftp://example.com/x/./y"),
        "ftp://example.com/x/y",
    );
}

// ----------------------------------------------------------------------
// Round-trip: parse → resolve → display → reparse
// ----------------------------------------------------------------------

#[test]
fn resolved_uri_reparses_to_same_string() {
    let cases = [
        ("g", "http://a/b/c/g"),
        ("../../../g", "http://a/g"),
        ("g?y#s", "http://a/b/c/g?y#s"),
    ];
    for (reference, _expected) in cases {
        let resolved = resolve(BASE, reference);
        // Reparse and re-display — should be byte-identical.
        let reparsed: Uri = resolved.parse().unwrap();
        assert_eq!(reparsed.to_string(), resolved, "round-trip {reference:?}");
    }
}
