//! Tests for the selector engine.
//!
//! Parse-error cases and the unsupported-pseudo list are drawn from the
//! lol-html selector test suite (the upstream this engine is modelled on,
//! which constrains itself to the same streaming-safe subset). The `An+B`
//! cases follow the canonical examples in CSS Syntax §"The An+B
//! microsyntax". Anything that ever slips through fuzzing should be added
//! here as a regression case.

use super::ast::NthType;
use super::{Compound, Dom, NodeId, Selector, SelectorError};

fn sel(s: &str) -> Selector {
    s.parse()
        .unwrap_or_else(|e| panic!("`{s}` should parse: {e}"))
}

fn err(s: &str) -> SelectorError {
    s.parse::<Selector>()
        .err()
        .unwrap_or_else(|| panic!("`{s}` should fail to parse"))
}

// --- parse errors -------------------------------------------------------

#[test]
fn parse_errors() {
    assert_eq!(err("div@"), SelectorError::UnexpectedToken);
    assert_eq!(err("div."), SelectorError::UnexpectedEnd);
    assert_eq!(err(r#"div[="foo"]"#), SelectorError::MissingAttributeName);
    assert_eq!(err(""), SelectorError::EmptySelector);
    assert_eq!(err("   "), SelectorError::EmptySelector);
    assert_eq!(err("div >"), SelectorError::DanglingCombinator);
    assert_eq!(
        err(r#"div[foo~"bar"]"#),
        SelectorError::UnexpectedTokenInAttribute
    );
    assert_eq!(err("svg|img"), SelectorError::NamespacedSelector);
    assert_eq!(err("*|img"), SelectorError::NamespacedSelector);
    assert_eq!(err(".foo()"), SelectorError::UnexpectedToken);
    assert_eq!(err(":not()"), SelectorError::EmptyNegation);
    assert_eq!(err("div + span"), SelectorError::UnsupportedCombinator('+'));
    assert_eq!(err("div ~ span"), SelectorError::UnsupportedCombinator('~'));
    assert_eq!(err(":nth-child(n of a)"), SelectorError::UnexpectedToken);
    assert_eq!(err("div[foo"), SelectorError::UnexpectedEnd);
    assert_eq!(err("a,"), SelectorError::UnexpectedEnd);
}

#[test]
fn unsupported_pseudo_classes() {
    for s in [
        ":active",
        ":any-link",
        ":checked",
        ":default",
        ":dir(rtl)",
        ":disabled",
        ":empty",
        ":enabled",
        ":first",
        ":focus",
        ":has(div)",
        ":host",
        ":host(h1)",
        ":hover",
        ":is(header)",
        ":lang(en)",
        ":last-child",
        ":last-of-type",
        ":link",
        ":nth-col(1)",
        ":nth-last-child(1)",
        ":nth-last-of-type(1)",
        ":only-child",
        ":only-of-type",
        ":root",
        ":scope",
        ":target",
        ":visited",
        ":where(p)",
    ] {
        assert_eq!(err(s), SelectorError::UnsupportedPseudoClass, "{s}");
    }
}

#[test]
fn unsupported_pseudo_elements() {
    for s in [
        "::after",
        "::before",
        "::first-letter",
        "::first-line",
        "::marker",
        "::placeholder",
        "::selection",
    ] {
        assert_eq!(err(s), SelectorError::UnsupportedPseudoClass, "{s}");
    }
}

#[test]
fn negation_restrictions() {
    for s in [
        ":not(foo bar)",
        ":not(foo > bar)",
        ":not(* > .x)",
        ":not(:nth-last-child(even))",
    ] {
        assert_eq!(err(s), SelectorError::UnsupportedPseudoClass, "{s}");
    }
}

// --- An+B parsing -------------------------------------------------------

fn nth_of(s: &str) -> (i32, i32) {
    let selector = sel(s);
    let nth = selector.selectors[0].parts[0]
        .compound
        .nth
        .first()
        .copied()
        .unwrap_or_else(|| panic!("`{s}` should contain an :nth value"));
    assert!(matches!(nth.ty, NthType::Child));
    (nth.a, nth.b)
}

#[test]
fn anb_valid() {
    assert_eq!(nth_of(":nth-child(even)"), (2, 0));
    assert_eq!(nth_of(":nth-child(odd)"), (2, 1));
    assert_eq!(nth_of(":nth-child(EVEN)"), (2, 0));
    assert_eq!(nth_of(":nth-child(2n+0)"), (2, 0));
    assert_eq!(nth_of(":nth-child(4n+1)"), (4, 1));
    assert_eq!(nth_of(":nth-child(-1n+6)"), (-1, 6));
    assert_eq!(nth_of(":nth-child(-4n+10)"), (-4, 10));
    assert_eq!(nth_of(":nth-child(0n+5)"), (0, 5));
    assert_eq!(nth_of(":nth-child(5)"), (0, 5));
    assert_eq!(nth_of(":nth-child(1n+0)"), (1, 0));
    assert_eq!(nth_of(":nth-child(n+0)"), (1, 0));
    assert_eq!(nth_of(":nth-child(n)"), (1, 0));
    assert_eq!(nth_of(":nth-child(2n)"), (2, 0));
    assert_eq!(nth_of(":nth-child(3n + 1)"), (3, 1));
    assert_eq!(nth_of(":nth-child(+3n - 2)"), (3, -2));
    assert_eq!(nth_of(":nth-child(-n+6)"), (-1, 6));
    assert_eq!(nth_of(":nth-child(-n+ 6)"), (-1, 6));
    assert_eq!(nth_of(":nth-child(+6)"), (0, 6));
    assert_eq!(nth_of(":first-child"), (0, 1));
}

#[test]
fn anb_invalid() {
    assert_eq!(err(":nth-child(3 n)"), SelectorError::UnexpectedToken);
    assert_eq!(err(":nth-child(+ 2n)"), SelectorError::InvalidNth);
    assert_eq!(err(":nth-child(+ 2)"), SelectorError::InvalidNth);
    assert_eq!(err(":nth-child(3n + -6)"), SelectorError::InvalidNth);
    assert_eq!(err(":nth-child()"), SelectorError::InvalidNth);
}

// --- serialization round-trip ------------------------------------------

#[test]
fn serialization_is_canonical() {
    for (input, canonical) in [
        ("DIV", "div"),
        ("a , b", "a, b"),
        ("a   b", "a b"),
        ("a>b", "a > b"),
        ("ul > li:nth-child(2n+1)", "ul > li:nth-child(2n+1)"),
        (":nth-of-type(odd)", ":nth-of-type(2n+1)"),
        (":first-child", ":nth-child(1)"),
        ("[HREF]", "[href]"),
        (r#"[class~=menu]"#, r#"[class~="menu"]"#),
        (r#"[a="b" i]"#, r#"[a="b" i]"#),
        (r#"[a="b" s]"#, r#"[a="b"]"#),
        ("*", "*"),
        ("a:not(.x)", "a:not(.x)"),
    ] {
        assert_eq!(sel(input).to_string(), canonical, "input: {input}");
    }
}

#[test]
fn round_trip_reparses_equal() {
    for s in [
        "*",
        "div",
        "a.b.c#d",
        "div > p a",
        "a, b, c",
        r#"input[type="text"][required]"#,
        r#"a[href^="https"][rel~="nofollow" i]"#,
        "li:nth-child(2n+1)",
        "tr:nth-of-type(-n+3)",
        "div:not(.hidden):not([disabled])",
        ":not(:not(div))",
        r#".foo\.bar"#,
        r#"a[title="quote \" here"]"#,
    ] {
        let parsed = sel(s);
        let reparsed = sel(&parsed.to_string());
        assert_eq!(parsed, reparsed, "input: {s}");
    }
}

#[test]
fn escapes_decode() {
    // `\.` is a literal dot in the class name.
    let s = sel(r#".foo\.bar"#);
    let class = &s.selectors[0].parts[0].compound.classes[0];
    assert_eq!(&**class, "foo.bar");

    // Hex escape `\26 ` is U+0026 AMPERSAND.
    let s = sel(r#".a\26 b"#);
    let class = &s.selectors[0].parts[0].compound.classes[0];
    assert_eq!(&**class, "a&b");
}

#[test]
fn nul_becomes_replacement_char() {
    // CSS input preprocessing maps U+0000 to U+FFFD; regression for a
    // fuzzer-found round-trip divergence on input `X0\<NUL>`.
    let s = sel("X0\\\u{0}");
    let name = s.selectors[0].parts[0]
        .compound
        .name
        .as_ref()
        .map(super::ast::LocalName::as_str);
    assert_eq!(name, Some("x0\u{FFFD}"));
    assert_eq!(s, sel(&s.to_string()));
}

// --- matching -----------------------------------------------------------

/// `<root><a class="x"><b id="i" data-k="v1 v2"/></a></root>`
fn fixture() -> (Dom, NodeId, NodeId, NodeId) {
    let mut dom = Dom::new();
    let root = dom.create("root");
    let a = dom.append(root, "a");
    dom.set_attr(a, "class", "x");
    let b = dom.append(a, "b");
    dom.set_attr(b, "id", "i");
    dom.set_attr(b, "data-k", "v1 v2");
    (dom, root, a, b)
}

#[test]
fn matching_basics() {
    let (dom, root, a, b) = fixture();

    assert!(sel("a").matches(&dom.element(a)));
    assert!(sel("*").matches(&dom.element(a)));
    assert!(sel("A").matches(&dom.element(a)));
    assert!(!sel("b").matches(&dom.element(a)));

    assert!(sel(".x").matches(&dom.element(a)));
    assert!(sel("a.x").matches(&dom.element(a)));
    assert!(!sel(".y").matches(&dom.element(a)));

    assert!(sel("#i").matches(&dom.element(b)));
    assert!(sel("b#i").matches(&dom.element(b)));
    assert!(!sel("#j").matches(&dom.element(b)));

    // selector list
    assert!(sel("x, a, y").matches(&dom.element(a)));
    assert!(!sel("x, y, z").matches(&dom.element(root)));
}

#[test]
fn matching_combinators() {
    let (dom, _root, a, b) = fixture();

    assert!(sel("a b").matches(&dom.element(b)));
    assert!(sel("root b").matches(&dom.element(b)));
    assert!(sel("a > b").matches(&dom.element(b)));
    assert!(!sel("root > b").matches(&dom.element(b))); // root is grandparent
    assert!(sel("root > a").matches(&dom.element(a)));
    assert!(sel("root a b").matches(&dom.element(b)));
    assert!(!sel("b a").matches(&dom.element(a)));
}

#[test]
fn matching_attributes() {
    let (dom, _root, _a, b) = fixture();
    let b = dom.element(b);

    assert!(sel("[data-k]").matches(&b));
    assert!(!sel("[data-x]").matches(&b));
    assert!(sel(r#"[data-k="v1 v2"]"#).matches(&b));
    assert!(sel(r#"[data-k~="v1"]"#).matches(&b));
    assert!(sel(r#"[data-k~="v2"]"#).matches(&b));
    assert!(!sel(r#"[data-k~="v3"]"#).matches(&b));
    assert!(sel(r#"[data-k^="v1"]"#).matches(&b));
    assert!(sel(r#"[data-k$="v2"]"#).matches(&b));
    assert!(sel(r#"[data-k*="1 v"]"#).matches(&b));
    assert!(!sel(r#"[data-k^="V1"]"#).matches(&b));
    assert!(sel(r#"[data-k^="V1" i]"#).matches(&b));
    assert!(sel(r#"[id="I" i]"#).matches(&b));
    assert!(!sel(r#"[id="I"]"#).matches(&b));
}

#[test]
fn matching_dash_match() {
    let mut dom = Dom::new();
    let el = dom.create("p");
    dom.set_attr(el, "lang", "en-US");
    let el = dom.element(el);
    // `|=` matches a value equal to "en" or beginning with "en-".
    assert!(sel(r#"[lang|="en"]"#).matches(&el));
    assert!(!sel(r#"[lang|="e"]"#).matches(&el));
    // "en-US" begins with "en-" but the rule requires value + '-', i.e. the
    // char after "en-" must itself be '-', so this does not match.
    assert!(!sel(r#"[lang|="en-"]"#).matches(&el));

    let mut dom = Dom::new();
    let el = dom.create("p");
    dom.set_attr(el, "lang", "en");
    assert!(sel(r#"[lang|="en"]"#).matches(&dom.element(el)));
}

#[test]
fn matching_nth() {
    let mut dom = Dom::new();
    let ul = dom.create("ul");
    let items: Vec<NodeId> = (0..5).map(|_| dom.append(ul, "li")).collect();

    let odd = sel("li:nth-child(odd)");
    let even = sel("li:nth-child(even)");
    for (i, &item) in items.iter().enumerate() {
        let one_based = i + 1;
        assert_eq!(odd.matches(&dom.element(item)), one_based % 2 == 1);
        assert_eq!(even.matches(&dom.element(item)), one_based % 2 == 0);
    }

    assert!(sel("li:first-child").matches(&dom.element(items[0])));
    assert!(!sel("li:first-child").matches(&dom.element(items[1])));

    // -n+2 matches the first two.
    let first_two = sel("li:nth-child(-n+2)");
    assert!(first_two.matches(&dom.element(items[0])));
    assert!(first_two.matches(&dom.element(items[1])));
    assert!(!first_two.matches(&dom.element(items[2])));
}

#[test]
fn matching_nth_of_type() {
    // <root><a/><b/><a/><b/></root>
    let mut dom = Dom::new();
    let root = dom.create("root");
    let a1 = dom.append(root, "a");
    let _b1 = dom.append(root, "b");
    let a2 = dom.append(root, "a");

    assert!(sel("a:first-of-type").matches(&dom.element(a1)));
    assert!(!sel("a:first-of-type").matches(&dom.element(a2)));
    assert!(sel("a:nth-of-type(2)").matches(&dom.element(a2)));
    // a2 is the 3rd child overall, so :nth-child(2) must NOT match it.
    assert!(!sel("a:nth-child(2)").matches(&dom.element(a2)));
}

#[test]
fn matching_negation() {
    let (dom, _root, a, b) = fixture();

    assert!(sel("a:not(.y)").matches(&dom.element(a)));
    assert!(!sel("a:not(.x)").matches(&dom.element(a)));
    assert!(sel("b:not([data-x])").matches(&dom.element(b)));
    assert!(!sel("b:not([data-k])").matches(&dom.element(b)));

    // double / triple negation
    assert!(sel(":not(:not(a))").matches(&dom.element(a)));
    assert!(!sel(":not(:not(a))").matches(&dom.element(b)));
    assert!(!sel(":not(:not(:not(a)))").matches(&dom.element(a)));
}

// --- builder ------------------------------------------------------------

#[test]
fn builder_equals_parse_and_round_trips() {
    let cases: [(Selector, &str); 13] = [
        (Selector::tag("DIV"), "div"),
        (Selector::class("menu"), ".menu"),
        (Selector::id("main"), "#main"),
        (Selector::any(), "*"),
        (Selector::tag("div").child(Compound::tag("a")), "div > a"),
        (
            Selector::tag("div").descendant(Compound::class("x")),
            "div .x",
        ),
        (Selector::tag("a").or(Selector::tag("b")), "a, b"),
        (
            Selector::of(Compound::tag("a").with_class("x").with_id("y")),
            "a.x#y",
        ),
        (
            Selector::of(
                Compound::tag("input")
                    .with_attr("required")
                    .with_attr_eq("type", "text"),
            ),
            r#"input[required][type="text"]"#,
        ),
        (
            Selector::of(Compound::tag("a").with_attr_prefix("href", "/")),
            r#"a[href^="/"]"#,
        ),
        (
            Selector::of(Compound::tag("a").with_attr_eq_ignore_case("rel", "x")),
            r#"a[rel="x" i]"#,
        ),
        (
            Selector::of(Compound::tag("li").with_nth_child(2, 1)),
            "li:nth-child(2n+1)",
        ),
        (
            Selector::of(Compound::tag("a").without(Compound::class("x"))),
            "a:not(.x)",
        ),
    ];
    for (built, parsed) in cases {
        assert_eq!(built, sel(parsed), "built vs `{parsed}`");
        // The builder output serializes and reparses to the same selector.
        assert_eq!(sel(&built.to_string()), built, "round-trip `{parsed}`");
    }
}

#[test]
fn builder_matching() {
    let (dom, _root, a, b) = fixture();

    assert!(Selector::tag("a").matches(&dom.element(a)));
    assert!(Selector::class("x").matches(&dom.element(a)));
    assert!(Selector::id("i").matches(&dom.element(b)));
    assert!(
        Selector::tag("a")
            .descendant(Compound::tag("b"))
            .matches(&dom.element(b))
    );
    assert!(
        Selector::tag("root")
            .child(Compound::tag("a"))
            .matches(&dom.element(a))
    );
    assert!(
        Selector::of(Compound::tag("a").without(Compound::class("y"))).matches(&dom.element(a))
    );
    assert!(
        !Selector::of(Compound::tag("a").without(Compound::class("x"))).matches(&dom.element(a))
    );
}

#[cfg(debug_assertions)]
#[test]
#[should_panic = "must be a non-empty literal"]
fn builder_rejects_whitespace_in_debug() {
    let _sel = Compound::tag("a b");
}

#[cfg(debug_assertions)]
#[test]
#[should_panic = "must be a non-empty literal"]
fn builder_rejects_empty_in_debug() {
    let _sel = Selector::class("");
}

#[test]
fn never_panics_on_garbage() {
    for s in [
        "",
        " ",
        "\\",
        "[",
        "]",
        ":",
        "::",
        "(",
        ")",
        "#",
        ".",
        ">",
        "a[b=",
        ":nth-child(",
        "\u{1f600}",
        "a\u{0}b",
        r#"["#,
        ":not(",
        "a>>b",
        "[a~~=b]",
    ] {
        // Must terminate with Ok or Err — never panic.
        drop(s.parse::<Selector>());
    }
}
