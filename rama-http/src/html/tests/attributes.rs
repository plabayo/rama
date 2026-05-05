//! Attribute syntax — required / optional / boolean / raw idents /
//! string-literal names / value escaping.

use crate::html::*;

#[test]
fn basic_idents() {
    assert_eq!(
        div!(class = "foo bar", id = "baz").into_string(),
        r#"<div class="foo bar" id="baz"></div>"#,
    );
}

#[test]
fn string_literal_name() {
    // `data-foo` is not a valid Rust ident, so it is given as a string lit.
    assert_eq!(
        div!("data-foo" = "x", "aria-label" = "ok").into_string(),
        r#"<div data-foo="x" aria-label="ok"></div>"#,
    );
}

#[test]
fn numeric_value() {
    assert_eq!(
        input!(maxlength = 32).into_string(),
        r#"<input maxlength="32">"#,
    );
}

#[test]
fn dynamic_string() {
    let id = String::from("x");
    assert_eq!(div!(id = &id).into_string(), r#"<div id="x"></div>"#);
}

#[test]
fn value_is_escaped() {
    let evil = "\" onclick=\"alert(1)";
    let out = div!(title = evil).into_string();
    // Interior quote must be escaped — a successful XSS would leave a raw `"`.
    assert!(!out.contains("title=\"\" "));
    assert!(out.contains("&quot;"));
}

#[test]
fn empty_value() {
    assert_eq!(div!(class = "").into_string(), r#"<div class=""></div>"#);
}

#[test]
fn unicode_value_escaped_correctly() {
    let v = "a < 🦙";
    assert_eq!(
        div!(title = v).into_string(),
        r#"<div title="a &lt; 🦙"></div>"#,
    );
}

#[test]
fn optional_some_none() {
    let some = Some("foo");
    let none: Option<String> = None;
    assert_eq!(
        div!(class? = some, id? = none).into_string(),
        r#"<div class="foo"></div>"#,
    );
}

#[test]
fn optional_with_owned_string() {
    let some = Some(String::from("hello"));
    assert_eq!(a!(href? = some).into_string(), r#"<a href="hello"></a>"#);
}

#[test]
fn optional_bool_true_false() {
    assert_eq!(
        button!(disabled? = true).into_string(),
        r#"<button disabled></button>"#,
    );
    assert_eq!(
        button!(disabled? = false).into_string(),
        r#"<button></button>"#,
    );
}

#[test]
fn optional_then_required() {
    let cls: Option<&str> = Some("x");
    assert_eq!(
        div!(class? = cls, id = "i").into_string(),
        r#"<div class="x" id="i"></div>"#,
    );
}

#[test]
fn raw_ident_strips_r_hash() {
    // `type` is a Rust keyword, so it must be written `r#type` in source —
    // but the rendered HTML attribute name should still be `type`.
    assert_eq!(
        input!(r#type = "text").into_string(),
        r#"<input type="text">"#,
    );
}

#[test]
fn many_attributes_dont_break_layout() {
    assert_eq!(
        input!(
            r#type = "text",
            name = "username",
            id = "u",
            class = "input",
            "data-required" = "true",
            placeholder = "...",
        )
        .into_string(),
        r#"<input type="text" name="username" id="u" class="input" data-required="true" placeholder="...">"#,
    );
}

#[test]
fn boolean_only_emits_when_true() {
    // Literal-bool form of the optional-attribute syntax.
    assert_eq!(
        input!(disabled? = true, readonly? = false).into_string(),
        r#"<input disabled>"#,
    );
}

#[test]
fn value_can_be_format_call() {
    let n = 5;
    let s = format!("user-{n}");
    assert_eq!(div!(id = &s).into_string(), r#"<div id="user-5"></div>"#);
}
