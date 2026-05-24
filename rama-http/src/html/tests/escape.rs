//! `escape` / `escape_into` are public helpers — exercise them so that
//! the publicly documented surface keeps working.

use std::borrow::Cow;

use crate::html::{IntoHtml, escape, escape_into, marker};

#[test]
fn escape_returns_owned_when_needed() {
    assert_eq!(escape("a<b&c"), "a&lt;b&amp;c");
    assert!(matches!(escape("a<b&c"), Cow::Owned(_)));
}

#[test]
fn escape_borrows_when_no_escape_needed() {
    let input = "alphanumeric-and_safe.0";
    let out = escape(input);
    assert_eq!(out, input);
    // Borrowed Cow points at the same buffer — verify with pointer identity.
    match out {
        Cow::Borrowed(s) => assert_eq!(s.as_ptr(), input.as_ptr()),
        Cow::Owned(_) => panic!("escape allocated for already-safe input"),
    }
}

#[test]
fn escape_into_appends_to_existing_buffer() {
    let mut buf = String::from("[");
    escape_into(&mut buf, "a<b");
    buf.push(']');
    assert_eq!(buf, "[a&lt;b]");
}

#[test]
fn escape_single_quote_for_attribute_context() {
    // Defends single-quoted attribute interpolation, e.g. <input value='…'>.
    assert_eq!(escape("a'b"), "a&#x27;b");
    assert_eq!(
        escape("' onmouseover='alert(1)"),
        "&#x27; onmouseover=&#x27;alert(1)"
    );
}

#[test]
fn escape_all_html_specials() {
    assert_eq!(escape("&<>\"'"), "&amp;&lt;&gt;&quot;&#x27;");
}

#[test]
fn marker_emits_processing_instruction() {
    assert_eq!(marker("cart").into_string(), r#"<?marker name="cart">"#);
    assert_eq!(
        marker("herd_42-a").into_string(),
        r#"<?marker name="herd_42-a">"#
    );
}

#[test]
fn marker_escapes_unsafe_chars() {
    assert_eq!(
        marker(r#"a"<&>b"#).into_string(),
        r#"<?marker name="a&quot;&lt;&amp;&gt;b">"#
    );
    assert_eq!(
        marker(String::from(" with space ")).into_string(),
        r#"<?marker name=" with space ">"#
    );
}
