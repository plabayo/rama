//! `escape` / `escape_into` are public helpers — exercise them so that
//! the publicly documented surface keeps working.

use crate::html::{escape, escape_into};

#[test]
fn escape_returns_owned_string() {
    assert_eq!(escape("a<b&c"), "a&lt;b&amp;c");
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
