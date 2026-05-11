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
