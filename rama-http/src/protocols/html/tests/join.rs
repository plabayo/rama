//! `join_display` — render an iterator of `Display` values as a separated list,
//! escaping each item while writing the separator verbatim.

use crate::protocols::html::*;

#[test]
fn csv_attribute_from_iter() {
    let langs = ["en", "fr", "de"];
    assert_eq!(
        meta!(
            "http-equiv" = "Content-Language",
            content = join_display(langs, ", ")
        )
        .into_string(),
        r#"<meta http-equiv="Content-Language" content="en, fr, de">"#,
    );
}

#[test]
fn single_item_has_no_separator() {
    assert_eq!(
        div!(class = join_display(["solo"], " ")).into_string(),
        r#"<div class="solo"></div>"#,
    );
}

#[test]
fn empty_iter_renders_nothing() {
    let empty: [&str; 0] = [];
    assert_eq!(
        div!(class = join_display(empty, ", ")).into_string(),
        r#"<div class=""></div>"#,
    );
}

#[test]
fn non_string_display_items() {
    // works for any `Display` type, not just strings
    assert_eq!(
        div!("data-x" = join_display([1, 2, 3], "-")).into_string(),
        r#"<div data-x="1-2-3"></div>"#,
    );
}

#[test]
fn items_are_escaped_separator_is_verbatim() {
    // each item is HTML-escaped (data), the separator is written as-is
    // (trusted structure). The interior quote in an item must be escaped so
    // it cannot break out of the attribute.
    let items = ["a<b", "c\"d"];
    let out = div!(title = join_display(items, " | ")).into_string();
    assert_eq!(out, r#"<div title="a&lt;b | c&quot;d"></div>"#);
}

#[test]
fn works_in_body_content() {
    assert_eq!(
        p!(join_display(["x", "y", "z"], ", ")).into_string(),
        r#"<p>x, y, z</p>"#,
    );
}
