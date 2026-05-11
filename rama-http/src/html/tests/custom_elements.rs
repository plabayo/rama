//! `custom!` — arbitrary-tag-name elements (web components etc.).

use crate::html::*;

#[test]
fn no_body() {
    let out = custom!("my-icon").into_string();
    assert_eq!(out, "<my-icon></my-icon>");
}

#[test]
fn only_attrs() {
    let out = custom!("my-icon", name = "smile").into_string();
    assert_eq!(out, r#"<my-icon name="smile"></my-icon>"#);
}

#[test]
fn with_known_child() {
    let out = custom!("user-card", "data-user-id" = 42, span!("Alice")).into_string();
    assert_eq!(
        out,
        r#"<user-card data-user-id="42"><span>Alice</span></user-card>"#,
    );
}

#[test]
fn known_element_with_custom_child() {
    let out = body!(custom!("page-header", h1!("hi"))).into_string();
    assert_eq!(out, "<body><page-header><h1>hi</h1></page-header></body>");
}

#[test]
fn nested_custom_elements() {
    let out = custom!("wc-outer", kind = "demo", custom!("wc-inner", "x"),).into_string();
    assert_eq!(
        out,
        r#"<wc-outer kind="demo"><wc-inner>x</wc-inner></wc-outer>"#,
    );
}

#[test]
fn dynamic_content_is_escaped() {
    let user = "<bad>";
    let out = custom!("my-banner", user).into_string();
    assert_eq!(out, "<my-banner>&lt;bad&gt;</my-banner>");
}

#[test]
fn optional_attr() {
    let cls: Option<&str> = Some("highlight");
    let out = custom!("my-thing", class? = cls).into_string();
    assert_eq!(out, r#"<my-thing class="highlight"></my-thing>"#);
}

#[test]
fn bare_html_element_via_custom_macro() {
    // Escape hatch: `html!` always emits doctype, so `custom!("html", ...)`
    // is the way to render a bare `<html>` element.
    let out = custom!("html", body!()).into_string();
    assert_eq!(out, "<html><body></body></html>");
}
