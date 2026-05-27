//! User-defined `IntoHtml` types — composite types delegating to
//! element macros, leaf types overriding `escape_and_write`, and types
//! that branch internally.

#![allow(unused_braces)]

use crate::html::*;

struct Article {
    title: &'static str,
    body: &'static str,
}

impl IntoHtml for Article {
    fn into_html(self) -> impl IntoHtml {
        article!(h1!(self.title), p!(self.body))
    }
}

#[test]
fn composite_type_composes() {
    let a = Article {
        title: "T",
        body: "<x>",
    };
    assert_eq!(
        a.into_string(),
        "<article><h1>T</h1><p>&lt;x&gt;</p></article>",
    );
}

#[test]
fn user_type_wrapped_in_element_macro() {
    let a = Article {
        title: "T",
        body: "B",
    };
    assert_eq!(
        body!(a).into_string(),
        "<body><article><h1>T</h1><p>B</p></article></body>",
    );
}

#[test]
fn leaf_type_returning_self() {
    struct Leaf(&'static str);
    impl IntoHtml for Leaf {
        fn into_html(self) -> impl IntoHtml {
            self
        }
        fn escape_and_write(self, buf: &mut String) {
            // Intentionally bypasses HTML escaping so we verify it's called.
            buf.push_str("[L:");
            buf.push_str(self.0);
            buf.push(']');
        }
        fn size_hint(&self) -> usize {
            self.0.len() + 3
        }
    }

    assert_eq!(span!(Leaf("hi")).into_string(), "<span>[L:hi]</span>");
}

#[test]
fn user_type_with_internal_branching() {
    struct Page {
        logged_in: bool,
    }
    impl IntoHtml for Page {
        fn into_html(self) -> impl IntoHtml {
            html!(body!(if self.logged_in {
                p!("welcome")
            } else {
                p!("please log in")
            }))
        }
    }
    assert_eq!(
        Page { logged_in: true }.into_string(),
        "<!DOCTYPE html><html><body><p>welcome</p></body></html>",
    );
    assert_eq!(
        Page { logged_in: false }.into_string(),
        "<!DOCTYPE html><html><body><p>please log in</p></body></html>",
    );
}
