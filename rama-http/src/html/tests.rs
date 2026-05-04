//! Test coverage for the `html` module — both the runtime traits in
//! [`super::core`] / [`super::either_impls`] and the proc-macro layer
//! exposed from `rama-http-macros`.
//!
//! The braces around single-element `if`/`else` arms in template tests
//! look "redundant" to rustc — they are not, the proc-macro looks for
//! `Expr::Block` to know where to insert `Either::A(..)` etc.

#![allow(unused_braces)]

use std::borrow::Cow;

use crate::BodyExtractExt;
use crate::service::web::response::IntoResponse;

use super::*;

// ---------------------------------------------------------------------------
// Element shape
// ---------------------------------------------------------------------------

#[test]
fn empty_single_tags() {
    assert_eq!(a!().into_string(), "<a></a>");
    assert_eq!(abbr!().into_string(), "<abbr></abbr>");
    assert_eq!(div!().into_string(), "<div></div>");
    assert_eq!(footer!().into_string(), "<footer></footer>");
    assert_eq!(header!().into_string(), "<header></header>");
    assert_eq!(h1!().into_string(), "<h1></h1>");
    assert_eq!(h6!().into_string(), "<h6></h6>");
    assert_eq!(svg!().into_string(), "<svg></svg>");
}

#[test]
fn empty_multi_tags() {
    assert_eq!((a!(), header!()).into_string(), "<a></a><header></header>",);
    assert_eq!(
        (div!(), span!(), span!(), span!(), div!()).into_string(),
        "<div></div><span></span><span></span><span></span><div></div>",
    );
}

#[test]
fn nested_single_tags() {
    assert_eq!(div!(span!()).into_string(), "<div><span></span></div>");
    assert_eq!(span!(h1!()).into_string(), "<span><h1></h1></span>");
    assert_eq!(
        html!(body!(div!())).into_string(),
        "<!DOCTYPE html><html><body><div></div></body></html>",
    );
}

#[test]
fn deeply_nested_tags() {
    assert_eq!(
        div!(div!(div!(div!(span!(div!()))))).into_string(),
        "<div><div><div><div><span><div></div></span></div></div></div></div>",
    );
}

#[test]
fn nested_multi_tags() {
    assert_eq!(
        html!(head!(title!()), body!(div!(div!(div!()), div!(span!())))).into_string(),
        "<!DOCTYPE html><html><head><title></title></head><body>\
         <div><div><div></div></div><div><span></span></div></div>\
         </body></html>",
    );
}

#[test]
fn void_tags_render_without_close() {
    for (got, want) in [
        (area!().into_string(), "<area>"),
        (base!().into_string(), "<base>"),
        (br!().into_string(), "<br>"),
        (col!().into_string(), "<col>"),
        (embed!().into_string(), "<embed>"),
        (hr!().into_string(), "<hr>"),
        (img!().into_string(), "<img>"),
        (input!().into_string(), "<input>"),
        (link!().into_string(), "<link>"),
        (meta!().into_string(), "<meta>"),
        (source!().into_string(), "<source>"),
        (track!().into_string(), "<track>"),
        (wbr!().into_string(), "<wbr>"),
    ] {
        assert_eq!(got, want);
    }
}

// ---------------------------------------------------------------------------
// Attributes
// ---------------------------------------------------------------------------

#[test]
fn attributes_basic_idents() {
    assert_eq!(
        div!(class = "foo bar", id = "baz").into_string(),
        r#"<div class="foo bar" id="baz"></div>"#,
    );
}

#[test]
fn attributes_string_literal_name() {
    // `data-foo` is not a valid Rust ident, so it is given as a string lit.
    assert_eq!(
        div!("data-foo" = "x", "aria-label" = "ok").into_string(),
        r#"<div data-foo="x" aria-label="ok"></div>"#,
    );
}

#[test]
fn attributes_numeric_value() {
    assert_eq!(
        input!(maxlength = 32).into_string(),
        r#"<input maxlength="32">"#,
    );
}

#[test]
fn attributes_dynamic_string() {
    let id = String::from("x");
    assert_eq!(div!(id = &id).into_string(), r#"<div id="x"></div>"#,);
}

#[test]
fn attributes_value_is_escaped() {
    let evil = "\" onclick=\"alert(1)";
    let out = div!(title = evil).into_string();
    // Interior quote must be escaped — a successful XSS would leave a raw `"`.
    assert!(!out.contains("title=\"\" "));
    assert!(out.contains("&quot;"));
}

#[test]
fn attributes_optional_some_none() {
    let some = Some("foo");
    let none: Option<String> = None;
    assert_eq!(
        div!(class? = some, id? = none).into_string(),
        r#"<div class="foo"></div>"#,
    );
}

#[test]
fn attributes_optional_with_owned_string() {
    let some = Some(String::from("hello"));
    assert_eq!(a!(href? = some).into_string(), r#"<a href="hello"></a>"#,);
}

#[test]
fn attributes_optional_bool_true_false() {
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
fn attributes_optional_then_required() {
    let cls: Option<&str> = Some("x");
    assert_eq!(
        div!(class? = cls, id = "i").into_string(),
        r#"<div class="x" id="i"></div>"#,
    );
}

// ---------------------------------------------------------------------------
// Text / scalar content
// ---------------------------------------------------------------------------

#[test]
fn escapes_text_content() {
    let user = "<script>alert('x')</script>";
    let out = p!(user).into_string();
    assert!(out.contains("&lt;script&gt;"));
    assert!(!out.contains("<script>"));
}

#[test]
fn escapes_ampersand_and_quote() {
    let s = "tom & jerry \"forever\"";
    let out = p!(s).into_string();
    assert_eq!(out, "<p>tom &amp; jerry &quot;forever&quot;</p>");
}

#[test]
fn string_literals_are_escaped_at_compile_time() {
    let out = p!("a < b > c").into_string();
    assert_eq!(out, "<p>a &lt; b &gt; c</p>");
}

#[test]
fn pre_escaped_passes_through() {
    let raw = PreEscaped("<i>raw</i>");
    let out = p!(raw).into_string();
    assert_eq!(out, "<p><i>raw</i></p>");
}

#[test]
fn pre_escaped_string_passes_through() {
    let raw = PreEscaped(String::from("<b>x</b>"));
    let out = p!(raw).into_string();
    assert_eq!(out, "<p><b>x</b></p>");
}

#[test]
fn pre_escaped_cow_passes_through() {
    let cow: Cow<'static, str> = Cow::Borrowed("<u>u</u>");
    let out = p!(PreEscaped(cow)).into_string();
    assert_eq!(out, "<p><u>u</u></p>");
}

#[test]
fn cow_str_is_escaped() {
    let cow: Cow<'static, str> = Cow::Borrowed("a<b");
    let out = p!(cow).into_string();
    assert_eq!(out, "<p>a&lt;b</p>");
}

#[test]
fn integer_content() {
    assert_eq!(span!(42_i32).into_string(), "<span>42</span>");
    assert_eq!(span!(0_u8).into_string(), "<span>0</span>");
    assert_eq!(span!(-1_i64).into_string(), "<span>-1</span>");
}

#[test]
fn float_content() {
    assert_eq!(span!(3.5_f64).into_string(), "<span>3.5</span>");
}

#[test]
fn char_content_escapes() {
    assert_eq!(span!('<').into_string(), "<span>&lt;</span>");
    assert_eq!(span!('a').into_string(), "<span>a</span>");
}

#[test]
fn bool_content_renders_words() {
    assert_eq!(span!(true).into_string(), "<span>true</span>");
    let v = false;
    assert_eq!(span!(v).into_string(), "<span>false</span>");
}

#[test]
fn option_content_some_renders_inner() {
    let some: Option<&str> = Some("yo");
    assert_eq!(span!(some).into_string(), "<span>yo</span>");
}

#[test]
fn option_content_none_renders_nothing() {
    let none: Option<&str> = None;
    assert_eq!(span!(none).into_string(), "<span></span>");
}

#[test]
fn vec_of_into_html_renders_concat() {
    let xs = vec!["a", "b", "c"];
    assert_eq!(span!(xs).into_string(), "<span>abc</span>");
}

#[test]
fn array_of_into_html_renders_concat() {
    let xs = ["a", "b"];
    assert_eq!(span!(xs).into_string(), "<span>ab</span>");
}

#[test]
fn iterator_map_renders() {
    // `Map` requires `ExactSizeIterator`, so we use a slice iterator (which
    // does implement it) rather than a generic numeric range.
    let items = [1u32, 2, 3].iter().map(|n| span!(*n));
    let out = ul!(li!(items)).into_string();
    assert_eq!(
        out,
        "<ul><li><span>1</span><span>2</span><span>3</span></li></ul>",
    );
}

#[test]
fn closure_writer_renders() {
    let render: Box<dyn FnOnce(&mut String)> = Box::new(|buf: &mut String| buf.push_str("hi"));
    // Closures are IntoHtml — verify by going through `IntoHtml` trait.
    let mut buf = String::new();
    (|b: &mut String| b.push_str("hi")).escape_and_write(&mut buf);
    assert_eq!(buf, "hi");
    drop(render);
}

// ---------------------------------------------------------------------------
// Mixed siblings, multiple text fragments
// ---------------------------------------------------------------------------

#[test]
fn mixed_text_and_element_siblings() {
    assert_eq!(
        p!("Hello, ", span!("world"), "!").into_string(),
        "<p>Hello, <span>world</span>!</p>",
    );
}

#[test]
fn dynamic_then_static_then_dynamic() {
    let name = "Alice";
    let age = 30;
    let out = p!("Hi ", name, ", age ", age).into_string();
    assert_eq!(out, "<p>Hi Alice, age 30</p>");
}

// ---------------------------------------------------------------------------
// Either / branching via if
// ---------------------------------------------------------------------------

#[test]
fn either_branches_two_way() {
    fn go(flag: bool) -> String {
        div!(if flag { "yes" } else { "no" }).into_string()
    }
    assert_eq!(go(true), "<div>yes</div>");
    assert_eq!(go(false), "<div>no</div>");
}

#[test]
fn either_branches_three_way() {
    fn go(n: u32) -> String {
        div!(if n == 0 {
            "zero"
        } else if n == 1 {
            "one"
        } else {
            "many"
        })
        .into_string()
    }
    assert_eq!(go(0), "<div>zero</div>");
    assert_eq!(go(1), "<div>one</div>");
    assert_eq!(go(7), "<div>many</div>");
}

#[test]
fn either_branches_no_else_renders_empty() {
    fn go(flag: bool) -> String {
        div!(if flag {
            "yes"
        })
        .into_string()
    }
    assert_eq!(go(true), "<div>yes</div>");
    assert_eq!(go(false), "<div></div>");
}

#[test]
fn either_branches_different_element_types() {
    fn go(b: bool) -> String {
        div!(if b { span!("a") } else { strong!("b") }).into_string()
    }
    assert_eq!(go(true), "<div><span>a</span></div>");
    assert_eq!(go(false), "<div><strong>b</strong></div>");
}

#[test]
fn manual_either_value_renders_correctly() {
    let v: Either<&str, u32> = Either::A("hi");
    assert_eq!(span!(v).into_string(), "<span>hi</span>");
    let v: Either<&str, u32> = Either::B(7);
    assert_eq!(span!(v).into_string(), "<span>7</span>");
}

#[test]
fn manual_either3_value_renders_correctly() {
    let v: Either3<&str, u32, char> = Either3::C('!');
    assert_eq!(span!(v).into_string(), "<span>!</span>");
}

// ---------------------------------------------------------------------------
// Custom elements (`custom!`) — web components / arbitrary tag names
// ---------------------------------------------------------------------------

#[test]
fn custom_element_no_body() {
    let out = custom!("my-icon").into_string();
    assert_eq!(out, "<my-icon></my-icon>");
}

#[test]
fn custom_element_only_attrs() {
    let out = custom!("my-icon", name = "smile").into_string();
    assert_eq!(out, r#"<my-icon name="smile"></my-icon>"#);
}

#[test]
fn custom_element_with_known_child() {
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
fn custom_element_with_dynamic_content_is_escaped() {
    let user = "<bad>";
    let out = custom!("my-banner", user).into_string();
    assert_eq!(out, "<my-banner>&lt;bad&gt;</my-banner>");
}

#[test]
fn custom_element_optional_attr() {
    let cls: Option<&str> = Some("highlight");
    let out = custom!("my-thing", class? = cls).into_string();
    assert_eq!(out, r#"<my-thing class="highlight"></my-thing>"#);
}

// ---------------------------------------------------------------------------
// IntoResponse — handler ergonomics
// ---------------------------------------------------------------------------

#[test]
fn html_buf_is_into_response_with_text_html_content_type() {
    let resp = div!("hi").into_response();
    let ct = resp
        .headers()
        .get(crate::header::CONTENT_TYPE)
        .expect("content-type set")
        .to_str()
        .unwrap()
        .to_owned();
    assert!(ct.starts_with("text/html"));
    assert!(ct.contains("utf-8"));
}

#[test]
fn html_buf_response_body_is_escaped_html() {
    let resp = div!("a < b").into_response();
    let body = collect_body(resp);
    assert_eq!(body, "<div>a &lt; b</div>");
}

#[test]
fn html_macro_auto_prepends_doctype() {
    let out = html!(body!(p!("ok"))).into_string();
    assert_eq!(out, "<!DOCTYPE html><html><body><p>ok</p></body></html>");
}

#[test]
fn html_macro_supports_attributes() {
    let out = html!(lang = "en", body!()).into_string();
    assert_eq!(
        out,
        r#"<!DOCTYPE html><html lang="en"><body></body></html>"#,
    );
}

#[test]
fn html_macro_is_into_response_directly() {
    // The whole point of the design: returning `html!(...)` from a
    // handler "just works" without any wrapper or `into_html_response`.
    let resp = html!(body!(p!("ok"))).into_response();
    let body = collect_body(resp);
    assert_eq!(body, "<!DOCTYPE html><html><body><p>ok</p></body></html>");
}

#[test]
fn bare_html_element_via_custom_macro() {
    // Escape hatch: if you really want `<html>` without doctype, use
    // the runtime-tag-name macro.
    let out = custom!("html", body!()).into_string();
    assert_eq!(out, "<html><body></body></html>");
}

// ---------------------------------------------------------------------------
// User-defined IntoHtml types
// ---------------------------------------------------------------------------

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
fn custom_into_html_type_composes() {
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
fn user_into_html_wrapped_in_element_macro() {
    let a = Article {
        title: "T",
        body: "B",
    };
    assert_eq!(
        body!(a).into_string(),
        "<body><article><h1>T</h1><p>B</p></article></body>",
    );
}

// ---------------------------------------------------------------------------
// Escape function is reachable as part of public surface
// ---------------------------------------------------------------------------

#[test]
fn escape_helper_works() {
    assert_eq!(escape("a<b&c"), "a&lt;b&amp;c");
}

#[test]
fn escape_into_helper_works() {
    let mut buf = String::from("[");
    escape_into(&mut buf, "a<b");
    buf.push(']');
    assert_eq!(buf, "[a&lt;b]");
}

// ---------------------------------------------------------------------------
// More edge cases
// ---------------------------------------------------------------------------

#[test]
fn empty_string_content() {
    assert_eq!(p!("").into_string(), "<p></p>");
}

#[test]
fn empty_string_attribute() {
    assert_eq!(div!(class = "").into_string(), r#"<div class=""></div>"#);
}

#[test]
fn unicode_content_passes_through() {
    let s = "🦙 hello, 世界";
    assert_eq!(p!(s).into_string(), "<p>🦙 hello, 世界</p>");
}

#[test]
fn unicode_attribute_value_escaped_correctly() {
    let v = "a < 🦙";
    assert_eq!(
        div!(title = v).into_string(),
        r#"<div title="a &lt; 🦙"></div>"#,
    );
}

#[test]
fn match_branching_via_manual_either() {
    fn render(state: u8) -> String {
        let body = match state {
            0 => Either3::A("idle"),
            1 => Either3::B(span!("running")),
            _ => Either3::C(strong!("done")),
        };
        div!(body).into_string()
    }
    assert_eq!(render(0), "<div>idle</div>");
    assert_eq!(render(1), "<div><span>running</span></div>");
    assert_eq!(render(99), "<div><strong>done</strong></div>");
}

#[test]
fn raw_ident_attribute_strips_r_hash() {
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
fn boolean_attribute_only_emits_when_true() {
    // Literal-bool form of the optional-attribute syntax.
    assert_eq!(
        input!(disabled? = true, readonly? = false).into_string(),
        r#"<input disabled>"#,
    );
}

#[test]
fn size_hint_is_lower_bound_on_buffer_growth() {
    let h = (PreEscaped("abc"), "x", 7_u32);
    assert!(h.size_hint() >= "abc".len());
}

#[test]
fn pre_escaped_char_renders_verbatim() {
    let out = p!(PreEscaped('<')).into_string();
    assert_eq!(out, "<p><</p>");
}

#[test]
fn user_type_returning_self_is_leaf() {
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
fn nested_user_into_html_with_branching() {
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

#[test]
fn attribute_value_can_be_a_format_call() {
    let n = 5;
    let s = format!("user-{n}");
    assert_eq!(div!(id = &s).into_string(), r#"<div id="user-5"></div>"#);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn collect_body(resp: crate::Response) -> String {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async move { resp.try_into_string().await.expect("body") })
}
