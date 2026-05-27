//! Text and scalar content — escaping, scalars, `Option<T>`, `Vec<T>`,
//! arrays, iterators, closures, `PreEscaped`, mixed siblings.

use std::borrow::Cow;

use crate::html::*;

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
fn empty_string_content() {
    assert_eq!(p!("").into_string(), "<p></p>");
}

#[test]
fn unicode_content_passes_through() {
    let s = "🦙 hello, 世界";
    assert_eq!(p!(s).into_string(), "<p>🦙 hello, 世界</p>");
}

#[test]
fn pre_escaped_str_passes_through() {
    let raw = PreEscaped("<i>raw</i>");
    assert_eq!(p!(raw).into_string(), "<p><i>raw</i></p>");
}

#[test]
fn pre_escaped_string_passes_through() {
    let raw = PreEscaped(String::from("<b>x</b>"));
    assert_eq!(p!(raw).into_string(), "<p><b>x</b></p>");
}

#[test]
fn pre_escaped_cow_passes_through() {
    let cow: Cow<'static, str> = Cow::Borrowed("<u>u</u>");
    assert_eq!(p!(PreEscaped(cow)).into_string(), "<p><u>u</u></p>");
}

#[test]
fn pre_escaped_char_renders_verbatim() {
    let out = p!(PreEscaped('<')).into_string();
    assert_eq!(out, "<p><</p>");
}

#[test]
fn cow_str_is_escaped() {
    let cow: Cow<'static, str> = Cow::Borrowed("a<b");
    assert_eq!(p!(cow).into_string(), "<p>a&lt;b</p>");
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

#[test]
fn size_hint_is_lower_bound_on_buffer_growth() {
    let h = (PreEscaped("abc"), "x", 7_u32);
    assert!(h.size_hint() >= "abc".len());
}
