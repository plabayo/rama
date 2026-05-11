//! `IntoHtml` for the rama-utils types — `ArcStr`, `Substr`,
//! `NonEmptyStr`, `SmolStr`, `SmallVec`, `NonEmptySmallVec`. Each
//! string-like type is checked as content, by-reference, in attribute
//! position, and wrapped in `PreEscaped`. Collection types are checked
//! for inline-vs-spilled equivalence and per-element escaping.

use rama_utils::{
    collections::{NonEmptySmallVec, smallvec::SmallVec},
    str::{
        NonEmptyStr,
        arcstr::{ArcStr, Substr, arcstr},
        smol_str::SmolStr,
    },
};

use crate::html::*;

#[test]
fn arcstr_content_is_escaped() {
    let s: ArcStr = arcstr!("a < b & c");
    assert_eq!(p!(s).into_string(), "<p>a &lt; b &amp; c</p>");
}

#[test]
fn arcstr_ref_content_is_escaped() {
    let s: ArcStr = arcstr!("<x>");
    assert_eq!(p!(&s).into_string(), "<p>&lt;x&gt;</p>");
    // The reference impl shouldn't consume the string.
    assert_eq!(s.as_str(), "<x>");
}

#[test]
fn arcstr_attribute_value_is_escaped() {
    let s: ArcStr = arcstr!("v\"x");
    assert_eq!(div!(id = s).into_string(), r#"<div id="v&quot;x"></div>"#);
}

#[test]
fn pre_escaped_arcstr_passes_through() {
    let s: ArcStr = arcstr!("<i>raw</i>");
    assert_eq!(p!(PreEscaped(s)).into_string(), "<p><i>raw</i></p>");
}

#[test]
fn substr_content_is_escaped() {
    let base: ArcStr = arcstr!("hi <there> friend");
    let sub: Substr = base.substr(3..10);
    assert_eq!(p!(sub).into_string(), "<p>&lt;there&gt;</p>");
}

#[test]
fn substr_ref_renders() {
    let base: ArcStr = arcstr!("a<b<c");
    let sub: Substr = base.substr(0..3);
    assert_eq!(p!(&sub).into_string(), "<p>a&lt;b</p>");
}

#[test]
fn pre_escaped_substr_passes_through() {
    let base: ArcStr = arcstr!("<b>x</b>!");
    let sub: Substr = base.substr(0..8);
    assert_eq!(p!(PreEscaped(sub)).into_string(), "<p><b>x</b></p>");
}

#[test]
fn non_empty_str_content_is_escaped() {
    let s: NonEmptyStr = "a<b".try_into().unwrap();
    assert_eq!(p!(s).into_string(), "<p>a&lt;b</p>");
}

#[test]
fn non_empty_str_ref_renders() {
    let s: NonEmptyStr = "ok".try_into().unwrap();
    assert_eq!(p!(&s).into_string(), "<p>ok</p>");
    // Still usable after the borrow.
    assert_eq!(&*s, "ok");
}

#[test]
fn pre_escaped_non_empty_str_passes_through() {
    let s: NonEmptyStr = "<i>x</i>".try_into().unwrap();
    assert_eq!(p!(PreEscaped(s)).into_string(), "<p><i>x</i></p>");
}

#[test]
fn smol_str_content_is_escaped() {
    let s = SmolStr::new("a<b");
    assert_eq!(p!(s).into_string(), "<p>a&lt;b</p>");
}

#[test]
fn smol_str_ref_renders() {
    let s = SmolStr::new("hello");
    assert_eq!(p!(&s).into_string(), "<p>hello</p>");
    assert_eq!(s.as_str(), "hello");
}

#[test]
fn smol_str_as_attribute_value() {
    let v = SmolStr::new("v");
    assert_eq!(div!(id = v).into_string(), r#"<div id="v"></div>"#);
}

#[test]
fn pre_escaped_smol_str_passes_through() {
    let s = SmolStr::new("<u>u</u>");
    assert_eq!(p!(PreEscaped(s)).into_string(), "<p><u>u</u></p>");
}

#[test]
fn smallvec_renders_concat() {
    let xs: SmallVec<[&str; 4]> = SmallVec::from_slice(&["a", "b", "c"]);
    assert_eq!(span!(xs).into_string(), "<span>abc</span>");
}

#[test]
fn smallvec_inlined_and_heap_render_identically() {
    let inline: SmallVec<[u32; 4]> = SmallVec::from_slice(&[1, 2, 3]);
    let heap: SmallVec<[u32; 1]> = SmallVec::from_slice(&[1, 2, 3]);
    assert!(!inline.spilled());
    assert!(heap.spilled());
    assert_eq!(span!(inline).into_string(), span!(heap).into_string());
}

#[test]
fn smallvec_escapes_each_element() {
    let xs: SmallVec<[&str; 2]> = SmallVec::from_slice(&["<a>", "<b>"]);
    assert_eq!(p!(xs).into_string(), "<p>&lt;a&gt;&lt;b&gt;</p>");
}

#[test]
fn non_empty_small_vec_renders_head_then_tail() {
    let mut tail: SmallVec<[&str; 4]> = SmallVec::new();
    tail.push("b");
    tail.push("c");
    let nesv: NonEmptySmallVec<4, &str> = NonEmptySmallVec { head: "a", tail };
    assert_eq!(span!(nesv).into_string(), "<span>abc</span>");
}

#[test]
fn non_empty_small_vec_escapes_each_element() {
    let mut tail: SmallVec<[&str; 2]> = SmallVec::new();
    tail.push("<b>");
    let nesv: NonEmptySmallVec<2, &str> = NonEmptySmallVec { head: "<a>", tail };
    assert_eq!(p!(nesv).into_string(), "<p>&lt;a&gt;&lt;b&gt;</p>");
}

#[test]
fn non_empty_small_vec_of_owned_strings() {
    // Stresses the trait bound: `T = String` for the head, tail of `String`s.
    let mut tail: SmallVec<[String; 2]> = SmallVec::new();
    tail.push(String::from("two"));
    let nesv: NonEmptySmallVec<2, String> = NonEmptySmallVec {
        head: String::from("one"),
        tail,
    };
    assert_eq!(ul!(nesv).into_string(), "<ul>onetwo</ul>");
}
