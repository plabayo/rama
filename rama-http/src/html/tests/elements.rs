//! Element shape — open/close tags, nesting, void elements.

use crate::html::*;

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
    assert_eq!((a!(), header!()).into_string(), "<a></a><header></header>");
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
