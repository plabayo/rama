//! `if`/`else` chains inside element macros desugar into `Either*` so
//! the arms can have different concrete types. `match` doesn't get the
//! same automatic rewrite — for that, users wrap arms in `Either*`
//! manually.

#![allow(unused_braces)]

use crate::html::*;

#[test]
fn if_two_way() {
    fn go(flag: bool) -> String {
        div!(if flag { "yes" } else { "no" }).into_string()
    }
    assert_eq!(go(true), "<div>yes</div>");
    assert_eq!(go(false), "<div>no</div>");
}

#[test]
fn if_three_way() {
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
fn if_no_else_renders_empty() {
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
fn if_different_element_types() {
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

#[test]
fn match_via_manual_either() {
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
