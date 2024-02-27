#![deny(noop_method_call)]

use rama_macros::AsRef;

#[derive(AsRef)]
struct State {
    inner: &'static str,
}

fn main() {}
