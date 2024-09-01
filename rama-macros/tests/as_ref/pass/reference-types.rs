#![deny(noop_method_call)]

use rama::context::AsRef;

#[derive(AsRef)]
struct State {
    inner: &'static str,
}

fn main() {}
