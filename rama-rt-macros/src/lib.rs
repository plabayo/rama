#![allow(clippy::needless_doctest_main)]
#![warn(
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    unreachable_pub
)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]

//! Macros for use with Rama

// This `extern` is required for older `rustc` versions but newer `rustc`
// versions warn about the unused `extern crate`.
#[allow(unused_extern_crates)]
extern crate proc_macro;

mod entry;

use proc_macro::TokenStream;

/// Marks async function to be executed by the selected runtime. This macro
/// helps set up a `Runtime` without requiring the user to use
/// Runtime or Builder directly.
#[proc_macro_attribute]
#[cfg(not(test))] // Work around for rust-lang/rust#62127
pub fn main(args: TokenStream, item: TokenStream) -> TokenStream {
    entry::main(args.into(), item.into()).into()
}

/// Marks async function to be executed by runtime, suitable to test environment.
/// This macro helps set up a `Runtime` without requiring the user to use
/// Runtime or Builder directly.
#[proc_macro_attribute]
pub fn test(args: TokenStream, item: TokenStream) -> TokenStream {
    entry::test(args.into(), item.into()).into()
}
