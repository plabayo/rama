//! Macros that were moved over from [`axum_macros`] and modified to work with rama
//!
//! [`axum`]: https://crates.io/crates/axum_macros

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

use proc_macro::TokenStream;
use quote::{ToTokens, quote};
use syn::parse::Parse;

pub(crate) mod attr_parsing;
pub(crate) mod from_ref;

pub(crate) fn expand_with<F, I, K>(input: TokenStream, f: F) -> TokenStream
where
    F: FnOnce(I) -> syn::Result<K>,
    I: Parse,
    K: ToTokens,
{
    expand(syn::parse(input).and_then(f))
}

pub(crate) fn expand<T>(result: syn::Result<T>) -> TokenStream
where
    T: ToTokens,
{
    match result {
        Ok(tokens) => {
            let tokens = (quote! { #tokens }).into();
            if std::env::var_os("AXUM_MACROS_DEBUG").is_some() {
                eprintln!("{tokens}");
            }
            tokens
        }
        Err(err) => err.into_compile_error().into(),
    }
}

#[cfg(test)]
fn run_ui_tests(directory: &str) {
    #[rustversion::nightly]
    fn go(directory: &str) {
        let t = trybuild::TestCases::new();

        if let Ok(mut path) = std::env::var("AXUM_TEST_ONLY") {
            if let Some(path_without_prefix) = path.strip_prefix("axum-macros/") {
                path = path_without_prefix.to_owned();
            }

            if !path.contains(&format!("/{directory}/")) {
                return;
            }

            if path.contains("/fail/") {
                t.compile_fail(path);
            } else if path.contains("/pass/") {
                t.pass(path);
            } else {
                panic!()
            }
        } else {
            t.compile_fail(format!("tests/{directory}/fail/*.rs"));
            t.pass(format!("tests/{directory}/pass/*.rs"));
        }
    }

    #[rustversion::not(nightly)]
    fn go(_directory: &str) {}

    go(directory);
}
