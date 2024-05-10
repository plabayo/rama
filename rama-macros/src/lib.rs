//! Macros for [`rama`].
//!
//! [`rama`]: https://crates.io/crates/rama

#![warn(
    clippy::all,
    clippy::dbg_macro,
    clippy::todo,
    clippy::empty_enum,
    clippy::enum_glob_use,
    clippy::mem_forget,
    clippy::unused_self,
    clippy::filter_map_next,
    clippy::needless_continue,
    clippy::needless_borrow,
    clippy::match_wildcard_for_single_variants,
    clippy::if_let_mutex,
    clippy::mismatched_target_os,
    clippy::await_holding_lock,
    clippy::match_on_vec_items,
    clippy::imprecise_flops,
    clippy::suboptimal_flops,
    clippy::lossy_float_literal,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::fn_params_excessive_bools,
    clippy::exit,
    clippy::inefficient_to_string,
    clippy::linkedlist,
    clippy::macro_use_imports,
    clippy::option_option,
    clippy::verbose_file_reads,
    clippy::unnested_or_patterns,
    clippy::str_to_string,
    rust_2018_idioms,
    future_incompatible,
    nonstandard_style,
    missing_debug_implementations,
    missing_docs
)]
#![deny(unreachable_pub)]
#![allow(elided_lifetimes_in_paths, clippy::type_complexity)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::parse::Parse;

mod as_ref;
mod attr_parsing;
mod type_parsing;

/// Derive an implementation of [`AsRef`] for each field in a struct.
///
/// [`AsRef`]: https://doc.rust-lang.org/std/convert/trait.AsRef.html
#[proc_macro_derive(AsRef, attributes(as_ref))]
pub fn derive_as_ref(item: TokenStream) -> TokenStream {
    expand_with(item, as_ref::expand)
}

fn expand_with<F, I, K>(input: TokenStream, f: F) -> TokenStream
where
    F: FnOnce(I) -> syn::Result<K>,
    I: Parse,
    K: ToTokens,
{
    expand(syn::parse(input).and_then(f))
}

fn expand<T>(result: syn::Result<T>) -> TokenStream
where
    T: ToTokens,
{
    match result {
        Ok(tokens) => {
            let tokens = (quote! { #tokens }).into();
            if std::env::var_os("RAMA_MACROS_DEBUG").is_some() {
                eprintln!("{tokens}");
            }
            tokens
        }
        Err(err) => err.into_compile_error().into(),
    }
}

#[cfg(test)]
fn run_ui_tests(directory: &str) {
    let t = trybuild::TestCases::new();

    if let Some(path) = std::env::var("RAMA_TEST_ONLY")
        .as_ref()
        .ok()
        .and_then(|s| s.strip_prefix("rama-macros/"))
    {
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
