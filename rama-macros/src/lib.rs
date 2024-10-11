//! Macros for [`rama`].
//!
//! [`rama`]: https://crates.io/crates/rama

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::parse::Parse;

mod as_ref;
mod attr_parsing;

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
