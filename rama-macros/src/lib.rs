//! Macros for [`rama`].
//!
//! There are no more macros for Rama. We used to have an `AsRef` one,
//! but it is recommended to either not use a macro for that anymore,
//! write one yourself or use a thirdparty crate such as `derive_more`.
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

/// Placeholder proc macro as Rama no longer has any official proc macros.
///
/// We keep this in here until we have a need for it again.
#[proc_macro_attribute]
pub fn same_same(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}
