//! Macros for [`rama`].
//!
//! There are no more macros for Rama. We used to have an `AsRef` one,
//! but it is recommended to either not use a macro for that anymore,
//! write one yourself or use a thirdparty crate such as `derive_more`.
//!
//! [`rama`]: https://crates.io/crates/rama
//!
//! ## Paste
//!
//! The nightly-only [`concat_idents!`] macro in the Rust standard library is
//! notoriously underpowered in that its concatenated identifiers can only refer to
//! existing items, they can never be used to define something new.
//!
//! [`concat_idents!`]: https://doc.rust-lang.org/std/macro.concat_idents.html
//!
//! This crate provides a flexible way to paste together identifiers in a macro,
//! including using pasted identifiers to define new items.
//!
//! This approach works with any Rust compiler 1.31+.
//!
//! <br>
//!
//! # Pasting identifiers
//!
//! Within the `paste!` macro, identifiers inside `[<`...`>]` are pasted
//! together to form a single identifier.
//!
//! ```
//! use rama_macros::paste;
//!
//! paste! {
//!     // Defines a const called `QRST`.
//!     const [<Q R S T>]: &str = "success!";
//! }
//!
//! assert_eq!(
//!     paste! { [<Q R S T>].len() },
//!     8,
//! );
//! ```
//!
//! <br><br>
//!
//! # More elaborate example
//!
//! The next example shows a macro that generates accessor methods for some
//! struct fields. It demonstrates how you might find it useful to bundle a
//! paste invocation inside of a macro\_rules macro.
//!
//! ```
//! use rama_macros::paste;
//!
//! macro_rules! make_a_struct_and_getters {
//!     ($name:ident { $($field:ident),* }) => {
//!         // Define a struct. This expands to:
//!         //
//!         //     pub struct S {
//!         //         a: String,
//!         //         b: String,
//!         //         c: String,
//!         //     }
//!         pub struct $name {
//!             $(
//!                 $field: String,
//!             )*
//!         }
//!
//!         // Build an impl block with getters. This expands to:
//!         //
//!         //     impl S {
//!         //         pub fn get_a(&self) -> &str { &self.a }
//!         //         pub fn get_b(&self) -> &str { &self.b }
//!         //         pub fn get_c(&self) -> &str { &self.c }
//!         //     }
//!         paste! {
//!             impl $name {
//!                 $(
//!                     pub fn [<get_ $field>](&self) -> &str {
//!                         &self.$field
//!                     }
//!                 )*
//!             }
//!         }
//!     }
//! }
//!
//! make_a_struct_and_getters!(S { a, b, c });
//!
//! fn call_some_getters(s: &S) -> bool {
//!     s.get_a() == s.get_b() && s.get_c().is_empty()
//! }
//! #
//! # fn main() {}
//! ```
//!
//! <br><br>
//!
//! # Case conversion
//!
//! Use `$var:lower` or `$var:upper` in the segment list to convert an
//! interpolated segment to lower- or uppercase as part of the paste. For
//! example, `[<ld_ $reg:lower _expr>]` would paste to `ld_bc_expr` if invoked
//! with $reg=`Bc`.
//!
//! Use `$var:snake` to convert CamelCase input to snake\_case.
//! Use `$var:camel` to convert snake\_case to CamelCase.
//! These compose, so for example `$var:snake:upper` would give you SCREAMING\_CASE.
//!
//! The precise Unicode conversions are as defined by [`str::to_lowercase`] and
//! [`str::to_uppercase`].
//!
//! [`str::to_lowercase`]: https://doc.rust-lang.org/std/primitive.str.html#method.to_lowercase
//! [`str::to_uppercase`]: https://doc.rust-lang.org/std/primitive.str.html#method.to_uppercase
//!
//! <br>
//!
//! # Pasting documentation strings
//!
//! Within the `paste!` macro, arguments to a #\[doc ...\] attribute are
//! implicitly concatenated together to form a coherent documentation string.
//!
//! ```
//! use rama_macros::paste;
//!
//! macro_rules! method_new {
//!     ($ret:ident) => {
//!         paste! {
//!             #[doc = "Create a new `" $ret "` object."]
//!             pub fn new() -> $ret { todo!() }
//!         }
//!     };
//! }
//!
//! pub struct Paste {}
//!
//! method_new!(Paste);  // expands to #[doc = "Create a new `Paste` object"]
//! ```

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

use proc_macro::TokenStream;

mod include_dir_macro;
mod paste_macro;

#[proc_macro]
pub fn paste(input: TokenStream) -> TokenStream {
    let mut contains_paste = false;
    let flatten_single_interpolation = true;
    match paste_macro::expand(
        input.clone(),
        &mut contains_paste,
        flatten_single_interpolation,
    ) {
        Ok(expanded) => {
            if contains_paste {
                expanded
            } else {
                input
            }
        }
        Err(err) => err.to_compile_error(),
    }
}

/// Embed the contents of a directory in your crate.
#[proc_macro]
pub fn include_dir(input: TokenStream) -> TokenStream {
    include_dir_macro::execute(input)
}
